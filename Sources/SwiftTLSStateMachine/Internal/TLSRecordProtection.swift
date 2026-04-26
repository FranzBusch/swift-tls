//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

public import Crypto

/// Encrypts and decrypts TLS 1.3 records per RFC 8446 Section 5.
///
/// Both encrypt and decrypt operate on ``EncryptedTLSRecordView`` /
/// ``DecryptedTLSRecordView`` with in-place semantics. The fragment
/// layout is `[ciphertext | tag(16)]`.
struct TLSRecordProtection {
    let key: SymmetricKey
    let iv: [UInt8]

    /// Creates a record protection instance from a traffic secret.
    init(trafficSecret: SymmetricKey, cipherSuite: CipherSuite) {
        self.key = TLSKeyDerivation<SHA256>.expandLabel(
            secret: trafficSecret,
            label: "key",
            context: [],
            length: Self.keyLength(for: cipherSuite)
        )
        let ivKey = TLSKeyDerivation<SHA256>.expandLabel(
            secret: trafficSecret,
            label: "iv",
            context: [],
            length: 12
        )
        self.iv = ivKey.withUnsafeBytes { Array($0) }
    }

    // MARK: - Decrypt

    /// Decrypts a TLS 1.3 record in-place.
    ///
    /// Splits `record.fragment` into ciphertext (all but last 16 bytes)
    /// and tag (last 16 bytes), decrypts ciphertext in-place, strips
    /// the inner content type and padding.
    @_lifetime(&record)
    func decrypt(
        record: inout EncryptedTLSRecordView,
        sequenceNumber: UInt64
    ) throws -> DecryptedTLSRecordView {
        let tagSize = 16
        let fragmentCount = record.fragment.count
        guard fragmentCount > tagSize else {
            throw TLSRecordProtectionError.recordTooShort
        }

        let ciphertextLength = fragmentCount - tagSize
        let nonce = try AES.GCM.Nonce(data: Self.buildNonce(iv: iv, sequenceNumber: sequenceNumber))
        let aad = Self.buildAAD(
            contentType: record.contentType,
            version: record.version,
            fragmentLength: fragmentCount
        )

        // Extract tag bytes first (read-only), then decrypt ciphertext in-place
        var tagBytes = [UInt8](repeating: 0, count: tagSize)
        for i in 0..<tagSize { tagBytes[i] = record.fragment[ciphertextLength + i] }

        // Create a span over just the ciphertext region for in-place decrypt
        var ciphertextSlice = record.fragment._mutatingExtracting(0..<ciphertextLength)

        try tagBytes.withUnsafeBufferPointer { tagBuf in
            let tagSpan = Span<UInt8>(_unsafeElements: tagBuf)
            try AES.GCM.openEmulatingInPlace(
                message: &ciphertextSlice,
                using: key,
                nonce: nonce,
                authenticating: aad.span,
                tag: tagSpan
            )
        }

        // Strip trailing zero padding and inner content type byte
        var plaintextLength = ciphertextLength
        while plaintextLength > 0 && ciphertextSlice[plaintextLength - 1] == 0 {
            plaintextLength -= 1
        }
        guard plaintextLength > 0 else {
            throw TLSRecordProtectionError.emptyInnerPlaintext
        }
        plaintextLength -= 1
        let contentTypeByte = ciphertextSlice[plaintextLength]

        return DecryptedTLSRecordView(
            contentType: ContentType(rawValue: contentTypeByte),
            plaintext: record.fragment._mutatingExtracting(0..<plaintextLength)
        )
    }

    // MARK: - Encrypt

    /// Encrypts plaintext in-place into a TLS 1.3 record.
    ///
    /// The `buffer` must be exactly `plaintextLength + 1 + 16` bytes.
    /// The first `plaintextLength` bytes contain the plaintext.
    @_lifetime(&buffer)
    func encrypt(
        buffer: inout MutableSpan<UInt8>,
        plaintextLength: Int,
        contentType: ContentType,
        sequenceNumber: UInt64
    ) throws -> EncryptedTLSRecordView {
        let ciphertextLength = plaintextLength + 1
        let tagSize = 16
        precondition(buffer.count == ciphertextLength + tagSize)

        // Write inner content type after plaintext
        buffer[plaintextLength] = contentType.rawValue

        let nonce = try AES.GCM.Nonce(data: Self.buildNonce(iv: iv, sequenceNumber: sequenceNumber))
        let aad = Self.buildAAD(
            contentType: .applicationData,
            version: .tlsv12,
            fragmentLength: ciphertextLength + tagSize
        )

        // Encrypt ciphertext region in-place, tag into temp array, copy tag back
        var ciphertextSlice = buffer._mutatingExtracting(0..<ciphertextLength)
        var tagBytes = [UInt8](repeating: 0, count: tagSize)

        try tagBytes.withUnsafeMutableBufferPointer { tagBuf in
            var tagSpan = MutableSpan<UInt8>(_unsafeStart: tagBuf.baseAddress!, count: tagBuf.count)
            try AES.GCM.sealEmulatingInPlace(
                message: &ciphertextSlice,
                using: key,
                nonce: nonce,
                authenticating: aad.span,
                tag: &tagSpan
            )
        }

        for i in 0..<tagSize {
            buffer[ciphertextLength + i] = tagBytes[i]
        }

        return EncryptedTLSRecordView(
            contentType: .applicationData,
            version: .tlsv12,
            fragment: buffer._mutatingExtracting(0..<buffer.count)
        )
    }

    // MARK: - Internal

    package static func buildNonce(iv: [UInt8], sequenceNumber: UInt64) -> [UInt8] {
        var nonce = iv
        var seq = sequenceNumber.bigEndian
        withUnsafeBytes(of: &seq) { seqBytes in
            for i in 0..<8 {
                nonce[nonce.count - 8 + i] ^= seqBytes[i]
            }
        }
        return nonce
    }

    package static func keyLength(for cipherSuite: CipherSuite) -> Int {
        switch cipherSuite {
        case .TLS_AES_128_GCM_SHA256: 16
        case .TLS_AES_256_GCM_SHA384: 32
        case .TLS_CHACHA20_POLY1305_SHA256: 32
        default: 16
        }
    }

    private static func buildAAD(
        contentType: ContentType,
        version: ProtocolVersion,
        fragmentLength: Int
    ) -> InlineArray<5 , UInt8> {
        [
            contentType.rawValue,
            version.major, version.minor,
            UInt8(truncatingIfNeeded: fragmentLength >> 8),
            UInt8(truncatingIfNeeded: fragmentLength),
        ]
    }
}

/// Errors from TLS record encryption/decryption.
enum TLSRecordProtectionError: Error, Sendable {
    case recordTooShort
    case emptyInnerPlaintext
}
