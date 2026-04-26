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

import Crypto
@testable import SwiftTLSStateMachine
import Testing

@Suite
struct TLSRecordProtectionTests {
    let trafficSecret = SymmetricKey(data: [UInt8](repeating: 0x42, count: 32))

    private func encryptInPlace(
        protection: TLSRecordProtection,
        plaintext: [UInt8],
        contentType: ContentType,
        sequenceNumber: UInt64
    ) throws -> [UInt8] {
        let fragmentLength = plaintext.count + 1 + 16
        var buffer = [UInt8](repeating: 0, count: fragmentLength)
        for i in 0..<plaintext.count { buffer[i] = plaintext[i] }
        try buffer.withUnsafeMutableBufferPointer { buf in
            var span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            _ = try protection.encrypt(
                buffer: &span,
                plaintextLength: plaintext.count,
                contentType: contentType,
                sequenceNumber: sequenceNumber
            )
        }
        return buffer
    }

    private func decryptInPlace(
        protection: TLSRecordProtection,
        fragment: inout [UInt8],
        sequenceNumber: UInt64
    ) throws -> (plaintext: [UInt8], contentType: ContentType) {
        try fragment.withUnsafeMutableBufferPointer { buf in
            let span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            var view = EncryptedTLSRecordView(
                contentType: .applicationData,
                version: .tlsv12,
                fragment: span
            )
            let decrypted = try protection.decrypt(record: &view, sequenceNumber: sequenceNumber)
            var plaintextBytes = [UInt8](repeating: 0, count: decrypted.plaintext.count)
            for i in 0..<decrypted.plaintext.count { plaintextBytes[i] = decrypted.plaintext[i] }
            return (plaintextBytes, decrypted.contentType)
        }
    }

    @Test func encryptDecryptRoundTrip() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        let plaintext: [UInt8] = Array("hello, TLS".utf8)

        var fragment = try encryptInPlace(
            protection: protection, plaintext: plaintext,
            contentType: .applicationData, sequenceNumber: 0
        )
        let (decrypted, contentType) = try decryptInPlace(
            protection: protection, fragment: &fragment, sequenceNumber: 0
        )
        #expect(decrypted == plaintext)
        #expect(contentType == .applicationData)
    }

    @Test func innerContentTypePreserved() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        var fragment = try encryptInPlace(
            protection: protection, plaintext: [0x01, 0x02, 0x03],
            contentType: .handshake, sequenceNumber: 0
        )
        let (_, innerType) = try decryptInPlace(
            protection: protection, fragment: &fragment, sequenceNumber: 0
        )
        #expect(innerType == .handshake)
    }

    @Test func sequenceNumberAffectsNonce() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        let plaintext: [UInt8] = [0xAA, 0xBB]

        let enc0 = try encryptInPlace(
            protection: protection, plaintext: plaintext,
            contentType: .applicationData, sequenceNumber: 0
        )
        let enc1 = try encryptInPlace(
            protection: protection, plaintext: plaintext,
            contentType: .applicationData, sequenceNumber: 1
        )
        #expect(enc0 != enc1)

        var frag0 = enc0
        var frag1 = enc1
        let (dec0, _) = try decryptInPlace(protection: protection, fragment: &frag0, sequenceNumber: 0)
        let (dec1, _) = try decryptInPlace(protection: protection, fragment: &frag1, sequenceNumber: 1)
        #expect(dec0 == plaintext)
        #expect(dec1 == plaintext)
    }

    @Test func wrongSequenceNumberFailsDecrypt() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        var fragment = try encryptInPlace(
            protection: protection, plaintext: [0x01],
            contentType: .applicationData, sequenceNumber: 5
        )
        #expect(throws: (any Error).self) {
            _ = try decryptInPlace(protection: protection, fragment: &fragment, sequenceNumber: 6)
        }
    }

    @Test func tamperedCiphertextFailsDecrypt() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        var fragment = try encryptInPlace(
            protection: protection, plaintext: Array("secret".utf8),
            contentType: .applicationData, sequenceNumber: 0
        )
        fragment[0] ^= 0xFF
        #expect(throws: (any Error).self) {
            _ = try decryptInPlace(protection: protection, fragment: &fragment, sequenceNumber: 0)
        }
    }

    @Test func recordTooShortForTag() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        var shortFragment = [UInt8](repeating: 0, count: 10)
        shortFragment.withUnsafeMutableBufferPointer { buf in
            let span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            var view = EncryptedTLSRecordView(
                contentType: .applicationData, version: .tlsv12, fragment: span
            )
            #expect(throws: TLSRecordProtectionError.self) {
                _ = try protection.decrypt(record: &view, sequenceNumber: 0)
            }
        }
    }

    @Test func emptyPlaintext() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        var fragment = try encryptInPlace(
            protection: protection, plaintext: [],
            contentType: .applicationData, sequenceNumber: 0
        )
        let (decrypted, contentType) = try decryptInPlace(
            protection: protection, fragment: &fragment, sequenceNumber: 0
        )
        #expect(decrypted.isEmpty)
        #expect(contentType == .applicationData)
    }

    @Test func largePayload() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        let plaintext = [UInt8](repeating: 0xDE, count: 16384)
        var fragment = try encryptInPlace(
            protection: protection, plaintext: plaintext,
            contentType: .applicationData, sequenceNumber: 42
        )
        let (decrypted, _) = try decryptInPlace(
            protection: protection, fragment: &fragment, sequenceNumber: 42
        )
        #expect(decrypted == plaintext)
    }

    @Test func differentKeysCannotDecrypt() throws {
        let encryptor = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        let otherSecret = SymmetricKey(data: [UInt8](repeating: 0x99, count: 32))
        let decryptor = TLSRecordProtection(
            trafficSecret: otherSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        var fragment = try encryptInPlace(
            protection: encryptor, plaintext: [0x01],
            contentType: .applicationData, sequenceNumber: 0
        )
        #expect(throws: (any Error).self) {
            _ = try decryptInPlace(protection: decryptor, fragment: &fragment, sequenceNumber: 0)
        }
    }

    @Test func multipleRecordsWithIncrementingSequence() throws {
        let protection = TLSRecordProtection(
            trafficSecret: trafficSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        for seq: UInt64 in 0..<10 {
            let plaintext = [UInt8(truncatingIfNeeded: seq)]
            var fragment = try encryptInPlace(
                protection: protection, plaintext: plaintext,
                contentType: .applicationData, sequenceNumber: seq
            )
            let (decrypted, _) = try decryptInPlace(
                protection: protection, fragment: &fragment, sequenceNumber: seq
            )
            #expect(decrypted == plaintext)
        }
    }
}
