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

/// A non-owning view over a decrypted TLS record.
///
/// Returned by ``TLSRecordProtection/decrypt(record:sequenceNumber:)-1lsk``
/// after in-place decryption. Contains the inner content type (stripped
/// from the decrypted plaintext) and a `MutableSpan` over the plaintext
/// bytes in the framing buffer.
public struct DecryptedTLSRecordView: ~Copyable, ~Escapable {
    /// The inner content type from the encrypted record
    /// (e.g., `.handshake` or `.applicationData`).
    public let contentType: ContentType

    /// The decrypted plaintext, borrowing from the framing buffer.
    public var plaintext: MutableSpan<UInt8>

    @_lifetime(copy plaintext)
    public init(
        contentType: ContentType,
        plaintext: consuming MutableSpan<UInt8>
    ) {
        self.contentType = contentType
        self.plaintext = plaintext
    }
}
