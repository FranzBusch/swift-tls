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

/// A non-owning view over an encrypted TLS record in a buffer.
///
/// The `fragment` contains `[ciphertext | tag(16)]` matching the TLS
/// wire format. Pass to
/// ``TLSRecordProtection/decrypt(record:sequenceNumber:)`` to get a
/// ``DecryptedTLSRecordView``. Produced by
/// ``TLSRecordProtection/encrypt(buffer:plaintextLength:contentType:sequenceNumber:)``.
public struct EncryptedTLSRecordView: ~Copyable, ~Escapable {
    /// The outer content type from the record header.
    public let contentType: ContentType

    /// The protocol version from the record header.
    public let version: ProtocolVersion

    /// The record fragment: `[ciphertext | tag(16)]`.
    public var fragment: MutableSpan<UInt8>

    @_lifetime(copy fragment)
    public init(
        contentType: ContentType,
        version: ProtocolVersion,
        fragment: consuming MutableSpan<UInt8>
    ) {
        self.contentType = contentType
        self.version = version
        self.fragment = fragment
    }
}
