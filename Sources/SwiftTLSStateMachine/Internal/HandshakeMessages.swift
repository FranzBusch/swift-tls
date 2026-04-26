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

public import BinaryParsing
import BinarySerialization

/// A TLS 1.3 Finished message per RFC 8446 Section 4.4.4.
///
/// Contains HMAC verify data whose length is determined by the
/// negotiated hash algorithm.
struct FinishedMessage: Equatable, Sendable {
    /// The HMAC verification data.
    var verifyData: [UInt8]

    init(verifyData: [UInt8]) {
        self.verifyData = verifyData
    }
}

/// A TLS 1.3 CertificateVerify message per RFC 8446 Section 4.4.3.
struct CertificateVerify: Equatable, Sendable {
    /// The signature algorithm used.
    var algorithm: SignatureScheme

    /// The digital signature.
    var signature: [UInt8]

    init(algorithm: SignatureScheme, signature: [UInt8]) {
        self.algorithm = algorithm
        self.signature = signature
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CertificateVerify: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.algorithm = try SignatureScheme(parsing: &input)
        let length = try UInt16(parsingBigEndian: &input)
        self.signature = try Array(parsing: &input, byteCount: Int(length))
    }
}

/// A TLS 1.3 EncryptedExtensions message per RFC 8446 Section 4.3.1.
struct EncryptedExtensions: Equatable, Sendable {
    /// The server's encrypted extensions.
    var extensions: [TLSExtension]

    init(extensions: [TLSExtension]) {
        self.extensions = extensions
    }
}

/// A single certificate entry in a Certificate message.
struct CertificateEntry: Equatable, Sendable {
    /// The DER-encoded certificate data.
    var certificateData: [UInt8]

    /// Per-certificate extensions.
    var extensions: [TLSExtension]

    init(certificateData: [UInt8], extensions: [TLSExtension] = []) {
        self.certificateData = certificateData
        self.extensions = extensions
    }
}

/// A TLS 1.3 Certificate message per RFC 8446 Section 4.4.2.
struct CertificateMessage: Equatable, Sendable {
    /// The certificate request context (empty for server certs).
    var requestContext: [UInt8]

    /// The certificate chain.
    var certificateList: [CertificateEntry]

    init(
        requestContext: [UInt8] = [],
        certificateList: [CertificateEntry]
    ) {
        self.requestContext = requestContext
        self.certificateList = certificateList
    }
}

/// A TLS 1.3 NewSessionTicket message per RFC 8446 Section 4.6.1.
struct NewSessionTicket: Equatable, Sendable {
    /// Ticket lifetime in seconds.
    var ticketLifetime: UInt32

    /// Random value for obfuscating ticket age.
    var ticketAgeAdd: UInt32

    /// Per-ticket nonce.
    var ticketNonce: [UInt8]

    /// The opaque ticket value.
    var ticket: [UInt8]

    /// Ticket extensions.
    var extensions: [TLSExtension]

    init(
        ticketLifetime: UInt32,
        ticketAgeAdd: UInt32,
        ticketNonce: [UInt8],
        ticket: [UInt8],
        extensions: [TLSExtension] = []
    ) {
        self.ticketLifetime = ticketLifetime
        self.ticketAgeAdd = ticketAgeAdd
        self.ticketNonce = ticketNonce
        self.ticket = ticket
        self.extensions = extensions
    }
}

/// A TLS 1.3 CertificateRequest message per RFC 8446 Section 4.3.2.
struct CertificateRequest: Equatable, Sendable {
    /// The certificate request context.
    var requestContext: [UInt8]

    /// Request extensions (e.g., signature_algorithms).
    var extensions: [TLSExtension]

    init(requestContext: [UInt8], extensions: [TLSExtension]) {
        self.requestContext = requestContext
        self.extensions = extensions
    }
}
