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

/// A TLS 1.3 ClientHello message per RFC 8446 Section 4.1.2.
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303;
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suites<2..2^16-2>;
///     opaque legacy_compression_methods<1..2^8-1>;
///     Extension extensions<8..2^16-1>;
/// } ClientHello;
/// ```
struct ClientHello: Equatable, Sendable {
    /// Always 0x0303 (TLS 1.2) for TLS 1.3.
    var legacyVersion: ProtocolVersion

    /// 32 bytes of random data.
    var random: [UInt8]

    /// Legacy session ID for middlebox compatibility.
    var legacySessionID: [UInt8]

    /// Offered cipher suites.
    var cipherSuites: [CipherSuite]

    /// Legacy compression methods (always [0] for TLS 1.3).
    var legacyCompressionMethods: [UInt8]

    /// ClientHello extensions.
    var extensions: [TLSExtension]

    init(
        legacyVersion: ProtocolVersion = .tlsv12,
        random: [UInt8],
        legacySessionID: [UInt8] = [],
        cipherSuites: [CipherSuite],
        legacyCompressionMethods: [UInt8] = [0],
        extensions: [TLSExtension]
    ) {
        self.legacyVersion = legacyVersion
        self.random = random
        self.legacySessionID = legacySessionID
        self.cipherSuites = cipherSuites
        self.legacyCompressionMethods = legacyCompressionMethods
        self.extensions = extensions
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ClientHello: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.legacyVersion = try ProtocolVersion(parsing: &input)
        self.random = try Array(parsing: &input, byteCount: 32)

        let sessionIDLength = try UInt8(parsing: &input)
        self.legacySessionID = try Array(parsing: &input, byteCount: Int(sessionIDLength))

        let cipherSuitesLength = try UInt16(parsingBigEndian: &input)
        var suiteSpan = try input.sliceSpan(byteCount: Int(cipherSuitesLength))
        var suites: [CipherSuite] = []
        while !suiteSpan.isEmpty {
            suites.append(try CipherSuite(parsing: &suiteSpan))
        }
        self.cipherSuites = suites

        let compressionLength = try UInt8(parsing: &input)
        self.legacyCompressionMethods = try Array(
            parsing: &input, byteCount: Int(compressionLength)
        )

        let extensionsLength = try UInt16(parsingBigEndian: &input)
        var extSpan = try input.sliceSpan(byteCount: Int(extensionsLength))
        var exts: [TLSExtension] = []
        while !extSpan.isEmpty {
            exts.append(try TLSExtension(parsing: &extSpan))
        }
        self.extensions = exts
    }
}

/// A TLS 1.3 ServerHello message per RFC 8446 Section 4.1.3.
///
/// ```
/// struct {
///     ProtocolVersion legacy_version = 0x0303;
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
/// ```
struct ServerHello: Equatable, Sendable {
    /// Always 0x0303 (TLS 1.2) for TLS 1.3.
    var legacyVersion: ProtocolVersion

    /// 32 bytes of random data.
    var random: [UInt8]

    /// Echoed session ID from the ClientHello.
    var legacySessionIDEcho: [UInt8]

    /// The selected cipher suite.
    var cipherSuite: CipherSuite

    /// Legacy compression method (always 0).
    var legacyCompressionMethod: UInt8

    /// ServerHello extensions.
    var extensions: [TLSExtension]

    init(
        legacyVersion: ProtocolVersion = .tlsv12,
        random: [UInt8],
        legacySessionIDEcho: [UInt8] = [],
        cipherSuite: CipherSuite,
        legacyCompressionMethod: UInt8 = 0,
        extensions: [TLSExtension]
    ) {
        self.legacyVersion = legacyVersion
        self.random = random
        self.legacySessionIDEcho = legacySessionIDEcho
        self.cipherSuite = cipherSuite
        self.legacyCompressionMethod = legacyCompressionMethod
        self.extensions = extensions
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ServerHello: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.legacyVersion = try ProtocolVersion(parsing: &input)
        self.random = try Array(parsing: &input, byteCount: 32)

        let sessionIDLength = try UInt8(parsing: &input)
        self.legacySessionIDEcho = try Array(
            parsing: &input, byteCount: Int(sessionIDLength)
        )

        self.cipherSuite = try CipherSuite(parsing: &input)
        self.legacyCompressionMethod = try UInt8(parsing: &input)

        let extensionsLength = try UInt16(parsingBigEndian: &input)
        var extSpan = try input.sliceSpan(byteCount: Int(extensionsLength))
        var exts: [TLSExtension] = []
        while !extSpan.isEmpty {
            exts.append(try TLSExtension(parsing: &extSpan))
        }
        self.extensions = exts
    }
}
