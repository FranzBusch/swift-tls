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

import BinaryParsing
import BinarySerialization
@testable import SwiftTLSStateMachine
import Testing

// MARK: - TLSExtension tests

@Suite
struct TLSExtensionTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseExtension() throws {
        // supported_versions extension with TLS 1.3
        let bytes: [UInt8] = [
            0x00, 0x2B,  // type = supportedVersions (43)
            0x00, 0x03,  // length = 3
            0x02,        // list length = 2
            0x03, 0x04,  // TLS 1.3
        ]
        let ext = try bytes.withParserSpan { span in
            try TLSExtension(parsing: &span)
        }
        #expect(ext.type == .supportedVersions)
        #expect(ext.data == [0x02, 0x03, 0x04])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripExtension() throws {
        let ext = TLSExtension.supportedVersions([.tlsv13, .tlsv12])
        let bytes = try serializeToBytes(ext)
        let parsed = try bytes.withParserSpan { span in
            try TLSExtension(parsing: &span)
        }
        #expect(parsed == ext)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeOneByteAtATime() throws {
        let ext = TLSExtension(type: .serverName, data: [0x01, 0x02])
        let bytes = try serializeToBytes(ext, outputSpanCapacity: 1)
        #expect(bytes == [0x00, 0x00, 0x00, 0x02, 0x01, 0x02])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func emptyExtensionData() throws {
        let ext = TLSExtension(type: .earlyData, data: [])
        let bytes = try serializeToBytes(ext)
        #expect(bytes == [0x00, 0x2A, 0x00, 0x00])
        let parsed = try bytes.withParserSpan { span in
            try TLSExtension(parsing: &span)
        }
        #expect(parsed == ext)
    }
}

// MARK: - ClientHello tests

@Suite
struct ClientHelloTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseMinimalClientHello() throws {
        var bytes: [UInt8] = []
        // legacy_version
        bytes.append(contentsOf: [0x03, 0x03])
        // random (32 bytes)
        bytes.append(contentsOf: [UInt8](repeating: 0xAA, count: 32))
        // legacy_session_id (empty)
        bytes.append(0x00)
        // cipher_suites (2 bytes: one suite)
        bytes.append(contentsOf: [0x00, 0x02, 0x13, 0x01])
        // legacy_compression_methods
        bytes.append(contentsOf: [0x01, 0x00])
        // extensions (empty list)
        bytes.append(contentsOf: [0x00, 0x00])

        let hello = try bytes.withParserSpan { span in
            try ClientHello(parsing: &span)
        }
        #expect(hello.legacyVersion == .tlsv12)
        #expect(hello.random.count == 32)
        #expect(hello.legacySessionID.isEmpty)
        #expect(hello.cipherSuites == [.TLS_AES_128_GCM_SHA256])
        #expect(hello.legacyCompressionMethods == [0])
        #expect(hello.extensions.isEmpty)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseClientHelloWithExtensions() throws {
        var bytes: [UInt8] = []
        bytes.append(contentsOf: [0x03, 0x03])
        bytes.append(contentsOf: [UInt8](repeating: 0xBB, count: 32))
        bytes.append(0x00) // no session ID
        bytes.append(contentsOf: [0x00, 0x04, 0x13, 0x01, 0x13, 0x02]) // 2 suites
        bytes.append(contentsOf: [0x01, 0x00]) // compression
        // extensions: supported_versions with TLS 1.3
        let extData: [UInt8] = [0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]
        let extLen = UInt16(extData.count)
        bytes.append(UInt8(truncatingIfNeeded: extLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: extLen))
        bytes.append(contentsOf: extData)

        let hello = try bytes.withParserSpan { span in
            try ClientHello(parsing: &span)
        }
        #expect(hello.cipherSuites.count == 2)
        #expect(hello.extensions.count == 1)
        #expect(hello.extensions[0].type == .supportedVersions)
    }
}

// MARK: - ServerHello tests

@Suite
struct ServerHelloTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseMinimalServerHello() throws {
        var bytes: [UInt8] = []
        bytes.append(contentsOf: [0x03, 0x03]) // version
        bytes.append(contentsOf: [UInt8](repeating: 0xCC, count: 32)) // random
        bytes.append(0x00) // session ID echo (empty)
        bytes.append(contentsOf: [0x13, 0x02]) // cipher suite
        bytes.append(0x00) // compression
        // extensions: supported_versions with TLS 1.3
        let extData: [UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]
        let extLen = UInt16(extData.count)
        bytes.append(UInt8(truncatingIfNeeded: extLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: extLen))
        bytes.append(contentsOf: extData)

        let hello = try bytes.withParserSpan { span in
            try ServerHello(parsing: &span)
        }
        #expect(hello.legacyVersion == .tlsv12)
        #expect(hello.cipherSuite == .TLS_AES_256_GCM_SHA384)
        #expect(hello.legacyCompressionMethod == 0)
        #expect(hello.extensions.count == 1)
    }
}

// MARK: - Other message tests

@Suite
struct HandshakeMessageTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseCertificateVerify() throws {
        var bytes: [UInt8] = []
        bytes.append(contentsOf: [0x04, 0x03]) // ecdsa_secp256r1_sha256
        bytes.append(contentsOf: [0x00, 0x03]) // signature length = 3
        bytes.append(contentsOf: [0xAA, 0xBB, 0xCC]) // signature

        let cv = try bytes.withParserSpan { span in
            try CertificateVerify(parsing: &span)
        }
        #expect(cv.algorithm == .ecdsa_secp256r1_sha256)
        #expect(cv.signature == [0xAA, 0xBB, 0xCC])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseEncryptedExtensions() throws {
        // Empty extensions list
        let bytes: [UInt8] = [0x00, 0x00]
        let ee = try bytes.withParserSpan { span in
            try EncryptedExtensions(parsing: &span)
        }
        #expect(ee.extensions.isEmpty)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseEncryptedExtensionsWithALPN() throws {
        // ALPN extension with "h2"
        let alpnExt: [UInt8] = [
            0x00, 0x10,  // type = ALPN (16)
            0x00, 0x05,  // ext length = 5
            0x00, 0x03,  // list length = 3
            0x02,        // protocol length = 2
            0x68, 0x32,  // "h2"
        ]
        var bytes: [UInt8] = []
        let totalLen = UInt16(alpnExt.count)
        bytes.append(UInt8(truncatingIfNeeded: totalLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: totalLen))
        bytes.append(contentsOf: alpnExt)

        let ee = try bytes.withParserSpan { span in
            try EncryptedExtensions(parsing: &span)
        }
        #expect(ee.extensions.count == 1)
        #expect(ee.extensions[0].type == .applicationLayerProtocolNegotiation)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseNewSessionTicket() throws {
        var bytes: [UInt8] = []
        bytes.append(contentsOf: [0x00, 0x01, 0x51, 0x80]) // lifetime = 86400
        bytes.append(contentsOf: [0x12, 0x34, 0x56, 0x78]) // age_add
        bytes.append(contentsOf: [0x02, 0xAA, 0xBB]) // nonce (length=2)
        bytes.append(contentsOf: [0x00, 0x03, 0x01, 0x02, 0x03]) // ticket (length=3)
        bytes.append(contentsOf: [0x00, 0x00]) // extensions (empty)

        let nst = try bytes.withParserSpan { span in
            try NewSessionTicket(parsing: &span)
        }
        #expect(nst.ticketLifetime == 86400)
        #expect(nst.ticketAgeAdd == 0x12345678)
        #expect(nst.ticketNonce == [0xAA, 0xBB])
        #expect(nst.ticket == [0x01, 0x02, 0x03])
        #expect(nst.extensions.isEmpty)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseCertificateMessage() throws {
        var bytes: [UInt8] = []
        bytes.append(0x00) // request_context length = 0
        // certificate_list: one entry with 3-byte cert
        let certData: [UInt8] = [0xDE, 0xAD, 0xBE]
        let entryBytes: [UInt8] = [
            0x00, 0x00, 0x03,  // cert_data length (UInt24)
        ] + certData + [
            0x00, 0x00,  // extensions length
        ]
        let listLen = entryBytes.count
        bytes.append(UInt8(truncatingIfNeeded: listLen >> 16))
        bytes.append(UInt8(truncatingIfNeeded: listLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: listLen))
        bytes.append(contentsOf: entryBytes)

        let cert = try bytes.withParserSpan { span in
            try CertificateMessage(parsing: &span)
        }
        #expect(cert.requestContext.isEmpty)
        #expect(cert.certificateList.count == 1)
        #expect(cert.certificateList[0].certificateData == [0xDE, 0xAD, 0xBE])
        #expect(cert.certificateList[0].extensions.isEmpty)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseCertificateRequest() throws {
        var bytes: [UInt8] = []
        bytes.append(0x00) // request_context length = 0
        // extensions: signature_algorithms
        let sigAlgExt: [UInt8] = [
            0x00, 0x0D,  // type = signature_algorithms
            0x00, 0x04,  // ext length
            0x00, 0x02,  // list length
            0x04, 0x03,  // ecdsa_secp256r1_sha256
        ]
        let extLen = UInt16(sigAlgExt.count)
        bytes.append(UInt8(truncatingIfNeeded: extLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: extLen))
        bytes.append(contentsOf: sigAlgExt)

        let cr = try bytes.withParserSpan { span in
            try CertificateRequest(parsing: &span)
        }
        #expect(cr.requestContext.isEmpty)
        #expect(cr.extensions.count == 1)
        #expect(cr.extensions[0].type == .signatureAlgorithms)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func handshakeMessageTypeMapping() {
        let msg = HandshakeMessage.clientHello(ClientHello(
            random: [UInt8](repeating: 0, count: 32),
            cipherSuites: [.TLS_AES_128_GCM_SHA256],
            extensions: []
        ))
        #expect(msg.handshakeType == .clientHello)

        let fin = HandshakeMessage.finished(FinishedMessage(
            verifyData: [0x01, 0x02]
        ))
        #expect(fin.handshakeType == .finished)
    }
}
