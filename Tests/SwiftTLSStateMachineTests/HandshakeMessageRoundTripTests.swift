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

@Suite
struct HandshakeMessageRoundTripTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripFinished() throws {
        let original = HandshakeMessage.finished(FinishedMessage(
            verifyData: [0xAA, 0xBB, 0xCC, 0xDD]
        ))
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripCertificateVerify() throws {
        let original = HandshakeMessage.certificateVerify(CertificateVerify(
            algorithm: .ecdsa_secp256r1_sha256,
            signature: [0x01, 0x02, 0x03, 0x04, 0x05]
        ))
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripEncryptedExtensions() throws {
        let original = HandshakeMessage.encryptedExtensions(
            EncryptedExtensions(extensions: [
                .alpn(["h2", "http/1.1"]),
            ])
        )
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripClientHello() throws {
        let original = HandshakeMessage.clientHello(ClientHello(
            random: [UInt8](repeating: 0x42, count: 32),
            legacySessionID: [0x01, 0x02, 0x03],
            cipherSuites: [.TLS_AES_256_GCM_SHA384, .TLS_CHACHA20_POLY1305_SHA256],
            extensions: [
                .supportedVersions([.tlsv13]),
                .supportedGroups([.x25519]),
                .signatureAlgorithms([.ecdsa_secp256r1_sha256]),
            ]
        ))
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripServerHello() throws {
        let original = HandshakeMessage.serverHello(ServerHello(
            random: [UInt8](repeating: 0xDD, count: 32),
            legacySessionIDEcho: [0x01, 0x02, 0x03],
            cipherSuite: .TLS_AES_256_GCM_SHA384,
            extensions: [
                .serverSupportedVersion(.tlsv13),
            ]
        ))
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripCertificateMessage() throws {
        let original = HandshakeMessage.certificate(CertificateMessage(
            certificateList: [
                CertificateEntry(certificateData: [0xDE, 0xAD, 0xBE, 0xEF]),
            ]
        ))
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripNewSessionTicket() throws {
        let original = HandshakeMessage.newSessionTicket(NewSessionTicket(
            ticketLifetime: 86400,
            ticketAgeAdd: 0x12345678,
            ticketNonce: [0x01],
            ticket: [0xAA, 0xBB, 0xCC]
        ))
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripCertificateRequest() throws {
        let original = HandshakeMessage.certificateRequest(CertificateRequest(
            requestContext: [],
            extensions: [
                .signatureAlgorithms([.ecdsa_secp256r1_sha256]),
            ]
        ))
        let bytes = try serializeToBytes(original)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func headerFormatIsCorrect() throws {
        let msg = HandshakeMessage.finished(FinishedMessage(
            verifyData: [0x01, 0x02, 0x03]
        ))
        let bytes = try serializeToBytes(msg)
        #expect(bytes[0] == 0x14) // finished = 20
        #expect(bytes[1] == 0x00)
        #expect(bytes[2] == 0x00)
        #expect(bytes[3] == 0x03) // body length = 3
        #expect(Array(bytes[4...]) == [0x01, 0x02, 0x03])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeOneByteAtATime() throws {
        let original = HandshakeMessage.finished(FinishedMessage(
            verifyData: [0xAA, 0xBB]
        ))
        let bytes = try serializeToBytes(original, outputSpanCapacity: 1)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeClientHelloOneByteAtATime() throws {
        let original = HandshakeMessage.clientHello(ClientHello(
            random: [UInt8](repeating: 0xFF, count: 32),
            cipherSuites: [.TLS_AES_128_GCM_SHA256],
            extensions: [.supportedVersions([.tlsv13])]
        ))
        let bytes = try serializeToBytes(original, outputSpanCapacity: 1)
        let parsed = try bytes.withParserSpan { span in
            try HandshakeMessage(parsing: &span)
        }
        #expect(parsed == original)
    }
}
