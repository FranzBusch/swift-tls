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

// MARK: - Test helper

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
func roundTrip<T: ExpressibleByParsing & SerializableToBytes & Equatable>(
    _ value: T,
    outputSpanCapacity: Int = 256
) throws {
    let bytes = try serializeToBytes(value, outputSpanCapacity: outputSpanCapacity)
    let parsed = try bytes.withParserSpan { span in
        try T(parsing: &span)
    }
    #expect(parsed == value)
}

// MARK: - ContentType

@Suite
struct ContentTypeTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseContentType() throws {
        let bytes: [UInt8] = [22]
        let parsed = try bytes.withParserSpan { span in
            try ContentType(parsing: &span)
        }
        #expect(parsed == .handshake)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeContentType() throws {
        let bytes = try serializeToBytes(ContentType.applicationData)
        #expect(bytes == [23])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripContentType() throws {
        try roundTrip(ContentType.handshake)
        try roundTrip(ContentType.alert)
        try roundTrip(ContentType.applicationData)
        try roundTrip(ContentType.changeCipherSpec)
        try roundTrip(ContentType.invalid)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeOneByteAtATime() throws {
        let bytes = try serializeToBytes(ContentType.handshake, outputSpanCapacity: 1)
        #expect(bytes == [22])
    }
}

// MARK: - ProtocolVersion

@Suite
struct ProtocolVersionTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseTLS12() throws {
        let bytes: [UInt8] = [0x03, 0x03]
        let parsed = try bytes.withParserSpan { span in
            try ProtocolVersion(parsing: &span)
        }
        #expect(parsed == .tlsv12)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseTLS13() throws {
        let bytes: [UInt8] = [0x03, 0x04]
        let parsed = try bytes.withParserSpan { span in
            try ProtocolVersion(parsing: &span)
        }
        #expect(parsed == .tlsv13)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeTLS12() throws {
        let bytes = try serializeToBytes(ProtocolVersion.tlsv12)
        #expect(bytes == [0x03, 0x03])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripAllVersions() throws {
        try roundTrip(ProtocolVersion.sslv3)
        try roundTrip(ProtocolVersion.tlsv10)
        try roundTrip(ProtocolVersion.tlsv11)
        try roundTrip(ProtocolVersion.tlsv12)
        try roundTrip(ProtocolVersion.tlsv13)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeOneByteAtATime() throws {
        let bytes = try serializeToBytes(ProtocolVersion.tlsv13, outputSpanCapacity: 1)
        #expect(bytes == [0x03, 0x04])
    }
}

// MARK: - HandshakeType

@Suite
struct HandshakeTypeTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseClientHello() throws {
        let bytes: [UInt8] = [1]
        let parsed = try bytes.withParserSpan { span in
            try HandshakeType(parsing: &span)
        }
        #expect(parsed == .clientHello)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripHandshakeTypes() throws {
        try roundTrip(HandshakeType.clientHello)
        try roundTrip(HandshakeType.serverHello)
        try roundTrip(HandshakeType.encryptedExtensions)
        try roundTrip(HandshakeType.certificate)
        try roundTrip(HandshakeType.certificateVerify)
        try roundTrip(HandshakeType.finished)
        try roundTrip(HandshakeType.newSessionTicket)
        try roundTrip(HandshakeType.keyUpdate)
    }
}

// MARK: - CipherSuite

@Suite
struct CipherSuiteTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseAES256() throws {
        let bytes: [UInt8] = [0x13, 0x02]
        let parsed = try bytes.withParserSpan { span in
            try CipherSuite(parsing: &span)
        }
        #expect(parsed == .TLS_AES_256_GCM_SHA384)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeAES128() throws {
        let bytes = try serializeToBytes(CipherSuite.TLS_AES_128_GCM_SHA256)
        #expect(bytes == [0x13, 0x01])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripCipherSuites() throws {
        try roundTrip(CipherSuite.TLS_AES_128_GCM_SHA256)
        try roundTrip(CipherSuite.TLS_AES_256_GCM_SHA384)
        try roundTrip(CipherSuite.TLS_CHACHA20_POLY1305_SHA256)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeOneByteAtATime() throws {
        let bytes = try serializeToBytes(
            CipherSuite.TLS_AES_256_GCM_SHA384,
            outputSpanCapacity: 1
        )
        #expect(bytes == [0x13, 0x02])
    }
}

// MARK: - NamedGroup

@Suite
struct NamedGroupTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseX25519() throws {
        let bytes: [UInt8] = [0x00, 0x1D]
        let parsed = try bytes.withParserSpan { span in
            try NamedGroup(parsing: &span)
        }
        #expect(parsed == .x25519)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripNamedGroups() throws {
        try roundTrip(NamedGroup.secp256)
        try roundTrip(NamedGroup.secp384)
        try roundTrip(NamedGroup.x25519)
        try roundTrip(NamedGroup.x25519MLKEM768)
    }
}

// MARK: - SignatureScheme

@Suite
struct SignatureSchemeTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseECDSA256() throws {
        let bytes: [UInt8] = [0x04, 0x03]
        let parsed = try bytes.withParserSpan { span in
            try SignatureScheme(parsing: &span)
        }
        #expect(parsed == .ecdsa_secp256r1_sha256)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripSignatureSchemes() throws {
        try roundTrip(SignatureScheme.ecdsa_secp256r1_sha256)
        try roundTrip(SignatureScheme.ecdsa_secp384r1_sha384)
        try roundTrip(SignatureScheme.rsa_pss_rsae_sha256)
    }
}

// MARK: - CertificateType

@Suite
struct CertificateTypeTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseX509() throws {
        let bytes: [UInt8] = [0]
        let parsed = try bytes.withParserSpan { span in
            try CertificateType(parsing: &span)
        }
        #expect(parsed == .x509)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripCertificateTypes() throws {
        try roundTrip(CertificateType.x509)
        try roundTrip(CertificateType.rawPublicKey)
    }
}

// MARK: - Alert

@Suite
struct AlertTests {
    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseCloseNotify() throws {
        let bytes: [UInt8] = [1, 0]
        let parsed = try bytes.withParserSpan { span in
            try Alert(parsing: &span)
        }
        #expect(parsed == .closeNotify)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseFatalAlert() throws {
        let bytes: [UInt8] = [2, 40]
        let parsed = try bytes.withParserSpan { span in
            try Alert(parsing: &span)
        }
        #expect(parsed == .handshakeFailure)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeAlert() throws {
        let bytes = try serializeToBytes(Alert.internalError)
        #expect(bytes == [2, 80])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func roundTripAlerts() throws {
        try roundTrip(Alert.closeNotify)
        try roundTrip(Alert.handshakeFailure)
        try roundTrip(Alert.internalError)
        try roundTrip(Alert.badRecordMac)
        try roundTrip(Alert.decodeError)
        try roundTrip(Alert.noApplicationProtocol)
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func serializeOneByteAtATime() throws {
        let bytes = try serializeToBytes(Alert.handshakeFailure, outputSpanCapacity: 1)
        #expect(bytes == [2, 40])
    }

    @Test
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
    func parseInsufficientData() throws {
        let bytes: [UInt8] = [1]
        #expect(throws: (any Error).self) {
            try bytes.withParserSpan { span in
                try Alert(parsing: &span)
            }
        }
    }
}
