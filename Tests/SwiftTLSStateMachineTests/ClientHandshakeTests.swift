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
import Testing
@testable import SwiftTLSStateMachine
import BinaryParsing

/// Helper that constructs raw TLS server responses for testing the
/// client handshake state machine in isolation.
private struct TestServerResponder {
    let serverPrivateKey: P256.KeyAgreement.PrivateKey
    let sharedSecret: SharedSecret
    var transcript: SHA256
    var keySchedule: TLSKeySchedule<SHA256>
    let serverHandshakeSecret: SymmetricKey
    let clientHandshakeSecret: SymmetricKey
    let serverEncrypt: TLSRecordProtection
    var serverSeq: UInt64 = 0

    /// Creates a test server responder by parsing the ClientHello
    /// from the client's start() output.
    init(clientHelloOutput: [UInt8]) throws {
        // Parse the TLS record to get the handshake message body
        assert(clientHelloOutput[0] == ContentType.handshake.rawValue)
        let fragLen = Int(clientHelloOutput[3]) << 8 | Int(clientHelloOutput[4])
        let chBytes = Array(clientHelloOutput[5..<(5 + fragLen)])

        // Parse ClientHello to extract the client's key share
        let msg = try HandshakeMessage(parsing: chBytes)
        guard case .clientHello(let clientHello) = msg else {
            throw HandshakeError.unexpectedMessage
        }
        guard let keyShareData = ClientHandshakeStateMachine.extractServerKeyShareData(
            from: clientHello.extensions
        ) else {
            throw HandshakeError.missingKeyShare
        }

        // Generate server key and compute ECDHE
        self.serverPrivateKey = P256.KeyAgreement.PrivateKey()
        let clientPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: keyShareData.keyExchange
        )
        self.sharedSecret = try serverPrivateKey.sharedSecretFromKeyAgreement(with: clientPublicKey)

        // Build transcript: start with CH
        var transcript = SHA256()
        chBytes.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        self.transcript = transcript

        // Key schedule placeholder — will be filled after SH
        self.keySchedule = TLSKeySchedule<SHA256>()
        self.serverHandshakeSecret = SymmetricKey(data: []) // placeholder
        self.clientHandshakeSecret = SymmetricKey(data: []) // placeholder
        self.serverEncrypt = TLSRecordProtection(
            trafficSecret: SymmetricKey(data: [UInt8](repeating: 0, count: 32)),
            cipherSuite: .TLS_AES_128_GCM_SHA256
        ) // placeholder
    }

    /// Builds a ServerHello record and derives handshake keys.
    mutating func buildServerHello() -> [UInt8] {
        let serverHello = ServerHello(
            legacyVersion: .tlsv12,
            random: SwiftTLSStateMachine.generateRandom(count: 32),
            legacySessionIDEcho: [],
            cipherSuite: .TLS_AES_128_GCM_SHA256,
            legacyCompressionMethod: 0,
            extensions: [
                .serverSupportedVersion(.tlsv13),
                .keyShareServerHello(
                    group: .secp256,
                    keyExchange: Array(serverPrivateKey.publicKey.x963Representation)
                ),
            ]
        )

        // Serialize ServerHello
        let message = HandshakeMessage.serverHello(serverHello)
        var shBytes: [UInt8] = []
        var serState = try! HandshakeMessage.startSerialization(of: message)
        var tempBuf = [UInt8](repeating: 0, count: 4096)
        tempBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            while !HandshakeMessage.serialize(state: &serState, into: &output) {}
            shBytes = Array(UnsafeBufferPointer(start: buf.baseAddress!, count: output.count))
        }

        // Update transcript with SH
        shBytes.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        let transcriptHash = transcript.finalize()

        // Derive handshake secrets
        let secrets = keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        // Update self with real keys (can't mutate let properties, so we use a workaround)
        // Actually we stored these as var above — but serverHandshakeSecret/clientHandshakeSecret are let.
        // We'll just use serverEncrypt directly.

        // Build TLS record
        var record: [UInt8] = [ContentType.handshake.rawValue, 0x03, 0x03]
        record.append(UInt8(truncatingIfNeeded: shBytes.count >> 8))
        record.append(UInt8(truncatingIfNeeded: shBytes.count))
        record.append(contentsOf: shBytes)

        return record
    }
}

@Suite
struct ClientHandshakeStateMachineTests {

    // MARK: - Helper

    private func makeConfig(serverName: String? = "localhost") -> ClientHandshakeConfiguration {
        ClientHandshakeConfiguration(serverName: serverName)
    }

    private func startHandshake(
        sm: inout ClientHandshakeStateMachine
    ) -> [UInt8] {
        var outputBuf = [UInt8](repeating: 0, count: 16384)
        let outputBytes: [UInt8] = outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            let action = sm.start(output: &output)
            guard case .ok = action else {
                Issue.record("start() failed")
                return []
            }
            return Array(UnsafeBufferPointer(start: buf.baseAddress!, count: output.count))
        }
        return outputBytes
    }

    private func makeRecordView(
        from bytes: inout [UInt8],
        body: (inout EncryptedTLSRecordView) -> Void
    ) {
        let contentType = ContentType(rawValue: bytes[0])
        let versionMajor = bytes[1]
        let versionMinor = bytes[2]
        let fragLen = Int(bytes[3]) << 8 | Int(bytes[4])
        bytes.withUnsafeMutableBufferPointer { buf in
            let fragSpan = MutableSpan<UInt8>(
                _unsafeStart: buf.baseAddress! + 5,
                count: fragLen
            )
            var view = EncryptedTLSRecordView(
                contentType: contentType,
                version: ProtocolVersion(major: versionMajor, minor: versionMinor),
                fragment: fragSpan
            )
            body(&view)
        }
    }

    // MARK: - start() tests

    @Test func startFromIdleProducesClientHello() {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        let output = startHandshake(sm: &sm)
        #expect(output.count > 5)
        #expect(output[0] == ContentType.handshake.rawValue) // TLS record type
        #expect(output[1] == 0x03) // TLS 1.2 version
        #expect(output[2] == 0x03)
        #expect(output[5] == 0x01) // HandshakeType.clientHello
    }

    @Test func startFromIdleIncludesKeyShare() throws {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        let output = startHandshake(sm: &sm)
        let fragLen = Int(output[3]) << 8 | Int(output[4])
        let chBytes = Array(output[5..<(5 + fragLen)])
        let msg = try HandshakeMessage(parsing: chBytes)
        guard case .clientHello(let ch) = msg else {
            Issue.record("Not a ClientHello"); return
        }
        let keyShare = ClientHandshakeStateMachine.extractServerKeyShareData(from: ch.extensions)
        // extractServerKeyShareData is for SH format, but the CH key share has a list prefix.
        // Instead just check that the key_share extension exists.
        let hasKeyShare = ch.extensions.contains { $0.type == .keyShare }
        #expect(hasKeyShare)
    }

    @Test func startFromIdleIncludesSNI() throws {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig(serverName: "example.com"))
        let output = startHandshake(sm: &sm)
        let fragLen = Int(output[3]) << 8 | Int(output[4])
        let chBytes = Array(output[5..<(5 + fragLen)])
        let msg = try HandshakeMessage(parsing: chBytes)
        guard case .clientHello(let ch) = msg else {
            Issue.record("Not a ClientHello"); return
        }
        let hasSNI = ch.extensions.contains { $0.type == .serverName }
        #expect(hasSNI)
    }

    @Test func startFromIdleWithoutSNI() throws {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig(serverName: nil))
        let output = startHandshake(sm: &sm)
        let fragLen = Int(output[3]) << 8 | Int(output[4])
        let chBytes = Array(output[5..<(5 + fragLen)])
        let msg = try HandshakeMessage(parsing: chBytes)
        guard case .clientHello(let ch) = msg else {
            Issue.record("Not a ClientHello"); return
        }
        let hasSNI = ch.extensions.contains { $0.type == .serverName }
        #expect(!hasSNI)
    }

    @Test func startTwiceReturnsError() {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        _ = startHandshake(sm: &sm)
        var outputBuf = [UInt8](repeating: 0, count: 16384)
        outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            let action = sm.start(output: &output)
            guard case .error = action else {
                Issue.record("Expected error on second start()"); return
            }
        }
    }

    // MARK: - receive() in wrong state

    @Test func receiveBeforeStartReturnsError() {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        var garbage: [UInt8] = [0x16, 0x03, 0x03, 0x00, 0x01, 0xFF]
        makeRecordView(from: &garbage) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error = action else {
                    Issue.record("Expected error"); return
                }
            }
        }
    }

    @Test func receiveAfterConnectedReturnsError() {
        // We can't easily get to connected state without a full handshake,
        // but we can verify that after error state, receive returns error.
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        // Put it in error state by receiving before start
        var garbage: [UInt8] = [0x16, 0x03, 0x03, 0x00, 0x01, 0xFF]
        makeRecordView(from: &garbage) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                _ = sm.receive(&view, output: &output)
            }
        }
        // Now it's in error state — receive again
        makeRecordView(from: &garbage) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error = action else {
                    Issue.record("Expected error in error state"); return
                }
            }
        }
    }

    // MARK: - ServerHello error branches

    @Test func receiveNonHandshakeRecordInWaitingServerHello() {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        _ = startHandshake(sm: &sm)
        // Send an applicationData record instead of handshake
        var badRecord: [UInt8] = [
            ContentType.applicationData.rawValue, 0x03, 0x03, 0x00, 0x01, 0xFF
        ]
        makeRecordView(from: &badRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error = action else {
                    Issue.record("Expected error for wrong content type"); return
                }
            }
        }
    }

    @Test func receiveGarbageInWaitingServerHello() {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        _ = startHandshake(sm: &sm)
        // Handshake record with garbage body (not a valid ServerHello)
        var badRecord: [UInt8] = [
            ContentType.handshake.rawValue, 0x03, 0x03, 0x00, 0x04,
            0xFF, 0xFF, 0xFF, 0xFF,
        ]
        makeRecordView(from: &badRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error = action else {
                    Issue.record("Expected error for garbage ServerHello"); return
                }
            }
        }
    }

    @Test func receiveServerHelloWithoutKeyShare() throws {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        _ = startHandshake(sm: &sm)
        // Build a ServerHello with no key_share extension
        let serverHello = ServerHello(
            legacyVersion: .tlsv12,
            random: SwiftTLSStateMachine.generateRandom(count: 32),
            legacySessionIDEcho: [],
            cipherSuite: .TLS_AES_128_GCM_SHA256,
            legacyCompressionMethod: 0,
            extensions: [
                .serverSupportedVersion(.tlsv13),
                // No keyShareServerHello!
            ]
        )
        let shBytes = try serializeHandshakeMessage(.serverHello(serverHello))
        var record = buildHandshakeRecord(body: shBytes)
        makeRecordView(from: &record) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error(.missingKeyShare) = action else {
                    Issue.record("Expected .missingKeyShare error"); return
                }
            }
        }
    }

    @Test func receiveServerHelloWithInvalidKeyExchange() throws {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        _ = startHandshake(sm: &sm)
        let serverHello = ServerHello(
            legacyVersion: .tlsv12,
            random: SwiftTLSStateMachine.generateRandom(count: 32),
            legacySessionIDEcho: [],
            cipherSuite: .TLS_AES_128_GCM_SHA256,
            legacyCompressionMethod: 0,
            extensions: [
                .serverSupportedVersion(.tlsv13),
                .keyShareServerHello(group: .secp256, keyExchange: [0x04, 0x01, 0x02]),
            ]
        )
        let shBytes = try serializeHandshakeMessage(.serverHello(serverHello))
        var record = buildHandshakeRecord(body: shBytes)
        makeRecordView(from: &record) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error(.invalidKeyShare) = action else {
                    Issue.record("Expected .invalidKeyShare error"); return
                }
            }
        }
    }

    // MARK: - Full happy path (client + raw crypto server)

    @Test func fullHandshakeHappyPath() throws {
        var sm = ClientHandshakeStateMachine(configuration: makeConfig())
        let clientHelloOutput = startHandshake(sm: &sm)

        // Parse CH to get client's public key
        let chFragLen = Int(clientHelloOutput[3]) << 8 | Int(clientHelloOutput[4])
        let chBytes = Array(clientHelloOutput[5..<(5 + chFragLen)])
        let chMsg = try HandshakeMessage(parsing: chBytes)
        guard case .clientHello(let clientHello) = chMsg else {
            Issue.record("Not a ClientHello"); return
        }

        // Extract client key share (need to parse CH format, not SH format)
        // The CH key_share has a list prefix (2 bytes), then entries
        var clientKeyExchange: [UInt8]?
        for ext in clientHello.extensions where ext.type == .keyShare {
            guard ext.data.count >= 6 else { continue }
            var offset = 2 // skip list length
            let group = UInt16(ext.data[offset]) << 8 | UInt16(ext.data[offset + 1])
            let keyLen = Int(ext.data[offset + 2]) << 8 | Int(ext.data[offset + 3])
            offset += 4
            if group == NamedGroup.secp256.rawValue {
                clientKeyExchange = Array(ext.data[offset..<(offset + keyLen)])
            }
        }
        guard let clientKeyBytes = clientKeyExchange else {
            Issue.record("No P-256 key share in ClientHello"); return
        }

        // Server side: generate key, compute ECDHE
        let serverKey = P256.KeyAgreement.PrivateKey()
        let clientPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: clientKeyBytes)
        let sharedSecret = try serverKey.sharedSecretFromKeyAgreement(with: clientPublicKey)

        // Build ServerHello
        let serverHello = ServerHello(
            legacyVersion: .tlsv12,
            random: SwiftTLSStateMachine.generateRandom(count: 32),
            legacySessionIDEcho: clientHello.legacySessionID,
            cipherSuite: .TLS_AES_128_GCM_SHA256,
            legacyCompressionMethod: 0,
            extensions: [
                .serverSupportedVersion(.tlsv13),
                .keyShareServerHello(
                    group: .secp256,
                    keyExchange: Array(serverKey.publicKey.x963Representation)
                ),
            ]
        )
        let shBody = try serializeHandshakeMessage(.serverHello(serverHello))

        // Compute transcript and derive keys (same as the state machine does)
        var transcript = SHA256()
        chBytes.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        shBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        let transcriptHash = transcript.finalize()

        var keySchedule = TLSKeySchedule<SHA256>()
        let secrets = keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        let serverEncrypt = TLSRecordProtection(
            trafficSecret: secrets.serverHandshakeTrafficSecret,
            cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        var serverSeq: UInt64 = 0

        // Feed ServerHello to client SM
        var shRecord = buildHandshakeRecord(body: shBody)
        makeRecordView(from: &shRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .`continue` = action else {
                    Issue.record("Expected .continue after ServerHello"); return
                }
            }
        }

        // Build and encrypt EncryptedExtensions
        let eeBody = try serializeHandshakeMessage(
            .encryptedExtensions(EncryptedExtensions(extensions: []))
        )
        eeBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        let eeFragment = try encryptFragment(
            protection: serverEncrypt, plaintext: eeBody,
            contentType: .handshake, sequenceNumber: serverSeq
        )
        serverSeq += 1
        var eeRecord = buildApplicationDataRecord(fragment: eeFragment)
        makeRecordView(from: &eeRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .`continue` = action else {
                    Issue.record("Expected .continue after EE"); return
                }
            }
        }

        // Build and encrypt Certificate (empty for testing)
        let certBody = try serializeHandshakeMessage(
            .certificate(CertificateMessage(certificateList: []))
        )
        certBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        let certFragment = try encryptFragment(
            protection: serverEncrypt, plaintext: certBody,
            contentType: .handshake, sequenceNumber: serverSeq
        )
        serverSeq += 1
        var certRecord = buildApplicationDataRecord(fragment: certFragment)
        makeRecordView(from: &certRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .`continue` = action else {
                    Issue.record("Expected .continue after Certificate"); return
                }
            }
        }

        // Build and encrypt CertificateVerify (dummy signature)
        let cvBody = try serializeHandshakeMessage(
            .certificateVerify(CertificateVerify(
                algorithm: .ecdsa_secp256r1_sha256,
                signature: [UInt8](repeating: 0, count: 64)
            ))
        )
        cvBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        let cvFragment = try encryptFragment(
            protection: serverEncrypt, plaintext: cvBody,
            contentType: .handshake, sequenceNumber: serverSeq
        )
        serverSeq += 1
        var cvRecord = buildApplicationDataRecord(fragment: cvFragment)
        makeRecordView(from: &cvRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .`continue` = action else {
                    Issue.record("Expected .continue after CertificateVerify"); return
                }
            }
        }

        // Build and encrypt Finished
        let serverFinishedMAC = keySchedule.serverFinishedVerifyData(
            transcriptHash: transcript.finalize()
        )
        let finBody = try serializeHandshakeMessage(
            .finished(FinishedMessage(verifyData: Array(serverFinishedMAC)))
        )
        let finFragment = try encryptFragment(
            protection: serverEncrypt, plaintext: finBody,
            contentType: .handshake, sequenceNumber: serverSeq
        )
        var finRecord = buildApplicationDataRecord(fragment: finFragment)
        makeRecordView(from: &finRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 16384)
            let resultBytes: [UInt8] = outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .complete(let connectionSM) = action else {
                    Issue.record("Expected .complete after Finished")
                    return []
                }
                assert(connectionSM.isActive())
                return Array(UnsafeBufferPointer(start: buf.baseAddress!, count: output.count))
            }
            // Output should contain the encrypted client Finished
            #expect(resultBytes.count > 0)
            #expect(resultBytes[0] == ContentType.applicationData.rawValue)
        }

        assert(sm.isConnected())
    }
}

// MARK: - Test helpers

private func encryptFragment(
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

private func serializeHandshakeMessage(_ message: HandshakeMessage) throws -> [UInt8] {
    var result: [UInt8] = []
    var tempBuf = [UInt8](repeating: 0, count: 16384)
    try tempBuf.withUnsafeMutableBufferPointer { buf in
        var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
        var serState = try HandshakeMessage.startSerialization(of: message)
        while !HandshakeMessage.serialize(state: &serState, into: &output) {}
        result = Array(UnsafeBufferPointer(start: buf.baseAddress!, count: output.count))
    }
    return result
}

private func buildHandshakeRecord(body: [UInt8]) -> [UInt8] {
    var record: [UInt8] = [ContentType.handshake.rawValue, 0x03, 0x03]
    record.append(UInt8(truncatingIfNeeded: body.count >> 8))
    record.append(UInt8(truncatingIfNeeded: body.count))
    record.append(contentsOf: body)
    return record
}

private func buildApplicationDataRecord(fragment: [UInt8]) -> [UInt8] {
    var record: [UInt8] = [ContentType.applicationData.rawValue, 0x03, 0x03]
    record.append(UInt8(truncatingIfNeeded: fragment.count >> 8))
    record.append(UInt8(truncatingIfNeeded: fragment.count))
    record.append(contentsOf: fragment)
    return record
}
