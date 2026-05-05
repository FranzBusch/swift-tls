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

@Suite
struct ServerHandshakeStateMachineTests {

    // MARK: - Helpers

    private func makeSigningKey() -> P256.Signing.PrivateKey {
        P256.Signing.PrivateKey()
    }

    private func makeConfig(
        signingKey: P256.Signing.PrivateKey? = nil,
        alpnProtocols: [String] = []
    ) -> ServerHandshakeConfiguration {
        let key = signingKey ?? makeSigningKey()
        return ServerHandshakeConfiguration(
            certificateChainDER: [Array("fakecert".utf8)],
            signingKey: key,
            alpnProtocols: alpnProtocols
        )
    }

    /// Builds a valid ClientHello record with a P-256 key share.
    /// Returns the record bytes and the client private key (for ECDHE later).
    private func buildClientHelloRecord(
        cipherSuites: [CipherSuite] = [.TLS_AES_128_GCM_SHA256],
        includeKeyShare: Bool = true,
        keyShareGroup: NamedGroup = .secp256
    ) -> (record: [UInt8], clientKey: P256.KeyAgreement.PrivateKey) {
        let clientKey = P256.KeyAgreement.PrivateKey()
        var extensions: [TLSExtension] = [
            .supportedVersions([.tlsv13]),
            .supportedGroups([.secp256]),
            .signatureAlgorithms([.ecdsa_secp256r1_sha256]),
        ]
        if includeKeyShare {
            extensions.append(.keyShareClientHello(
                group: keyShareGroup,
                keyExchange: Array(clientKey.publicKey.x963Representation)
            ))
        }
        let clientHello = ClientHello(
            random: SwiftTLSStateMachine.generateRandom(count: 32),
            legacySessionID: SwiftTLSStateMachine.generateRandom(count: 32),
            cipherSuites: cipherSuites,
            extensions: extensions
        )
        let body = try! serializeHandshakeMessage(.clientHello(clientHello))
        let record = buildHandshakeRecord(body: body)
        return (record, clientKey)
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

    /// Parses the server flight output to extract the ServerHello's server
    /// public key. Returns the key exchange bytes.
    private func extractServerKeyFromOutput(_ output: [UInt8]) throws -> [UInt8] {
        // First record is the ServerHello (unencrypted handshake)
        guard output[0] == ContentType.handshake.rawValue else {
            throw HandshakeError.unexpectedMessage
        }
        let shFragLen = Int(output[3]) << 8 | Int(output[4])
        let shBody = Array(output[5..<(5 + shFragLen)])
        let msg = try HandshakeMessage(parsing: shBody)
        guard case .serverHello(let sh) = msg else {
            throw HandshakeError.unexpectedMessage
        }
        guard let keyShareData = ClientHandshakeStateMachine.extractServerKeyShareData(
            from: sh.extensions
        ) else {
            throw HandshakeError.missingKeyShare
        }
        return keyShareData.keyExchange
    }

    // MARK: - receive() with ClientHello: happy path

    @Test func receiveValidClientHelloProducesServerFlight() throws {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        var (chRecord, _) = buildClientHelloRecord()

        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 65536)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .`continue` = action else {
                    Issue.record("Expected .continue after ClientHello"); return
                }
                // Output should contain at least the ServerHello record
                #expect(output.count > 5)
                // First byte should be handshake (ServerHello is unencrypted)
                #expect(buf[0] == ContentType.handshake.rawValue)
            }
        }
    }

    @Test func serverFlightContainsMultipleRecords() throws {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        var (chRecord, _) = buildClientHelloRecord()

        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 65536)
            let outputBytes: [UInt8] = outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .`continue` = action else {
                    Issue.record("Expected .continue"); return []
                }
                return Array(UnsafeBufferPointer(start: buf.baseAddress!, count: output.count))
            }

            // Count TLS records in the output
            var recordCount = 0
            var offset = 0
            while offset + 5 <= outputBytes.count {
                let fragLen = Int(outputBytes[offset + 3]) << 8 | Int(outputBytes[offset + 4])
                offset += 5 + fragLen
                recordCount += 1
            }
            // Should be 5 records: SH + EE + Cert + CV + Finished
            #expect(recordCount == 5)
        }
    }

    // MARK: - receive() with ClientHello: error branches

    @Test func receiveNonHandshakeRecord() {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        var badRecord: [UInt8] = [
            ContentType.applicationData.rawValue, 0x03, 0x03, 0x00, 0x01, 0xFF
        ]
        makeRecordView(from: &badRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error = action else {
                    Issue.record("Expected error for non-handshake record"); return
                }
            }
        }
    }

    @Test func receiveGarbageClientHello() {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
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
                    Issue.record("Expected error for garbage"); return
                }
            }
        }
    }

    @Test func receiveClientHelloWithUnsupportedCipherSuite() {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        // Build CH with a cipher suite the server doesn't support
        var (chRecord, _) = buildClientHelloRecord(
            cipherSuites: [CipherSuite(rawValue: 0xFFFF)]
        )
        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error(.unsupportedCipherSuite) = action else {
                    Issue.record("Expected .unsupportedCipherSuite"); return
                }
            }
        }
    }

    @Test func receiveClientHelloWithoutKeyShare() {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        var (chRecord, _) = buildClientHelloRecord(includeKeyShare: false)
        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error(.missingKeyShare) = action else {
                    Issue.record("Expected .missingKeyShare"); return
                }
            }
        }
    }

    // MARK: - receive() in wrong state

    @Test func receiveInConnectedState() throws {
        // Drive to connected state via full handshake, then verify error
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        var (chRecord, clientKey) = buildClientHelloRecord()

        // First receive: ClientHello → server flight
        var serverOutput: [UInt8] = []
        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 65536)
            serverOutput = outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                _ = sm.receive(&view, output: &output)
                return Array(UnsafeBufferPointer(start: buf.baseAddress!, count: output.count))
            }
        }

        // Build client Finished
        let serverKeyBytes = try extractServerKeyFromOutput(serverOutput)
        let serverPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: serverKeyBytes)
        let sharedSecret = try clientKey.sharedSecretFromKeyAgreement(with: serverPublicKey)

        // Parse CH body for transcript
        let chFragLen = Int(chRecord[3]) << 8 | Int(chRecord[4])
        let chBody = Array(chRecord[5..<(5 + chFragLen)])

        // Parse SH body for transcript
        let shFragLen = Int(serverOutput[3]) << 8 | Int(serverOutput[4])
        let shBody = Array(serverOutput[5..<(5 + shFragLen)])

        var transcript = SHA256()
        chBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        shBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        let transcriptHash = transcript.finalize()

        var keySchedule = TLSKeySchedule<SHA256>()
        let secrets = keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        let clientEncrypt = TLSRecordProtection(
            trafficSecret: secrets.clientHandshakeTrafficSecret,
            cipherSuite: .TLS_AES_128_GCM_SHA256
        )

        // Build a dummy Finished (verify data doesn't matter for this test —
        // the server SM doesn't verify it currently)
        let finBody = try serializeHandshakeMessage(
            .finished(FinishedMessage(verifyData: [UInt8](repeating: 0, count: 32)))
        )
        let finFragment = try encryptFragment(
            protection: clientEncrypt, plaintext: finBody,
            contentType: .handshake, sequenceNumber: 0
        )
        var finRecord = buildApplicationDataRecord(fragment: finFragment)

        // Second receive: client Finished → complete
        makeRecordView(from: &finRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .complete(var appState) = action else {
                    Issue.record("Expected .complete"); return
                }
                _ = appState.takeReadStateMachine()
            }
        }

        assert(sm.isConnected())

        // Third receive: should error (already connected)
        var extraRecord: [UInt8] = [
            ContentType.applicationData.rawValue, 0x03, 0x03, 0x00, 0x01, 0xFF
        ]
        makeRecordView(from: &extraRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error = action else {
                    Issue.record("Expected error in connected state"); return
                }
            }
        }
    }

    @Test func receiveInErrorState() {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        // Put in error state with garbage
        var garbage: [UInt8] = [0x17, 0x03, 0x03, 0x00, 0x01, 0xFF]
        makeRecordView(from: &garbage) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                _ = sm.receive(&view, output: &output)
            }
        }
        // Now in error state
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

    // MARK: - Client Finished error branches

    @Test func clientFinishedWrongContentType() throws {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        var (chRecord, _) = buildClientHelloRecord()

        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 65536)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                _ = sm.receive(&view, output: &output)
            }
        }

        // Send a handshake record instead of applicationData
        var badRecord: [UInt8] = [
            ContentType.handshake.rawValue, 0x03, 0x03, 0x00, 0x01, 0xFF
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

    @Test func clientFinishedGarbageEncrypted() throws {
        var sm = ServerHandshakeStateMachine(configuration: makeConfig())
        var (chRecord, _) = buildClientHelloRecord()

        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 65536)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                _ = sm.receive(&view, output: &output)
            }
        }

        // Send applicationData with garbage (will fail decryption)
        var badRecord: [UInt8] = [ContentType.applicationData.rawValue, 0x03, 0x03, 0x00, 0x20]
        badRecord.append(contentsOf: [UInt8](repeating: 0xFF, count: 32))
        makeRecordView(from: &badRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .error = action else {
                    Issue.record("Expected error for garbage encrypted"); return
                }
            }
        }
    }

    // MARK: - Full happy path

    @Test func fullServerHandshakeHappyPath() throws {
        let signingKey = makeSigningKey()
        var sm = ServerHandshakeStateMachine(configuration: makeConfig(signingKey: signingKey))
        var (chRecord, clientKey) = buildClientHelloRecord()

        // First receive: ClientHello → server flight
        var serverOutput: [UInt8] = []
        makeRecordView(from: &chRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 65536)
            serverOutput = outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .`continue` = action else {
                    Issue.record("Expected .continue after ClientHello"); return []
                }
                return Array(UnsafeBufferPointer(start: buf.baseAddress!, count: output.count))
            }
        }
        #expect(serverOutput.count > 0)

        // Derive client handshake keys from the server's output
        let serverKeyBytes = try extractServerKeyFromOutput(serverOutput)
        let serverPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: serverKeyBytes)
        let sharedSecret = try clientKey.sharedSecretFromKeyAgreement(with: serverPublicKey)

        let chFragLen = Int(chRecord[3]) << 8 | Int(chRecord[4])
        let chBody = Array(chRecord[5..<(5 + chFragLen)])
        let shFragLen = Int(serverOutput[3]) << 8 | Int(serverOutput[4])
        let shBody = Array(serverOutput[5..<(5 + shFragLen)])

        var transcript = SHA256()
        chBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        shBody.withUnsafeBytes { transcript.update(bufferPointer: $0) }
        let transcriptHash = transcript.finalize()

        var keySchedule = TLSKeySchedule<SHA256>()
        let secrets = keySchedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash
        )

        let clientEncrypt = TLSRecordProtection(
            trafficSecret: secrets.clientHandshakeTrafficSecret,
            cipherSuite: .TLS_AES_128_GCM_SHA256
        )

        // Build encrypted client Finished
        let finBody = try serializeHandshakeMessage(
            .finished(FinishedMessage(verifyData: [UInt8](repeating: 0, count: 32)))
        )
        let finFragment = try encryptFragment(
            protection: clientEncrypt, plaintext: finBody,
            contentType: .handshake, sequenceNumber: 0
        )
        var finRecord = buildApplicationDataRecord(fragment: finFragment)

        // Second receive: client Finished → complete
        makeRecordView(from: &finRecord) { view in
            var outputBuf = [UInt8](repeating: 0, count: 4096)
            outputBuf.withUnsafeMutableBufferPointer { buf in
                var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                let action = sm.receive(&view, output: &output)
                guard case .complete(var appState) = action else {
                    Issue.record("Expected .complete after client Finished"); return
                }
                _ = appState.takeWriteStateMachine()
            }
        }

        assert(sm.isConnected())
    }
}

// MARK: - Shared test helpers (reuse from client tests)

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
