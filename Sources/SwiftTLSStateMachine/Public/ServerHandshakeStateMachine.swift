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
import BinaryParsing
import BinarySerialization

/// A TLS 1.3 server handshake state machine.
///
/// Takes raw TLS records (via ``TLSRecordView``) and an output span for
/// serialization. The first ``receive(_:output:)`` call processes the
/// ClientHello and writes the entire server flight (ServerHello +
/// EncryptedExtensions + Certificate + CertificateVerify + Finished)
/// into the output. The second call processes the client Finished and
/// returns a ``TLSConnectionStateMachine``.
public struct ServerHandshakeStateMachine: ~Copyable {
    private var state: State

    public init(configuration: ServerHandshakeConfiguration) {
        self.state = .idle(IdleState(configuration: configuration))
    }

    private init(state: consuming State) {
        self.state = state
    }

    // MARK: - receive

    public enum ReceiveAction: ~Copyable {
        case `continue`
        case complete(TLSConnectionStateMachine)
        case error(HandshakeError)
    }

    /// Processes an incoming TLS record.
    ///
    /// On the first call (ClientHello), the entire server handshake
    /// flight is serialized into the output span. On the second call
    /// (client Finished), the handshake completes.
    public mutating func receive(
        _ record: inout EncryptedTLSRecordView,
        output: inout OutputSpan<UInt8>
    ) -> ReceiveAction {
        switch consume self.state {
        case .idle(let idle):
            do {
                self = try Self(state: .waitingClientFinished(
                    WaitingClientFinishedState(
                        idle: idle,
                        record: record,
                        output: &output
                    )
                ))
                return .`continue`
            } catch {
                self = Self(state: .error)
                return .error(error)
            }

        case .waitingClientFinished(let waitingClientFinished):
            guard record.contentType == .applicationData else {
                self = Self(state: .error)
                return .error(.unexpectedMessage)
            }

            let decrypted: DecryptedTLSRecordView
            do {
                decrypted = try waitingClientFinished.clientDecrypt.decrypt(
                    record: &record,
                    sequenceNumber: 0
                )
            } catch {
                self = Self(state: .error)
                return .error(.unexpectedMessage)
            }
            guard decrypted.contentType == .handshake else {
                self = Self(state: .error)
                return .error(.unexpectedMessage)
            }
            var parserSpan = ParserSpan(decrypted.plaintext.bytes)
            guard let msg = try? HandshakeMessage(parsing: &parserSpan),
                  case .finished = msg else {
                self = Self(state: .error)
                return .error(.unexpectedMessage)
            }
            precondition(parserSpan.isEmpty)

            let connectionSM = TLSConnectionStateMachine(
                readProtection: waitingClientFinished.clientAppDecrypt,
                writeProtection: waitingClientFinished.serverAppEncrypt,
                cipherSuite: waitingClientFinished.negotiatedCipherSuite,
                negotiatedALPN: waitingClientFinished.negotiatedALPN
            )

            self = Self(state: .connected)
            return .complete(connectionSM)

        case .connected:
            self = Self(state: .error)
            return .error(.unexpectedMessage)

        case .error:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        }
    }
}

// MARK: - State

extension ServerHandshakeStateMachine {
    private enum State: ~Copyable {
        case idle(IdleState)
        case waitingClientFinished(WaitingClientFinishedState)
        case connected
        case error
    }

    private struct IdleState: ~Copyable {
        let configuration: ServerHandshakeConfiguration
    }

    private struct WaitingClientFinishedState: ~Copyable {
        let negotiatedCipherSuite: CipherSuite
        let negotiatedALPN: String?
        var clientDecrypt: TLSRecordProtection
        var clientAppDecrypt: TLSRecordProtection
        var serverAppEncrypt: TLSRecordProtection

        init(
            idle: consuming IdleState,
            record: borrowing EncryptedTLSRecordView,
            output: inout OutputSpan<UInt8>
        ) throws(HandshakeError) {
            // 1. Parse ClientHello
            guard record.contentType == .handshake else {
                throw .unexpectedMessage
            }

            let clientHello: ClientHello
            do {
                var parserSpan = ParserSpan(record.fragment.bytes)
                let msg = try HandshakeMessage(parsing: &parserSpan)
                precondition(parserSpan.isEmpty)
                guard case .clientHello(let ch) = msg else {
                    throw HandshakeError.unexpectedMessage
                }
                clientHello = ch
            } catch {
                throw .unexpectedMessage
            }

            guard let selectedSuite = ServerHandshakeStateMachine.selectCipherSuite(
                offered: clientHello.cipherSuites,
                supported: idle.configuration.cipherSuites
            ) else {
                throw .unsupportedCipherSuite
            }

            guard let clientKeyShare = ServerHandshakeStateMachine.extractClientKeyShare(
                from: clientHello.extensions,
                supportedGroups: idle.configuration.supportedGroups
            ) else {
                throw .missingKeyShare
            }

            let alpn = ServerHandshakeStateMachine.selectALPN(
                offered: clientHello.extensions,
                supported: idle.configuration.alpnProtocols
            )

            // Start transcript with ClientHello
            var transcript = SHA256()
            transcript.update(bytes: record.fragment.bytes)

            // 2. Generate server key, compute ECDHE
            let serverPrivateKey = P256.KeyAgreement.PrivateKey()
            let sharedSecret: SharedSecret
            do {
                let clientPublicKey = try P256.KeyAgreement.PublicKey(
                    x963Representation: clientKeyShare.keyExchange
                )
                sharedSecret = try serverPrivateKey.sharedSecretFromKeyAgreement(with: clientPublicKey)
            } catch {
                throw .invalidKeyShare
            }

            // 3. Serialize ServerHello (unencrypted) into output
            let serverHello = ServerHello(
                legacyVersion: .tlsv12,
                random: generateRandom(count: 32),
                legacySessionIDEcho: clientHello.legacySessionID,
                cipherSuite: selectedSuite,
                legacyCompressionMethod: 0,
                extensions: [
                    .serverSupportedVersion(.tlsv13),
                    .keyShareServerHello(
                        group: clientKeyShare.group,
                        keyExchange: Array(serverPrivateKey.publicKey.x963Representation)
                    ),
                ]
            )

            let shBodyRange: Range<Int>
            do {
                shBodyRange = try ClientHandshakeStateMachine.writeTLSRecord(
                    contentType: .handshake,
                    into: &output
                ) { output in
                    let message = HandshakeMessage.serverHello(serverHello)
                    var serState = try HandshakeMessage.startSerialization(of: message)
                    guard HandshakeMessage.serialize(state: &serState, into: &output) else {
                        throw HandshakeError.unexpectedMessage
                    }
                }
            } catch {
                throw .unexpectedMessage
            }

            // Update transcript with SH
            transcript.updateWithSpan(output.span.extracting(shBodyRange))
            let transcriptHash = transcript.finalize()

            // 4. Derive handshake keys
            var keySchedule = TLSKeySchedule<SHA256>()
            let hsSecrets = keySchedule.deriveHandshakeSecrets(
                sharedSecret: sharedSecret,
                transcriptHash: transcriptHash
            )

            let serverEncrypt = TLSRecordProtection(
                trafficSecret: hsSecrets.serverHandshakeTrafficSecret,
                cipherSuite: selectedSuite
            )
            let clientDecryptProtection = TLSRecordProtection(
                trafficSecret: hsSecrets.clientHandshakeTrafficSecret,
                cipherSuite: selectedSuite
            )
            var serverSeq: UInt64 = 0

            // 5. Serialize encrypted EncryptedExtensions
            var eeExtensions: [TLSExtension] = []
            if !idle.configuration.alpnProtocols.isEmpty {
                eeExtensions.append(.alpn(idle.configuration.alpnProtocols))
            }
            let eeMessage = HandshakeMessage.encryptedExtensions(
                EncryptedExtensions(extensions: eeExtensions)
            )
            try Self.serializeEncryptedHandshakeMessage(
                eeMessage,
                into: &output,
                transcript: &transcript,
                protection: serverEncrypt,
                sequenceNumber: &serverSeq
            )

            // 6. Serialize encrypted Certificate
            var certEntries: [CertificateEntry] = []
            for certDER in idle.configuration.certificateChainDER {
                certEntries.append(CertificateEntry(certificateData: certDER))
            }
            let certMessage = HandshakeMessage.certificate(
                CertificateMessage(certificateList: certEntries)
            )
            try Self.serializeEncryptedHandshakeMessage(
                certMessage,
                into: &output,
                transcript: &transcript,
                protection: serverEncrypt,
                sequenceNumber: &serverSeq
            )

            // 7. Serialize encrypted CertificateVerify
            let cvTranscript = transcript
            let cvHash = cvTranscript.finalize()
            let signature: [UInt8]
            do {
                var content: [UInt8] = []
                content.append(contentsOf: [UInt8](repeating: 0x20, count: 64))
                content.append(contentsOf: "TLS 1.3, server CertificateVerify\0".utf8)
                content.append(contentsOf: cvHash)
                let sig = try idle.configuration.signingKey.signature(for: content)
                signature = Array(sig.derRepresentation)
            } catch {
                throw .unexpectedMessage
            }
            let cvMessage = HandshakeMessage.certificateVerify(
                CertificateVerify(algorithm: .ecdsa_secp256r1_sha256, signature: signature)
            )
            try Self.serializeEncryptedHandshakeMessage(
                cvMessage,
                into: &output,
                transcript: &transcript,
                protection: serverEncrypt,
                sequenceNumber: &serverSeq
            )

            // 8. Serialize encrypted Finished
            let finTranscript = transcript
            let finHash = finTranscript.finalize()
            let finishedKey = TLSKeyDerivation<SHA256>.expandLabel(
                secret: hsSecrets.serverHandshakeTrafficSecret,
                label: "finished",
                context: [],
                length: SHA256.Digest.byteCount
            )
            let mac = HMAC<SHA256>.authenticationCode(
                for: Array(finHash),
                using: finishedKey
            )
            let finMessage = HandshakeMessage.finished(
                FinishedMessage(verifyData: Array(mac))
            )
            try Self.serializeEncryptedHandshakeMessage(
                finMessage,
                into: &output,
                transcript: &transcript,
                protection: serverEncrypt,
                sequenceNumber: &serverSeq
            )

            // 9. Derive application keys
            let appTranscript = transcript
            let appHash = appTranscript.finalize()
            let appSecrets = keySchedule.deriveMasterSecrets(
                transcriptHash: appHash
            )

            self.negotiatedCipherSuite = selectedSuite
            self.negotiatedALPN = alpn
            self.clientDecrypt = clientDecryptProtection
            self.clientAppDecrypt = TLSRecordProtection(
                trafficSecret: appSecrets.clientApplicationTrafficSecret,
                cipherSuite: selectedSuite
            )
            self.serverAppEncrypt = TLSRecordProtection(
                trafficSecret: appSecrets.serverApplicationTrafficSecret,
                cipherSuite: selectedSuite
            )
        }

        private static func serializeEncryptedHandshakeMessage(
            _ message: HandshakeMessage,
            into output: inout OutputSpan<UInt8>,
            transcript: inout SHA256,
            protection: TLSRecordProtection,
            sequenceNumber: inout UInt64
        ) throws(HandshakeError) {
            // Serialize the handshake message to plaintext bytes
            var plaintext: [UInt8] = []
            do {
                var serState = try HandshakeMessage.startSerialization(of: message)
                // Use a temporary OutputSpan to serialize into an array
                // TODO: This allocates — could be improved with direct OutputSpan serialization
                var tempBuf = [UInt8](repeating: 0, count: 16384)
                tempBuf.withUnsafeMutableBufferPointer { buf in
                    var tempOutput = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
                    while !HandshakeMessage.serialize(state: &serState, into: &tempOutput) {}
                    plaintext = Array(UnsafeBufferPointer(start: buf.baseAddress!, count: tempOutput.count))
                }
            } catch {
                throw .unexpectedMessage
            }

            // Update transcript with plaintext handshake bytes
            plaintext.withUnsafeBytes {
                transcript.update(bufferPointer: UnsafeRawBufferPointer($0))
            }

            // Encrypt and write record to output
            let plaintextLength = plaintext.count
            let fragmentLength = plaintextLength + 1 + 16

            output.append(ContentType.applicationData.rawValue)
            output.append(0x03)
            output.append(0x03)
            output.append(UInt8(truncatingIfNeeded: fragmentLength >> 8))
            output.append(UInt8(truncatingIfNeeded: fragmentLength))

            let fragmentStart = output.count
            for byte in plaintext { output.append(byte) }
            for _ in 0..<17 { output.append(0) }

            do {
                var mspan = output.mutableSpan
                var fragmentSpan = mspan._mutatingExtracting(
                    fragmentStart..<(fragmentStart + fragmentLength)
                )
                _ = try protection.encrypt(
                    buffer: &fragmentSpan,
                    plaintextLength: plaintextLength,
                    contentType: .handshake,
                    sequenceNumber: sequenceNumber
                )
            } catch {
                throw .unexpectedMessage
            }
            sequenceNumber += 1
        }
    }
}

// MARK: - Queries

extension ServerHandshakeStateMachine {
    public borrowing func isConnected() -> Bool {
        switch state {
        case .connected: true
        default: false
        }
    }
}

// MARK: - Negotiation helpers

extension ServerHandshakeStateMachine {
    static func selectCipherSuite(
        offered: [CipherSuite],
        supported: [CipherSuite]
    ) -> CipherSuite? {
        for suite in supported {
            if offered.contains(suite) { return suite }
        }
        return nil
    }

    static func selectALPN(
        offered: [TLSExtension],
        supported: [String]
    ) -> String? {
        guard !supported.isEmpty else { return nil }
        for ext in offered where ext.type == .applicationLayerProtocolNegotiation {
            guard ext.data.count >= 2 else { return nil }
            var offset = 2
            while offset < ext.data.count {
                let length = Int(ext.data[offset])
                offset += 1
                guard offset + length <= ext.data.count else { return nil }
                if let proto = String(
                    bytes: ext.data[offset..<(offset + length)],
                    encoding: .utf8
                ), supported.contains(proto) {
                    return proto
                }
                offset += length
            }
        }
        return nil
    }

    static func extractClientKeyShare(
        from extensions: [TLSExtension],
        supportedGroups: [NamedGroup]
    ) -> (group: NamedGroup, keyExchange: [UInt8])? {
        for ext in extensions where ext.type == .keyShare {
            guard ext.data.count >= 2 else { return nil }
            var offset = 2
            while offset + 4 <= ext.data.count {
                let group = NamedGroup(
                    rawValue: UInt16(ext.data[offset]) << 8
                        | UInt16(ext.data[offset + 1])
                )
                let keyLength = Int(ext.data[offset + 2]) << 8
                    | Int(ext.data[offset + 3])
                offset += 4
                guard offset + keyLength <= ext.data.count else { return nil }
                if supportedGroups.contains(group) {
                    return (group, Array(ext.data[offset..<(offset + keyLength)]))
                }
                offset += keyLength
            }
        }
        return nil
    }
}
