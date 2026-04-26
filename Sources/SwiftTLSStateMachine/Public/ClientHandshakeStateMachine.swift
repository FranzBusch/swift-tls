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

public import Crypto
import BinaryParsing
import BinarySerialization

/// A TLS 1.3 client handshake state machine.
///
/// Takes raw TLS records (via ``TLSRecordView``) and an output span for
/// serialization. Handles all parsing, ECDHE key exchange, key derivation,
/// transcript hashing, and record decryption internally. Returns a
/// ``TLSConnectionStateMachine`` when the handshake completes.
public struct ClientHandshakeStateMachine: ~Copyable {
    private var state: State

    public init(configuration: ClientHandshakeConfiguration) {
        self.state = .idle(IdleState(configuration: configuration))
    }

    private init(state: consuming State) {
        self.state = state
    }

    // MARK: - start

    public enum StartAction: ~Copyable {
        case ok
        case error(HandshakeError)
    }

    /// Starts the handshake by serializing a ClientHello into the output.
    ///
    /// Generates an ephemeral P-256 key pair internally. The output
    /// receives a complete TLS record (header + handshake message).
    public mutating func start(
        output: inout OutputSpan<UInt8>
    ) -> StartAction {
        switch consume self.state {
        case .idle(let s):
            let privateKey = P256.KeyAgreement.PrivateKey()

            var extensions: [TLSExtension] = []
            extensions.reserveCapacity(6)
            if let serverName = s.configuration.serverName {
                extensions.append(.serverName(serverName))
            }
            extensions.append(.supportedVersions(s.configuration.supportedVersions))
            extensions.append(.supportedGroups(s.configuration.supportedGroups))
            extensions.append(.signatureAlgorithms(s.configuration.signatureAlgorithms))
            if !s.configuration.alpnProtocols.isEmpty {
                extensions.append(.alpn(s.configuration.alpnProtocols))
            }
            extensions.append(.keyShareClientHello(
                group: .secp256,
                keyExchange: Array(privateKey.publicKey.x963Representation)
            ))

            let clientHello = ClientHello(
                random: generateRandom(count: 32),
                legacySessionID: generateRandom(count: 32),
                cipherSuites: s.configuration.cipherSuites,
                extensions: extensions
            )

            let bodyRange: Range<Int>
            do {
                bodyRange = try Self.writeTLSRecord(contentType: .handshake, into: &output) { output in
                    let message = HandshakeMessage.clientHello(clientHello)
                    var serState = try HandshakeMessage.startSerialization(of: message)
                    guard HandshakeMessage.serialize(state: &serState, into: &output) else {
                        throw HandshakeError.unexpectedMessage
                    }
                }
            } catch {
                self = Self(state: .error)
                return .error(.unexpectedMessage)
            }

            var transcript = SHA256()
            transcript.updateWithSpan(output.span.extracting(bodyRange))

            self = Self(state: .waitingServerHello(WaitingServerHelloState(
                privateKey: privateKey,
                transcript: transcript
            )))

            return .ok

        case .waitingServerHello:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        case .waitingEncryptedExtensions:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        case .waitingServerCertificate:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        case .waitingCertificateVerify:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        case .waitingFinished:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        case .connected:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        case .error:
            self = Self(state: .error)
            return .error(.unexpectedMessage)
        }
    }

    // MARK: - receive

    public enum ReceiveAction: ~Copyable {
        case `continue`
        case complete(TLSConnectionStateMachine)
        case error(HandshakeError)
    }

    /// Processes an incoming TLS record.
    public mutating func receive(
        _ record: inout EncryptedTLSRecordView,
        output: inout OutputSpan<UInt8>
    ) -> ReceiveAction {
        switch consume self.state {
        case .idle:
            self = Self(state: .error)
            return .error(.unexpectedMessage)

        case .waitingServerHello(let waitingServerHelloState):
            do {
                self = try Self(state: .waitingEncryptedExtensions(
                    WaitingEncryptedExtensionsState(
                        waitingServerHelloState: waitingServerHelloState,
                        record: record
                    )
                ))
                return .`continue`
            } catch {
                self = Self(state: .error)
                return .error(error)
            }

        case .waitingEncryptedExtensions(let waitingEncryptedExtensions):
            do {
                self = try Self(state: .waitingServerCertificate(
                    WaitingServerCertificateState(
                        waitingEncryptedExtensions: waitingEncryptedExtensions,
                        record: &record
                    )
                ))
                return .`continue`
            } catch {
                self = Self(state: .error)
                return .error(error)
            }

        case .waitingServerCertificate(let waitingServerCertificate):
            do {
                self = try Self(state: .waitingCertificateVerify(
                    WaitingCertificateVerifyState(
                        waitingServerCertificate: waitingServerCertificate,
                        record: &record
                    )
                ))
                return .`continue`
            } catch {
                self = Self(state: .error)
                return .error(error)
            }

        case .waitingCertificateVerify(let waitingCertificateVerify):
            do {
                self = try Self(state: .waitingFinished(
                    WaitingFinishedState(
                        waitingCertificateVerify: waitingCertificateVerify,
                        record: &record
                    )
                ))
                return .`continue`
            } catch {
                self = Self(state: .error)
                return .error(error)
            }

        case .waitingFinished(var waitingFinished):
            guard record.contentType == .applicationData else {
                self = Self(state: .error)
                return .error(.unexpectedMessage)
            }

            let decrypted: DecryptedTLSRecordView
            do {
                decrypted = try waitingFinished.serverDecrypt.decrypt(
                    record: &record,
                    sequenceNumber: waitingFinished.serverSeq
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

            waitingFinished.transcript.update(bytes: decrypted.plaintext.bytes)
            let transcriptHash = waitingFinished.transcript.finalize()

            var keySchedule = waitingFinished.keySchedule
            let clientFinishedMAC = keySchedule.clientFinishedVerifyData(
                transcriptHash: transcriptHash
            )
            let appSecrets = keySchedule.deriveMasterSecrets(
                transcriptHash: transcriptHash
            )

            let macBytes = Array(clientFinishedMAC)
            var finBytes: [UInt8] = [HandshakeType.finished.rawValue]
            let macLen = macBytes.count
            finBytes.append(UInt8(truncatingIfNeeded: macLen >> 16))
            finBytes.append(UInt8(truncatingIfNeeded: macLen >> 8))
            finBytes.append(UInt8(truncatingIfNeeded: macLen))
            finBytes.append(contentsOf: macBytes)

            do {
                let plaintextLength = finBytes.count
                let fragmentLength = plaintextLength + 1 + 16

                // Write record header
                output.append(ContentType.applicationData.rawValue)
                output.append(0x03)
                output.append(0x03)
                output.append(UInt8(truncatingIfNeeded: fragmentLength >> 8))
                output.append(UInt8(truncatingIfNeeded: fragmentLength))

                // Write plaintext + space for content type + tag
                let fragmentStart = output.count
                for byte in finBytes { output.append(byte) }
                for _ in 0..<17 { output.append(0) }

                var mspan = output.mutableSpan
                var fragmentSpan = mspan._mutatingExtracting(
                    fragmentStart..<(fragmentStart + fragmentLength)
                )
                _ = try waitingFinished.clientEncrypt.encrypt(
                    buffer: &fragmentSpan,
                    plaintextLength: plaintextLength,
                    contentType: .handshake,
                    sequenceNumber: 0
                )
            } catch {
                self = Self(state: .error)
                return .error(.unexpectedMessage)
            }

            let connectionSM = TLSConnectionStateMachine(
                readProtection: TLSRecordProtection(
                    trafficSecret: appSecrets.serverApplicationTrafficSecret,
                    cipherSuite: waitingFinished.negotiatedCipherSuite
                ),
                writeProtection: TLSRecordProtection(
                    trafficSecret: appSecrets.clientApplicationTrafficSecret,
                    cipherSuite: waitingFinished.negotiatedCipherSuite
                ),
                cipherSuite: waitingFinished.negotiatedCipherSuite,
                negotiatedALPN: waitingFinished.negotiatedALPN
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

extension ClientHandshakeStateMachine {
    private enum State: ~Copyable {
        case idle(IdleState)
        case waitingServerHello(WaitingServerHelloState)
        case waitingEncryptedExtensions(WaitingEncryptedExtensionsState)
        case waitingServerCertificate(WaitingServerCertificateState)
        case waitingCertificateVerify(WaitingCertificateVerifyState)
        case waitingFinished(WaitingFinishedState)
        case connected
        case error
    }

    private struct IdleState: ~Copyable {
        let configuration: ClientHandshakeConfiguration
    }

    private struct WaitingServerHelloState: ~Copyable {
        var privateKey: P256.KeyAgreement.PrivateKey
        var transcript: SHA256
    }

    private struct WaitingEncryptedExtensionsState: ~Copyable {
        let negotiatedCipherSuite: CipherSuite
        var transcript: SHA256
        var keySchedule: TLSKeySchedule<SHA256>
        var serverDecrypt: TLSRecordProtection
        var clientEncrypt: TLSRecordProtection
        var serverSeq: UInt64

        init(
            waitingServerHelloState s: consuming WaitingServerHelloState,
            record: borrowing EncryptedTLSRecordView
        ) throws(HandshakeError) {
            guard record.contentType == .handshake else {
                throw .unexpectedMessage
            }

            let serverHello: ServerHello
            do {
                var parserSpan = ParserSpan(record.fragment.bytes)
                let msg = try HandshakeMessage(parsing: &parserSpan)
                precondition(parserSpan.isEmpty)
                guard case .serverHello(let sh) = msg else {
                    throw HandshakeError.unexpectedMessage
                }
                serverHello = sh
            } catch {
                throw .unexpectedMessage
            }

            guard let keyShareData = ClientHandshakeStateMachine.extractServerKeyShareData(
                from: serverHello.extensions
            ) else {
                throw .missingKeyShare
            }

            let sharedSecret: SharedSecret
            do {
                let serverPublicKey = try P256.KeyAgreement.PublicKey(
                    x963Representation: keyShareData.keyExchange
                )
                sharedSecret = try s.privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
            } catch {
                throw .invalidKeyShare
            }
            s.transcript.update(bytes: record.fragment.bytes)
            let transcriptHash = s.transcript.finalize()

            var keySchedule = TLSKeySchedule<SHA256>()
            let secrets = keySchedule.deriveHandshakeSecrets(
                sharedSecret: sharedSecret,
                transcriptHash: transcriptHash
            )

            let cipherSuite = serverHello.cipherSuite
            self.negotiatedCipherSuite = cipherSuite
            self.transcript = s.transcript
            self.keySchedule = keySchedule
            self.serverDecrypt = TLSRecordProtection(
                trafficSecret: secrets.serverHandshakeTrafficSecret,
                cipherSuite: cipherSuite
            )
            self.clientEncrypt = TLSRecordProtection(
                trafficSecret: secrets.clientHandshakeTrafficSecret,
                cipherSuite: cipherSuite
            )
            self.serverSeq = 0
        }
    }

    private struct WaitingServerCertificateState: ~Copyable {
        let negotiatedCipherSuite: CipherSuite
        let negotiatedALPN: String?
        var transcript: SHA256
        var keySchedule: TLSKeySchedule<SHA256>
        var serverDecrypt: TLSRecordProtection
        var clientEncrypt: TLSRecordProtection
        var serverSeq: UInt64

        init(
            waitingEncryptedExtensions: consuming WaitingEncryptedExtensionsState,
            record: inout EncryptedTLSRecordView
        ) throws(HandshakeError) {
            guard record.contentType == .applicationData else {
                throw .unexpectedMessage
            }
            let decrypted: DecryptedTLSRecordView
            do {
                decrypted = try waitingEncryptedExtensions.serverDecrypt.decrypt(
                    record: &record,
                    sequenceNumber: waitingEncryptedExtensions.serverSeq
                )
            } catch {
                throw .unexpectedMessage
            }
            guard decrypted.contentType == .handshake else {
                throw .unexpectedMessage
            }
            waitingEncryptedExtensions.transcript.update(bytes: decrypted.plaintext.bytes)

            var parserSpan = ParserSpan(decrypted.plaintext.bytes)
            guard let msg = try? HandshakeMessage(parsing: &parserSpan),
                  case .encryptedExtensions(let ee) = msg else {
                throw .unexpectedMessage
            }
            precondition(parserSpan.isEmpty)

            self.negotiatedCipherSuite = waitingEncryptedExtensions.negotiatedCipherSuite
            self.negotiatedALPN = ClientHandshakeStateMachine.extractALPN(from: ee.extensions)
            self.transcript = waitingEncryptedExtensions.transcript
            self.keySchedule = waitingEncryptedExtensions.keySchedule
            self.serverDecrypt = waitingEncryptedExtensions.serverDecrypt
            self.clientEncrypt = waitingEncryptedExtensions.clientEncrypt
            self.serverSeq = waitingEncryptedExtensions.serverSeq + 1
        }
    }

    private struct WaitingCertificateVerifyState: ~Copyable {
        let negotiatedCipherSuite: CipherSuite
        let negotiatedALPN: String?
        var transcript: SHA256
        var keySchedule: TLSKeySchedule<SHA256>
        var serverDecrypt: TLSRecordProtection
        var clientEncrypt: TLSRecordProtection
        var serverSeq: UInt64

        init(
            waitingServerCertificate: consuming WaitingServerCertificateState,
            record: inout EncryptedTLSRecordView
        ) throws(HandshakeError) {
            guard record.contentType == .applicationData else {
                throw .unexpectedMessage
            }
            let decrypted: DecryptedTLSRecordView
            do {
                decrypted = try waitingServerCertificate.serverDecrypt.decrypt(
                    record: &record,
                    sequenceNumber: waitingServerCertificate.serverSeq
                )
            } catch {
                throw .unexpectedMessage
            }
            guard decrypted.contentType == .handshake else {
                throw .unexpectedMessage
            }
            waitingServerCertificate.transcript.update(bytes: decrypted.plaintext.bytes)

            var parserSpan = ParserSpan(decrypted.plaintext.bytes)
            guard let msg = try? HandshakeMessage(parsing: &parserSpan),
                  case .certificate = msg else {
                throw .unexpectedMessage
            }
            precondition(parserSpan.isEmpty)

            self.negotiatedCipherSuite = waitingServerCertificate.negotiatedCipherSuite
            self.negotiatedALPN = waitingServerCertificate.negotiatedALPN
            self.transcript = waitingServerCertificate.transcript
            self.keySchedule = waitingServerCertificate.keySchedule
            self.serverDecrypt = waitingServerCertificate.serverDecrypt
            self.clientEncrypt = waitingServerCertificate.clientEncrypt
            self.serverSeq = waitingServerCertificate.serverSeq + 1
        }
    }

    private struct WaitingFinishedState: ~Copyable {
        let negotiatedCipherSuite: CipherSuite
        let negotiatedALPN: String?
        var transcript: SHA256
        var keySchedule: TLSKeySchedule<SHA256>
        var serverDecrypt: TLSRecordProtection
        var clientEncrypt: TLSRecordProtection
        var serverSeq: UInt64

        init(
            waitingCertificateVerify: consuming WaitingCertificateVerifyState,
            record: inout EncryptedTLSRecordView
        ) throws(HandshakeError) {
            guard record.contentType == .applicationData else {
                throw .unexpectedMessage
            }
            let decrypted: DecryptedTLSRecordView
            do {
                decrypted = try waitingCertificateVerify.serverDecrypt.decrypt(
                    record: &record,
                    sequenceNumber: waitingCertificateVerify.serverSeq
                )
            } catch {
                throw .unexpectedMessage
            }
            guard decrypted.contentType == .handshake else {
                throw .unexpectedMessage
            }
            waitingCertificateVerify.transcript.update(bytes: decrypted.plaintext.bytes)

            var parserSpan = ParserSpan(decrypted.plaintext.bytes)
            guard let msg = try? HandshakeMessage(parsing: &parserSpan),
                  case .certificateVerify = msg else {
                throw .unexpectedMessage
            }
            precondition(parserSpan.isEmpty)

            self.negotiatedCipherSuite = waitingCertificateVerify.negotiatedCipherSuite
            self.negotiatedALPN = waitingCertificateVerify.negotiatedALPN
            self.transcript = waitingCertificateVerify.transcript
            self.keySchedule = waitingCertificateVerify.keySchedule
            self.serverDecrypt = waitingCertificateVerify.serverDecrypt
            self.clientEncrypt = waitingCertificateVerify.clientEncrypt
            self.serverSeq = waitingCertificateVerify.serverSeq + 1
        }
    }
}

// MARK: - Queries

extension ClientHandshakeStateMachine {
    public borrowing func isConnected() -> Bool {
        switch state {
        case .connected: true
        default: false
        }
    }
}

// MARK: - Helpers

extension ClientHandshakeStateMachine {
    /// Writes a TLS record into the output span: 5-byte header, body from
    /// the closure, then patches the length. Returns the body byte range
    /// (excluding the header) for transcript hashing.
    static func writeTLSRecord(
        contentType: ContentType,
        into output: inout OutputSpan<UInt8>,
        body: (inout OutputSpan<UInt8>) throws -> Void
    ) throws -> Range<Int> {
        let headerStart = output.count
        output.append(contentType.rawValue)
        output.append(0x03)
        output.append(0x03)
        output.append(0x00)
        output.append(0x00)

        let bodyStart = output.count
        try body(&output)
        let bodyLength = output.count - bodyStart

        var mspan = output.mutableSpan
        mspan[headerStart + 3] = UInt8(truncatingIfNeeded: bodyLength >> 8)
        mspan[headerStart + 4] = UInt8(truncatingIfNeeded: bodyLength)

        return bodyStart..<output.count
    }

    static func extractALPN(from extensions: [TLSExtension]) -> String? {
        for ext in extensions where ext.type == .applicationLayerProtocolNegotiation {
            guard ext.data.count >= 4 else { return nil }
            let protoLength = Int(ext.data[2])
            guard ext.data.count >= 3 + protoLength else { return nil }
            return String(bytes: ext.data[3..<(3 + protoLength)], encoding: .utf8)
        }
        return nil
    }

    static func extractServerKeyShareData(
        from extensions: [TLSExtension]
    ) -> (group: NamedGroup, keyExchange: [UInt8])? {
        for ext in extensions where ext.type == .keyShare {
            guard ext.data.count >= 4 else { return nil }
            let group = NamedGroup(
                rawValue: UInt16(ext.data[0]) << 8 | UInt16(ext.data[1])
            )
            let keyLength = Int(ext.data[2]) << 8 | Int(ext.data[3])
            guard ext.data.count >= 4 + keyLength else { return nil }
            return (group, Array(ext.data[4..<(4 + keyLength)]))
        }
        return nil
    }
}

package func generateRandom(count: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    for i in 0..<count {
        bytes[i] = UInt8.random(in: 0...255)
    }
    return bytes
}

extension SHA256 {
    mutating func updateWithSpan(_ span: borrowing Span<UInt8>) {
        span.withUnsafeBytes { update(bufferPointer: $0) }
    }

    mutating func update(bytes: borrowing RawSpan) {
        bytes.withUnsafeBytes { update(bufferPointer: $0) }
    }
}
