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

/// Tracks TLS 1.3 key derivation through the handshake phases.
///
/// Implements the key schedule defined in RFC 8446 Section 7.1.
/// Advances through four phases: early, handshake, master, and complete.
struct TLSKeySchedule<HF: HashFunction> {
    private var state: State

    /// Creates a key schedule starting from the early secret phase.
    ///
    /// - Parameter psk: The pre-shared key, or nil for a full handshake.
    init(psk: SymmetricKey? = nil) {
        let inputKey = psk ?? TLSKeyDerivation<HF>.zeroKey
        let earlySecret = TLSKeyDerivation<HF>.extract(
            inputKeyMaterial: inputKey,
            salt: TLSKeyDerivation<HF>.zeroKey
        )
        self.state = .earlySecret(EarlySecretState(earlySecret: earlySecret))
    }

    /// Derives the client early traffic secret.
    public mutating func clientEarlyTrafficSecret(
        transcriptHash: HF.Digest
    ) -> SymmetricKey {
        guard case .earlySecret(let s) = state else {
            preconditionFailure("clientEarlyTrafficSecret called in wrong state")
        }
        return TLSKeyDerivation<HF>.deriveSecret(
            secret: s.earlySecret,
            label: "c e traffic",
            transcriptHash: transcriptHash
        )
    }

    /// Advances to the handshake secret phase using the ECDHE shared secret.
    ///
    /// - Parameters:
    ///   - sharedSecret: The ECDHE shared secret from key exchange.
    ///   - transcriptHash: The transcript hash up to and including ServerHello.
    /// - Returns: The client and server handshake traffic secrets.
    public mutating func deriveHandshakeSecrets(
        sharedSecret: SharedSecret,
        transcriptHash: HF.Digest
    ) -> HandshakeSecrets {
        guard case .earlySecret(let s) = state else {
            preconditionFailure("deriveHandshakeSecrets called in wrong state")
        }
        let derivedSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: s.earlySecret,
            label: "derived",
            transcriptHash: TLSKeyDerivation<HF>.emptyHash
        )
        let handshakeSecret = TLSKeyDerivation<HF>.extract(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: derivedSecret
        )
        let clientSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: handshakeSecret,
            label: "c hs traffic",
            transcriptHash: transcriptHash
        )
        let serverSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: handshakeSecret,
            label: "s hs traffic",
            transcriptHash: transcriptHash
        )
        state = .handshakeSecret(HandshakeSecretState(
            handshakeSecret: handshakeSecret,
            clientHandshakeTrafficSecret: clientSecret,
            serverHandshakeTrafficSecret: serverSecret
        ))
        return HandshakeSecrets(
            clientHandshakeTrafficSecret: clientSecret,
            serverHandshakeTrafficSecret: serverSecret
        )
    }

    /// Advances to the master secret phase.
    ///
    /// - Parameter transcriptHash: The transcript hash up to and including
    ///   server Finished.
    /// - Returns: The client and server application traffic secrets.
    public mutating func deriveMasterSecrets(
        transcriptHash: HF.Digest
    ) -> ApplicationSecrets {
        guard case .handshakeSecret(let s) = state else {
            preconditionFailure("deriveMasterSecrets called in wrong state")
        }
        let derivedSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: s.handshakeSecret,
            label: "derived",
            transcriptHash: TLSKeyDerivation<HF>.emptyHash
        )
        let masterSecret = TLSKeyDerivation<HF>.extract(
            inputKeyMaterial: TLSKeyDerivation<HF>.zeroKey,
            salt: derivedSecret
        )
        let clientAppSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: masterSecret,
            label: "c ap traffic",
            transcriptHash: transcriptHash
        )
        let serverAppSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: masterSecret,
            label: "s ap traffic",
            transcriptHash: transcriptHash
        )
        let exporterSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: masterSecret,
            label: "exp master",
            transcriptHash: transcriptHash
        )
        state = .masterSecret(MasterSecretState(
            masterSecret: masterSecret,
            clientApplicationTrafficSecret: clientAppSecret,
            serverApplicationTrafficSecret: serverAppSecret,
            exporterMasterSecret: exporterSecret
        ))
        return ApplicationSecrets(
            clientApplicationTrafficSecret: clientAppSecret,
            serverApplicationTrafficSecret: serverAppSecret,
            exporterMasterSecret: exporterSecret
        )
    }

    /// Derives the resumption master secret after the full handshake.
    ///
    /// - Parameter transcriptHash: The transcript hash including client
    ///   Finished.
    /// - Returns: The resumption master secret.
    public mutating func deriveResumptionSecret(
        transcriptHash: HF.Digest
    ) -> SymmetricKey {
        guard case .masterSecret(let s) = state else {
            preconditionFailure("deriveResumptionSecret called in wrong state")
        }
        let resumptionSecret = TLSKeyDerivation<HF>.deriveSecret(
            secret: s.masterSecret,
            label: "res master",
            transcriptHash: transcriptHash
        )
        state = .complete(CompleteState(
            resumptionMasterSecret: resumptionSecret
        ))
        return resumptionSecret
    }

    /// Computes the server Finished verify data.
    func serverFinishedVerifyData(
        transcriptHash: HF.Digest
    ) -> HMAC<HF>.MAC {
        guard case .handshakeSecret(let s) = state else {
            preconditionFailure("serverFinishedVerifyData called in wrong state")
        }
        return TLSKeyDerivation<HF>.finishedVerifyData(
            baseKey: s.serverHandshakeTrafficSecret,
            transcriptHash: transcriptHash
        )
    }

    /// Computes the client Finished verify data.
    func clientFinishedVerifyData(
        transcriptHash: HF.Digest
    ) -> HMAC<HF>.MAC {
        guard case .handshakeSecret(let s) = state else {
            preconditionFailure("clientFinishedVerifyData called in wrong state")
        }
        return TLSKeyDerivation<HF>.finishedVerifyData(
            baseKey: s.clientHandshakeTrafficSecret,
            transcriptHash: transcriptHash
        )
    }
}

// MARK: - Return types

extension TLSKeySchedule {
    /// The handshake traffic secrets derived after ServerHello.
    struct HandshakeSecrets {
        public let clientHandshakeTrafficSecret: SymmetricKey
        public let serverHandshakeTrafficSecret: SymmetricKey
    }

    /// The application traffic secrets derived after server Finished.
    struct ApplicationSecrets {
        public let clientApplicationTrafficSecret: SymmetricKey
        public let serverApplicationTrafficSecret: SymmetricKey
        public let exporterMasterSecret: SymmetricKey
    }
}

// MARK: - Internal state

extension TLSKeySchedule {
    private enum State {
        case earlySecret(EarlySecretState)
        case handshakeSecret(HandshakeSecretState)
        case masterSecret(MasterSecretState)
        case complete(CompleteState)
    }

    private struct EarlySecretState {
        let earlySecret: SymmetricKey
    }

    private struct HandshakeSecretState {
        let handshakeSecret: SymmetricKey
        let clientHandshakeTrafficSecret: SymmetricKey
        let serverHandshakeTrafficSecret: SymmetricKey
    }

    private struct MasterSecretState {
        let masterSecret: SymmetricKey
        let clientApplicationTrafficSecret: SymmetricKey
        let serverApplicationTrafficSecret: SymmetricKey
        let exporterMasterSecret: SymmetricKey
    }

    private struct CompleteState {
        let resumptionMasterSecret: SymmetricKey
    }
}
