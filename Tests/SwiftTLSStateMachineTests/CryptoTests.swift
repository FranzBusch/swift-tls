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
@testable import SwiftTLSStateMachine
import Testing

@Suite
struct TLSKeyDerivationTests {
    @Test
    func expandLabelProducesCorrectLength() {
        let secret = SymmetricKey(data: [UInt8](repeating: 0xAA, count: 32))
        let result = TLSKeyDerivation<SHA256>.expandLabel(
            secret: secret,
            label: "test",
            context: [],
            length: 32
        )
        result.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }
    }

    @Test
    func expandLabelDifferentLabelsProduceDifferentKeys() {
        let secret = SymmetricKey(data: [UInt8](repeating: 0xBB, count: 32))
        let key1 = TLSKeyDerivation<SHA256>.expandLabel(
            secret: secret,
            label: "label1",
            context: [],
            length: 32
        )
        let key2 = TLSKeyDerivation<SHA256>.expandLabel(
            secret: secret,
            label: "label2",
            context: [],
            length: 32
        )
        key1.withUnsafeBytes { bytes1 in
            key2.withUnsafeBytes { bytes2 in
                #expect(Array(bytes1) != Array(bytes2))
            }
        }
    }

    @Test
    func expandLabelDifferentContextsProduceDifferentKeys() {
        let secret = SymmetricKey(data: [UInt8](repeating: 0xCC, count: 32))
        let key1 = TLSKeyDerivation<SHA256>.expandLabel(
            secret: secret,
            label: "test",
            context: [0x01],
            length: 32
        )
        let key2 = TLSKeyDerivation<SHA256>.expandLabel(
            secret: secret,
            label: "test",
            context: [0x02],
            length: 32
        )
        key1.withUnsafeBytes { bytes1 in
            key2.withUnsafeBytes { bytes2 in
                #expect(Array(bytes1) != Array(bytes2))
            }
        }
    }

    @Test
    func emptyHashIsConsistent() {
        let hash1 = TLSKeyDerivation<SHA256>.emptyHash
        let hash2 = TLSKeyDerivation<SHA256>.emptyHash
        #expect(Array(hash1) == Array(hash2))
    }

    @Test
    func zeroKeyHasCorrectLength() {
        let key = TLSKeyDerivation<SHA256>.zeroKey
        key.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
            #expect(bytes.allSatisfy { $0 == 0 })
        }
    }

    @Test
    func sha384KeyDerivation() {
        let secret = SymmetricKey(data: [UInt8](repeating: 0xDD, count: 48))
        let result = TLSKeyDerivation<SHA384>.expandLabel(
            secret: secret,
            label: "test",
            context: [],
            length: 48
        )
        result.withUnsafeBytes { bytes in
            #expect(bytes.count == 48)
        }
    }

    @Test
    func finishedVerifyDataIsDeterministic() {
        let baseKey = SymmetricKey(data: [UInt8](repeating: 0xEE, count: 32))
        let hash = SHA256.hash(data: [0x01, 0x02, 0x03] as [UInt8])
        let mac1 = TLSKeyDerivation<SHA256>.finishedVerifyData(
            baseKey: baseKey,
            transcriptHash: hash
        )
        let mac2 = TLSKeyDerivation<SHA256>.finishedVerifyData(
            baseKey: baseKey,
            transcriptHash: hash
        )
        #expect(Array(mac1) == Array(mac2))
    }
}

@Suite
struct TLSKeyScheduleTests {
    @Test
    func fullKeyScheduleProgression() throws {
        var schedule = TLSKeySchedule<SHA256>()

        let transcriptHash1 = SHA256.hash(data: [0x01] as [UInt8])
        let earlySecret = schedule.clientEarlyTrafficSecret(
            transcriptHash: transcriptHash1
        )
        earlySecret.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }

        let privateKey = P256.KeyAgreement.PrivateKey()
        let peerKey = P256.KeyAgreement.PrivateKey().publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
            with: peerKey
        )

        let transcriptHash2 = SHA256.hash(data: [0x01, 0x02] as [UInt8])
        let hsSecrets = schedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: transcriptHash2
        )
        hsSecrets.clientHandshakeTrafficSecret.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }
        hsSecrets.serverHandshakeTrafficSecret.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }

        let transcriptHash3 = SHA256.hash(
            data: [0x01, 0x02, 0x03] as [UInt8]
        )
        let appSecrets = schedule.deriveMasterSecrets(
            transcriptHash: transcriptHash3
        )
        appSecrets.clientApplicationTrafficSecret.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }
        appSecrets.serverApplicationTrafficSecret.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }

        let transcriptHash4 = SHA256.hash(
            data: [0x01, 0x02, 0x03, 0x04] as [UInt8]
        )
        let resumption = schedule.deriveResumptionSecret(
            transcriptHash: transcriptHash4
        )
        resumption.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }
    }

    @Test
    func handshakeSecretsAreDifferentForClientAndServer() throws {
        var schedule = TLSKeySchedule<SHA256>()

        let privateKey = P256.KeyAgreement.PrivateKey()
        let peerKey = P256.KeyAgreement.PrivateKey().publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
            with: peerKey
        )
        let hash = SHA256.hash(data: [0xFF] as [UInt8])
        let secrets = schedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: hash
        )

        secrets.clientHandshakeTrafficSecret.withUnsafeBytes { clientBytes in
            secrets.serverHandshakeTrafficSecret.withUnsafeBytes { serverBytes in
                #expect(Array(clientBytes) != Array(serverBytes))
            }
        }
    }

    @Test
    func finishedVerifyDataMatchesExpected() throws {
        var schedule = TLSKeySchedule<SHA256>()

        let privateKey = P256.KeyAgreement.PrivateKey()
        let peerKey = P256.KeyAgreement.PrivateKey().publicKey
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
            with: peerKey
        )
        let hash = SHA256.hash(data: [0x01] as [UInt8])
        _ = schedule.deriveHandshakeSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: hash
        )

        let mac1 = schedule.serverFinishedVerifyData(transcriptHash: hash)
        let mac2 = schedule.serverFinishedVerifyData(transcriptHash: hash)
        #expect(Array(mac1) == Array(mac2))
        #expect(mac1.byteCount == 32)
    }

    @Test
    func pskBasedKeySchedule() {
        let psk = SymmetricKey(data: [UInt8](repeating: 0x42, count: 32))
        var schedule = TLSKeySchedule<SHA256>(psk: psk)

        let hash = SHA256.hash(data: [0x01] as [UInt8])
        let earlySecret = schedule.clientEarlyTrafficSecret(
            transcriptHash: hash
        )
        earlySecret.withUnsafeBytes { bytes in
            #expect(bytes.count == 32)
        }
    }

    @Test
    func differentPSKsProduceDifferentEarlySecrets() {
        let psk1 = SymmetricKey(data: [UInt8](repeating: 0x01, count: 32))
        let psk2 = SymmetricKey(data: [UInt8](repeating: 0x02, count: 32))

        var schedule1 = TLSKeySchedule<SHA256>(psk: psk1)
        var schedule2 = TLSKeySchedule<SHA256>(psk: psk2)

        let hash = SHA256.hash(data: [0xFF] as [UInt8])
        let secret1 = schedule1.clientEarlyTrafficSecret(transcriptHash: hash)
        let secret2 = schedule2.clientEarlyTrafficSecret(transcriptHash: hash)

        secret1.withUnsafeBytes { bytes1 in
            secret2.withUnsafeBytes { bytes2 in
                #expect(Array(bytes1) != Array(bytes2))
            }
        }
    }
}
