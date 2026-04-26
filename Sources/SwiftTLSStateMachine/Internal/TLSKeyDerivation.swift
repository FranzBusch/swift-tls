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

/// TLS 1.3 HKDF utilities per RFC 8446 Section 7.1.
package enum TLSKeyDerivation<HF: HashFunction> {
    /// Performs HKDF-Expand-Label as defined in RFC 8446 Section 7.1.
    ///
    /// ```
    /// HKDF-Expand-Label(Secret, Label, Context, Length) =
    ///     HKDF-Expand(Secret, HkdfLabel, Length)
    ///
    /// struct {
    ///     uint16 length = Length;
    ///     opaque label<7..255> = "tls13 " + Label;
    ///     opaque context<0..255> = Context;
    /// } HkdfLabel;
    /// ```
    package static func expandLabel(
        secret: SymmetricKey,
        label: String,
        context: [UInt8],
        length: Int
    ) -> SymmetricKey {
        let fullLabel = "tls13 " + label
        var hkdfLabel: [UInt8] = []
        hkdfLabel.reserveCapacity(2 + 1 + fullLabel.utf8.count + 1 + HF.Digest.byteCount)

        hkdfLabel.append(UInt8(truncatingIfNeeded: length >> 8))
        hkdfLabel.append(UInt8(truncatingIfNeeded: length))

        hkdfLabel.append(UInt8(fullLabel.utf8.count))
        hkdfLabel.append(contentsOf: fullLabel.utf8)

        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(contentsOf: context)

        return HKDF<HF>.expand(
            pseudoRandomKey: secret,
            info: hkdfLabel,
            outputByteCount: length
        )
    }

    /// Derives a secret from a base secret and transcript hash.
    ///
    /// ```
    /// Derive-Secret(Secret, Label, Messages) =
    ///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
    /// ```
    package static func deriveSecret(
        secret: SymmetricKey,
        label: String,
        transcriptHash: HF.Digest
    ) -> SymmetricKey {
        expandLabel(
            secret: secret,
            label: label,
            context: Array(transcriptHash),
            length: HF.Digest.byteCount
        )
    }

    /// Performs HKDF-Extract.
    package static func extract(
        inputKeyMaterial: SymmetricKey,
        salt: SymmetricKey
    ) -> SymmetricKey {
        salt.withUnsafeBytes { saltBytes in
            let prk = HKDF<HF>.extract(
                inputKeyMaterial: inputKeyMaterial,
                salt: saltBytes
            )
            return SymmetricKey(data: prk)
        }
    }

    /// Returns a zero-filled symmetric key of the hash output length.
    package static var zeroKey: SymmetricKey {
        SymmetricKey(data: [UInt8](repeating: 0, count: HF.Digest.byteCount))
    }

    /// Returns the hash of an empty input.
    package static var emptyHash: HF.Digest {
        HF().finalize()
    }

    /// Computes the Finished verify data per RFC 8446 Section 4.4.4.
    ///
    /// ```
    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    /// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
    /// ```
    package static func finishedVerifyData(
        baseKey: SymmetricKey,
        transcriptHash: HF.Digest
    ) -> HMAC<HF>.MAC {
        let finishedKey = expandLabel(
            secret: baseKey,
            label: "finished",
            context: [UInt8](),
            length: HF.Digest.byteCount
        )
        return HMAC<HF>.authenticationCode(
            for: Array(transcriptHash),
            using: finishedKey
        )
    }
}
