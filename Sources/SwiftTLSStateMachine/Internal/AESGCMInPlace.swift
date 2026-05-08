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

// Emulates the in-place AES-GCM APIs coming in Swift Crypto (macOS 27+).

extension AES.GCM {
    /// Encrypts `message` in-place and writes the authentication tag
    /// into `tag`.
    static func sealEmulatingInPlace(
        message: inout MutableSpan<UInt8>,
        using key: SymmetricKey,
        nonce: AES.GCM.Nonce,
        authenticating aad: borrowing Span<UInt8>,
        tag: inout MutableSpan<UInt8>
    ) throws {
        precondition(tag.count == 16)

        var plaintext = [UInt8](repeating: 0, count: message.count)
        for i in 0..<message.count { plaintext[i] = message[i] }


        var aadStorage = [UInt8](repeating: 0, count: aad.count)
        for i in 0..<aad.count { aadStorage[i] = aad[i] }
        let sealedBox = try AES.GCM.seal(
            plaintext, using: key, nonce: nonce, authenticating: aadStorage
        )

        let ct = sealedBox.ciphertext
        precondition(ct.count == message.count)
        for i in 0..<ct.count {
            message[i] = ct[ct.startIndex + i]
        }

        let sealedTag = sealedBox.tag
        precondition(sealedTag.count == 16)
        for i in 0..<sealedTag.count {
            tag[i] = sealedTag[sealedTag.startIndex + i]
        }
    }

    /// Decrypts `message` in-place, verifying against `tag`.
    static func openEmulatingInPlace(
        message: inout MutableSpan<UInt8>,
        using key: SymmetricKey,
        nonce: AES.GCM.Nonce,
        authenticating aad: borrowing Span<UInt8>,
        tag: borrowing Span<UInt8>
    ) throws {
        precondition(tag.count == 16)

        var ciphertext = [UInt8](repeating: 0, count: message.count)
        for i in 0..<message.count { ciphertext[i] = message[i] }

        var tagBytes = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { tagBytes[i] = tag[i] }

        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce, ciphertext: ciphertext, tag: tagBytes
        )
        var aadStorage = [UInt8](repeating: 0, count: aad.count)
        for i in 0..<aad.count { aadStorage[i] = aad[i] }
        let plaintext = try Array(AES.GCM.open(sealedBox, using: key, authenticating: aadStorage))

        precondition(plaintext.count == message.count)
        for i in 0..<plaintext.count {
            message[i] = plaintext[i]
        }
    }
}
