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

/// Configuration for a TLS 1.3 server handshake.
public struct ServerHandshakeConfiguration: @unchecked Sendable {
    /// The cipher suites the server supports, in preference order.
    public var cipherSuites: [CipherSuite]

    /// The key exchange groups the server supports.
    public var supportedGroups: [NamedGroup]

    /// The signature algorithms the server supports.
    public var signatureAlgorithms: [SignatureScheme]

    /// The ALPN protocols the server supports, in preference order.
    public var alpnProtocols: [String]

    /// The certificate chain as DER-encoded bytes, leaf first.
    public var certificateChainDER: [[UInt8]]

    /// The server's ECDSA P-256 signing key.
    public var signingKey: P256.Signing.PrivateKey

    /// Creates a server handshake configuration.
    public init(
        certificateChainDER: [[UInt8]],
        signingKey: P256.Signing.PrivateKey,
        alpnProtocols: [String] = []
    ) {
        self.cipherSuites = [
            .TLS_AES_128_GCM_SHA256,
            .TLS_CHACHA20_POLY1305_SHA256,
            // TODO: TLS_AES_256_GCM_SHA384 requires SHA384 key schedule + transcript hash.
            // Currently the key schedule is hardcoded to SHA256. Add SHA384 support
            // before enabling this cipher suite.
        ]
        self.supportedGroups = [.x25519, .secp256]
        self.signatureAlgorithms = [
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
        ]
        self.alpnProtocols = alpnProtocols
        self.certificateChainDER = certificateChainDER
        self.signingKey = signingKey
    }
}
