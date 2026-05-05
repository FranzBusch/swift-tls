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

/// Configuration for a TLS 1.3 client handshake.
public struct ClientHandshakeConfiguration: Sendable {
    /// The cipher suites to offer.
    public var cipherSuites: [CipherSuite]

    /// The key exchange groups to support.
    public var supportedGroups: [NamedGroup]

    /// The signature algorithms to accept.
    public var signatureAlgorithms: [SignatureScheme]

    /// The TLS versions to offer.
    public var supportedVersions: [ProtocolVersion]

    /// The server hostname for SNI.
    public var serverName: String?

    /// The ALPN protocols to offer.
    public var alpnProtocols: [String]

    /// Creates a client handshake configuration with sensible defaults.
    public init(
        serverName: String? = nil,
        alpnProtocols: [String] = []
    ) {
        self.cipherSuites = [
            .TLS_AES_128_GCM_SHA256,
            .TLS_CHACHA20_POLY1305_SHA256,
            // TODO: TLS_AES_256_GCM_SHA384 requires SHA384 key schedule + transcript hash
        ]
        self.supportedGroups = [.x25519, .secp256]
        self.signatureAlgorithms = [
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
        ]
        self.supportedVersions = [.tlsv13]
        self.serverName = serverName
        self.alpnProtocols = alpnProtocols
    }
}
