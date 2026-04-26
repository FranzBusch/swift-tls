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

/// Describes a problem detected during a TLS handshake state machine
/// transition.
///
/// The caller decides how to handle the error, including which TLS
/// ``Alert`` to send to the peer if any.
public enum HandshakeError: Error, Hashable, Sendable {
    /// A message was received that is not valid in the current state.
    case unexpectedMessage

    /// The peer's ServerHello did not include a usable key share.
    case missingKeyShare

    /// The peer's key share data could not be parsed.
    case invalidKeyShare

    /// The peer selected a cipher suite that was not offered.
    case unsupportedCipherSuite

    /// The peer selected a protocol version that was not offered.
    case unsupportedVersion
}
