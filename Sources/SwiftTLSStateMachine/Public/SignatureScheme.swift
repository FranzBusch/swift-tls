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

public import BinaryParsing
public import BinarySerialization

/// Identifies a TLS signature algorithm.
public struct SignatureScheme: RawRepresentable, Hashable, Sendable {
    public var rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

extension SignatureScheme {
    public static let ecdsa_secp256r1_sha256 = SignatureScheme(rawValue: 0x0403)
    public static let ecdsa_secp384r1_sha384 = SignatureScheme(rawValue: 0x0503)
    public static let rsa_pss_rsae_sha256 = SignatureScheme(rawValue: 0x0804)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension SignatureScheme: ExpressibleByParsing {
    public init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.rawValue = try UInt16(parsingBigEndian: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension SignatureScheme: SerializableToBytes {
    public typealias SerializationState = UInt16.SerializationState

    public static func startSerialization(
        of value: borrowing SignatureScheme
    ) throws(SerializationError) -> SerializationState {
        try UInt16.startSerialization(of: value.rawValue)
    }

    @discardableResult
    public static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        state.serialize(into: &output)
    }
}

extension SignatureScheme: CustomStringConvertible {
    public var description: String {
        switch self {
        case .ecdsa_secp256r1_sha256: ".ecdsa_secp256r1_sha256"
        case .ecdsa_secp384r1_sha384: ".ecdsa_secp384r1_sha384"
        case .rsa_pss_rsae_sha256: ".rsa_pss_rsae_sha256"
        default: "SignatureScheme(rawValue: \(self.rawValue))"
        }
    }
}
