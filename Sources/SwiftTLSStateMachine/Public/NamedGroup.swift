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

/// Identifies a named elliptic curve or key exchange group.
public struct NamedGroup: RawRepresentable, Hashable, Sendable {
    public var rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

extension NamedGroup {
    public static let secp256 = NamedGroup(rawValue: 0x0017)
    public static let secp384 = NamedGroup(rawValue: 0x0018)
    public static let x25519 = NamedGroup(rawValue: 0x001D)
    public static let x25519MLKEM768 = NamedGroup(rawValue: 0x11EC)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension NamedGroup: ExpressibleByParsing {
    public init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.rawValue = try UInt16(parsingBigEndian: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension NamedGroup: SerializableToBytes {
    public typealias SerializationState = UInt16.SerializationState

    public static func startSerialization(
        of value: borrowing NamedGroup
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

extension NamedGroup: CustomStringConvertible {
    public var description: String {
        switch self {
        case .secp256: ".secp256"
        case .secp384: ".secp384"
        case .x25519: ".x25519"
        case .x25519MLKEM768: ".x25519MLKEM768"
        default: "NamedGroup(rawValue: \(self.rawValue))"
        }
    }
}
