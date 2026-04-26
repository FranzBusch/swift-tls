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

/// Identifies the TLS protocol version.
public struct ProtocolVersion: Hashable, Sendable {
    /// The major version number.
    public var major: UInt8

    /// The minor version number.
    public var minor: UInt8

    /// Creates a protocol version from major and minor components.
    public init(major: UInt8, minor: UInt8) {
        self.major = major
        self.minor = minor
    }
}

extension ProtocolVersion {
    public static let sslv3 = ProtocolVersion(major: 3, minor: 0)
    public static let tlsv10 = ProtocolVersion(major: 3, minor: 1)
    public static let tlsv11 = ProtocolVersion(major: 3, minor: 2)
    public static let tlsv12 = ProtocolVersion(major: 3, minor: 3)
    public static let tlsv13 = ProtocolVersion(major: 3, minor: 4)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ProtocolVersion: ExpressibleByParsing {
    public init(parsing input: inout ParserSpan) throws(ParsingError) {
        let raw = try UInt16(parsingBigEndian: &input)
        self.major = UInt8(truncatingIfNeeded: raw >> 8)
        self.minor = UInt8(truncatingIfNeeded: raw)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ProtocolVersion: SerializableToBytes {
    public typealias SerializationState = UInt16.SerializationState

    public static func startSerialization(
        of value: borrowing ProtocolVersion
    ) throws(SerializationError) -> SerializationState {
        let raw = UInt16(value.major) << 8 | UInt16(value.minor)
        return try UInt16.startSerialization(of: raw)
    }

    @discardableResult
    public static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        state.serialize(into: &output)
    }
}

extension ProtocolVersion: CustomStringConvertible {
    public var description: String {
        switch self {
        case .sslv3: ".sslv3"
        case .tlsv10: ".tlsv10"
        case .tlsv11: ".tlsv11"
        case .tlsv12: ".tlsv12"
        case .tlsv13: ".tlsv13"
        default: "ProtocolVersion(major: \(self.major), minor: \(self.minor))"
        }
    }
}
