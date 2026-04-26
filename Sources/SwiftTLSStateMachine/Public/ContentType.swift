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

/// Identifies the type of a TLS record.
public struct ContentType: RawRepresentable, Hashable, Sendable {
    public var rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

extension ContentType {
    public static let invalid = ContentType(rawValue: 0)
    public static let changeCipherSpec = ContentType(rawValue: 20)
    public static let alert = ContentType(rawValue: 21)
    public static let handshake = ContentType(rawValue: 22)
    public static let applicationData = ContentType(rawValue: 23)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ContentType: ExpressibleByParsing {
    public init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.rawValue = try UInt8(parsing: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ContentType: SerializableToBytes {
    public typealias SerializationState = UInt8.SerializationState

    public static func startSerialization(
        of value: borrowing ContentType
    ) throws(SerializationError) -> SerializationState {
        try UInt8.startSerialization(of: value.rawValue)
    }

    @discardableResult
    public static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        state.serialize(into: &output)
    }
}

extension ContentType: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalid: ".invalid"
        case .changeCipherSpec: ".changeCipherSpec"
        case .alert: ".alert"
        case .handshake: ".handshake"
        case .applicationData: ".applicationData"
        default: "ContentType(rawValue: \(self.rawValue))"
        }
    }
}
