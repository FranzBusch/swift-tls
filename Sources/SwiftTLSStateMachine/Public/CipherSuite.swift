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

/// Identifies a TLS cipher suite.
public struct CipherSuite: RawRepresentable, Hashable, Sendable {
    public var rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

extension CipherSuite {
    public static let TLS_AES_128_GCM_SHA256 = CipherSuite(rawValue: 0x1301)
    public static let TLS_AES_256_GCM_SHA384 = CipherSuite(rawValue: 0x1302)
    public static let TLS_CHACHA20_POLY1305_SHA256 = CipherSuite(rawValue: 0x1303)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CipherSuite: ExpressibleByParsing {
    public init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.rawValue = try UInt16(parsingBigEndian: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CipherSuite: SerializableToBytes {
    public typealias SerializationState = UInt16.SerializationState

    public static func startSerialization(
        of value: borrowing CipherSuite
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

extension CipherSuite: CustomStringConvertible {
    public var description: String {
        switch self {
        case .TLS_AES_128_GCM_SHA256: "TLS_AES_128_GCM_SHA256"
        case .TLS_AES_256_GCM_SHA384: "TLS_AES_256_GCM_SHA384"
        case .TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256"
        default: "CipherSuite(0x\(String(self.rawValue, radix: 16)))"
        }
    }
}
