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

/// Identifies a TLS extension type.
struct ExtensionType: RawRepresentable, Hashable, Sendable {
    var rawValue: UInt16

    init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

extension ExtensionType {
    static let serverName = ExtensionType(rawValue: 0)
    static let supportedGroups = ExtensionType(rawValue: 10)
    static let signatureAlgorithms = ExtensionType(rawValue: 13)
    static let applicationLayerProtocolNegotiation = ExtensionType(rawValue: 16)
    static let clientCertificateType = ExtensionType(rawValue: 19)
    static let serverCertificateType = ExtensionType(rawValue: 20)
    static let preSharedKey = ExtensionType(rawValue: 41)
    static let earlyData = ExtensionType(rawValue: 42)
    static let supportedVersions = ExtensionType(rawValue: 43)
    static let preSharedKeyKexModes = ExtensionType(rawValue: 45)
    static let keyShare = ExtensionType(rawValue: 51)
    static let quicTransportParameters = ExtensionType(rawValue: 57)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ExtensionType: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.rawValue = try UInt16(parsingBigEndian: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension ExtensionType: SerializableToBytes {
    public typealias SerializationState = UInt16.SerializationState

    static func startSerialization(
        of value: borrowing ExtensionType
    ) throws(SerializationError) -> SerializationState {
        try UInt16.startSerialization(of: value.rawValue)
    }

    @discardableResult
    static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        state.serialize(into: &output)
    }
}
