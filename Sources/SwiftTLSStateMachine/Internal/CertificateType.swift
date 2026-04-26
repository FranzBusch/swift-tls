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

/// Identifies a certificate encoding format.
struct CertificateType: RawRepresentable, Hashable, Sendable {
    var rawValue: UInt8

    init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

extension CertificateType {
    static let x509 = CertificateType(rawValue: 0)
    static let rawPublicKey = CertificateType(rawValue: 2)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CertificateType: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.rawValue = try UInt8(parsing: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CertificateType: SerializableToBytes {
    public typealias SerializationState = UInt8.SerializationState

    static func startSerialization(
        of value: borrowing CertificateType
    ) throws(SerializationError) -> SerializationState {
        try UInt8.startSerialization(of: value.rawValue)
    }

    @discardableResult
    static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        state.serialize(into: &output)
    }
}

extension CertificateType: CustomStringConvertible {
    var description: String {
        switch self {
        case .x509: ".x509"
        case .rawPublicKey: ".rawPublicKey"
        default: "CertificateType(rawValue: \(self.rawValue))"
        }
    }
}
