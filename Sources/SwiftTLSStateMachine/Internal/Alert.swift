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

/// Represents a TLS alert message with a level and description.
struct Alert: Hashable, Sendable {
    /// The alert severity level.
    var alertLevel: UInt8

    /// The alert description code.
    var alertDescription: UInt8

    /// Creates an alert from a level and description.
    init(_ alertLevel: UInt8, _ alertDescription: UInt8) {
        self.alertLevel = alertLevel
        self.alertDescription = alertDescription
    }
}

extension Alert {
    static let warningLevel: UInt8 = 1
    static let fatalLevel: UInt8 = 2

    static let closeNotify = Alert(warningLevel, 0)
    static let unexpectedMessage = Alert(fatalLevel, 10)
    static let badRecordMac = Alert(fatalLevel, 20)
    static let recordOverflow = Alert(fatalLevel, 22)
    static let handshakeFailure = Alert(fatalLevel, 40)
    static let badCertificate = Alert(fatalLevel, 42)
    static let unsupportedCertificate = Alert(fatalLevel, 43)
    static let certificateRevoked = Alert(fatalLevel, 44)
    static let certificateExpired = Alert(fatalLevel, 45)
    static let certificateUnknown = Alert(fatalLevel, 46)
    static let illegalParameter = Alert(fatalLevel, 47)
    static let unknownCA = Alert(fatalLevel, 48)
    static let accessDenied = Alert(fatalLevel, 49)
    static let decodeError = Alert(fatalLevel, 50)
    static let decryptError = Alert(fatalLevel, 51)
    static let protocolVersion = Alert(fatalLevel, 70)
    static let insufficientSecurity = Alert(fatalLevel, 71)
    static let internalError = Alert(fatalLevel, 80)
    static let inappropriateFallback = Alert(fatalLevel, 86)
    static let userCanceled = Alert(fatalLevel, 90)
    static let missingExtension = Alert(fatalLevel, 109)
    static let unsupportedExtension = Alert(fatalLevel, 110)
    static let unrecognizedName = Alert(fatalLevel, 112)
    static let badCertificateStatusResponse = Alert(fatalLevel, 113)
    static let unknownPskIdentity = Alert(fatalLevel, 115)
    static let certificateRequired = Alert(fatalLevel, 116)
    static let noApplicationProtocol = Alert(fatalLevel, 120)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension Alert: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.alertLevel = try UInt8(parsing: &input)
        self.alertDescription = try UInt8(parsing: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension Alert: SerializableToBytes {
    public typealias SerializationState = FixedSizeSerializationState<2>

    static func startSerialization(
        of value: borrowing Alert
    ) throws(SerializationError) -> SerializationState {
        var bytes = InlineArray<2, UInt8>(repeating: 0)
        bytes[0] = value.alertLevel
        bytes[1] = value.alertDescription
        return FixedSizeSerializationState(bytes: bytes)
    }

    @discardableResult
    static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        state.serialize(into: &output)
    }
}

extension Alert: CustomStringConvertible {
    var description: String {
        switch self {
        case .closeNotify: "close notify"
        case .unexpectedMessage: "unexpected message"
        case .badRecordMac: "bad record mac"
        case .recordOverflow: "record overflow"
        case .handshakeFailure: "handshake failure"
        case .badCertificate: "bad certificate"
        case .illegalParameter: "illegal parameter"
        case .decodeError: "decode error"
        case .internalError: "internal error"
        case .missingExtension: "missing extension"
        case .noApplicationProtocol: "no application protocol"
        default: "Alert(level: \(self.alertLevel), description: \(self.alertDescription))"
        }
    }
}
