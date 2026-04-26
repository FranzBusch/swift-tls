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

/// Identifies the type of a TLS handshake message.
struct HandshakeType: RawRepresentable, Hashable, Sendable {
    var rawValue: UInt8

    init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

extension HandshakeType {
    static let clientHello = HandshakeType(rawValue: 1)
    static let serverHello = HandshakeType(rawValue: 2)
    static let newSessionTicket = HandshakeType(rawValue: 4)
    static let endOfEarlyData = HandshakeType(rawValue: 5)
    static let encryptedExtensions = HandshakeType(rawValue: 8)
    static let certificate = HandshakeType(rawValue: 11)
    static let certificateRequest = HandshakeType(rawValue: 13)
    static let certificateVerify = HandshakeType(rawValue: 15)
    static let finished = HandshakeType(rawValue: 20)
    static let keyUpdate = HandshakeType(rawValue: 24)
    static let messageHash = HandshakeType(rawValue: 254)
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension HandshakeType: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.rawValue = try UInt8(parsing: &input)
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension HandshakeType: SerializableToBytes {
    public typealias SerializationState = UInt8.SerializationState

    static func startSerialization(
        of value: borrowing HandshakeType
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

extension HandshakeType: CustomStringConvertible {
    var description: String {
        switch self {
        case .clientHello: ".clientHello"
        case .serverHello: ".serverHello"
        case .newSessionTicket: ".newSessionTicket"
        case .endOfEarlyData: ".endOfEarlyData"
        case .encryptedExtensions: ".encryptedExtensions"
        case .certificate: ".certificate"
        case .certificateRequest: ".certificateRequest"
        case .certificateVerify: ".certificateVerify"
        case .finished: ".finished"
        case .keyUpdate: ".keyUpdate"
        case .messageHash: ".messageHash"
        default: "HandshakeType(rawValue: \(self.rawValue))"
        }
    }
}
