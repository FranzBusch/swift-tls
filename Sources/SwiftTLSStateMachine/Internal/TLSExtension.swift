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

/// A TLS extension as sent in handshake messages.
///
/// Each extension has a 2-byte type and 2-byte length prefix on the wire:
/// ```
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
struct TLSExtension: Equatable, Sendable {
    /// The extension type.
    var type: ExtensionType

    /// The raw extension data bytes.
    var data: [UInt8]

    /// Creates an extension from a type and raw data.
    init(type: ExtensionType, data: [UInt8]) {
        self.type = type
        self.data = data
    }
}

// MARK: - Well-known extension constructors

extension TLSExtension {
    /// Creates a supported_versions extension for a ClientHello.
    static func supportedVersions(_ versions: [ProtocolVersion]) -> TLSExtension {
        var data: [UInt8] = []
        let listLength = UInt8(versions.count * 2)
        data.append(listLength)
        for version in versions {
            data.append(version.major)
            data.append(version.minor)
        }
        return TLSExtension(type: .supportedVersions, data: data)
    }

    /// Creates a supported_versions extension for a ServerHello.
    static func serverSupportedVersion(_ version: ProtocolVersion) -> TLSExtension {
        TLSExtension(
            type: .supportedVersions,
            data: [version.major, version.minor]
        )
    }

    /// Creates a supported_groups extension.
    static func supportedGroups(_ groups: [NamedGroup]) -> TLSExtension {
        var data: [UInt8] = []
        let listLength = UInt16(groups.count * 2)
        data.append(UInt8(truncatingIfNeeded: listLength >> 8))
        data.append(UInt8(truncatingIfNeeded: listLength))
        for group in groups {
            data.append(UInt8(truncatingIfNeeded: group.rawValue >> 8))
            data.append(UInt8(truncatingIfNeeded: group.rawValue))
        }
        return TLSExtension(type: .supportedGroups, data: data)
    }

    /// Creates a signature_algorithms extension.
    static func signatureAlgorithms(_ schemes: [SignatureScheme]) -> TLSExtension {
        var data: [UInt8] = []
        let listLength = UInt16(schemes.count * 2)
        data.append(UInt8(truncatingIfNeeded: listLength >> 8))
        data.append(UInt8(truncatingIfNeeded: listLength))
        for scheme in schemes {
            data.append(UInt8(truncatingIfNeeded: scheme.rawValue >> 8))
            data.append(UInt8(truncatingIfNeeded: scheme.rawValue))
        }
        return TLSExtension(type: .signatureAlgorithms, data: data)
    }

    /// Creates a key_share extension with a single key exchange entry
    /// for a ClientHello (includes list length prefix).
    static func keyShareClientHello(group: NamedGroup, keyExchange: [UInt8]) -> TLSExtension {
        var data: [UInt8] = []
        let entryLength = 2 + 2 + keyExchange.count
        let listLength = UInt16(entryLength)
        data.append(UInt8(truncatingIfNeeded: listLength >> 8))
        data.append(UInt8(truncatingIfNeeded: listLength))
        data.append(UInt8(truncatingIfNeeded: group.rawValue >> 8))
        data.append(UInt8(truncatingIfNeeded: group.rawValue))
        let keyLength = UInt16(keyExchange.count)
        data.append(UInt8(truncatingIfNeeded: keyLength >> 8))
        data.append(UInt8(truncatingIfNeeded: keyLength))
        data.append(contentsOf: keyExchange)
        return TLSExtension(type: .keyShare, data: data)
    }

    /// Creates a key_share extension for a ServerHello (no list length
    /// prefix, just a single KeyShareEntry).
    static func keyShareServerHello(group: NamedGroup, keyExchange: [UInt8]) -> TLSExtension {
        var data: [UInt8] = []
        data.append(UInt8(truncatingIfNeeded: group.rawValue >> 8))
        data.append(UInt8(truncatingIfNeeded: group.rawValue))
        let keyLength = UInt16(keyExchange.count)
        data.append(UInt8(truncatingIfNeeded: keyLength >> 8))
        data.append(UInt8(truncatingIfNeeded: keyLength))
        data.append(contentsOf: keyExchange)
        return TLSExtension(type: .keyShare, data: data)
    }

    /// Creates a server_name extension.
    static func serverName(_ hostname: String) -> TLSExtension {
        let nameBytes = Array(hostname.utf8)
        var data: [UInt8] = []
        let nameLength = UInt16(nameBytes.count)
        let entryLength = UInt16(1 + 2 + nameBytes.count)
        let listLength = UInt16(entryLength)
        data.append(UInt8(truncatingIfNeeded: listLength >> 8))
        data.append(UInt8(truncatingIfNeeded: listLength))
        data.append(0x00) // host_name type
        data.append(UInt8(truncatingIfNeeded: nameLength >> 8))
        data.append(UInt8(truncatingIfNeeded: nameLength))
        data.append(contentsOf: nameBytes)
        return TLSExtension(type: .serverName, data: data)
    }

    /// Creates an ALPN extension.
    static func alpn(_ protocols: [String]) -> TLSExtension {
        var listData: [UInt8] = []
        for proto in protocols {
            let protoBytes = Array(proto.utf8)
            listData.append(UInt8(protoBytes.count))
            listData.append(contentsOf: protoBytes)
        }
        var data: [UInt8] = []
        let listLength = UInt16(listData.count)
        data.append(UInt8(truncatingIfNeeded: listLength >> 8))
        data.append(UInt8(truncatingIfNeeded: listLength))
        data.append(contentsOf: listData)
        return TLSExtension(type: .applicationLayerProtocolNegotiation, data: data)
    }
}

// MARK: - Parsing and serialization

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension TLSExtension: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.type = try ExtensionType(parsing: &input)
        let length = try UInt16(parsingBigEndian: &input)
        self.data = try Array(parsing: &input, byteCount: Int(length))
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension TLSExtension: SerializableToBytes {
    enum SerializationState {
        case header(
            FixedSizeSerializationState<4>,
            pendingData: [UInt8]
        )
        case data(Array<UInt8>.SerializationState)
    }

    static func startSerialization(
        of value: borrowing TLSExtension
    ) throws(SerializationError) -> SerializationState {
        guard value.data.count <= Int(UInt16.max) else {
            throw SerializationError(status: .valueTooLarge)
        }
        let length = UInt16(value.data.count)
        var headerBytes = InlineArray<4, UInt8>(repeating: 0)
        headerBytes[0] = UInt8(truncatingIfNeeded: value.type.rawValue >> 8)
        headerBytes[1] = UInt8(truncatingIfNeeded: value.type.rawValue)
        headerBytes[2] = UInt8(truncatingIfNeeded: length >> 8)
        headerBytes[3] = UInt8(truncatingIfNeeded: length)
        return .header(
            FixedSizeSerializationState(bytes: headerBytes),
            pendingData: Array(value.data)
        )
    }

    @discardableResult
    static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        switch state {
        case .header(var headerState, let pendingData):
            if headerState.serialize(into: &output) {
                var dataState = try! [UInt8].startSerialization(of: pendingData)
                if [UInt8].serialize(state: &dataState, into: &output) {
                    return true
                }
                state = .data(dataState)
                return false
            }
            state = .header(headerState, pendingData: pendingData)
            return false
        case .data(var dataState):
            let done = [UInt8].serialize(state: &dataState, into: &output)
            if !done { state = .data(dataState) }
            return done
        }
    }
}
