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

/// A TLS 1.3 handshake message.
///
/// On the wire, each handshake message is framed as:
/// ```
/// struct {
///     HandshakeType msg_type;    /* 1 byte */
///     uint24 length;             /* 3 bytes */
///     select (msg_type) { ... }; /* variable */
/// } Handshake;
/// ```
///
/// Conforms to ``ExpressibleByParsing`` and ``SerializableToBytes``
/// so it works directly with `ParsingAsyncReader` and
/// `SerializingAsyncWriter`.
enum HandshakeMessage: Equatable, Sendable {
    case clientHello(ClientHello)
    case serverHello(ServerHello)
    case encryptedExtensions(EncryptedExtensions)
    case certificateRequest(CertificateRequest)
    case certificate(CertificateMessage)
    case certificateVerify(CertificateVerify)
    case finished(FinishedMessage)
    case newSessionTicket(NewSessionTicket)

    /// The handshake type byte for this message.
    var handshakeType: HandshakeType {
        switch self {
        case .clientHello: .clientHello
        case .serverHello: .serverHello
        case .encryptedExtensions: .encryptedExtensions
        case .certificateRequest: .certificateRequest
        case .certificate: .certificate
        case .certificateVerify: .certificateVerify
        case .finished: .finished
        case .newSessionTicket: .newSessionTicket
        }
    }
}

// MARK: - Parsing helpers for remaining message types

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension EncryptedExtensions: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        let extensionsLength = try UInt16(parsingBigEndian: &input)
        var extSpan = try input.sliceSpan(byteCount: Int(extensionsLength))
        var exts: [TLSExtension] = []
        while !extSpan.isEmpty {
            exts.append(try TLSExtension(parsing: &extSpan))
        }
        self.extensions = exts
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CertificateEntry: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        // cert_data length is UInt24 (3 bytes)
        let b0 = try UInt8(parsing: &input)
        let b1 = try UInt8(parsing: &input)
        let b2 = try UInt8(parsing: &input)
        let certDataLength = Int(b0) << 16 | Int(b1) << 8 | Int(b2)
        self.certificateData = try Array(parsing: &input, byteCount: certDataLength)

        let extensionsLength = try UInt16(parsingBigEndian: &input)
        var extSpan = try input.sliceSpan(byteCount: Int(extensionsLength))
        var exts: [TLSExtension] = []
        while !extSpan.isEmpty {
            exts.append(try TLSExtension(parsing: &extSpan))
        }
        self.extensions = exts
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CertificateMessage: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        let contextLength = try UInt8(parsing: &input)
        self.requestContext = try Array(parsing: &input, byteCount: Int(contextLength))

        // certificate_list length is UInt24
        let b0 = try UInt8(parsing: &input)
        let b1 = try UInt8(parsing: &input)
        let b2 = try UInt8(parsing: &input)
        let listLength = Int(b0) << 16 | Int(b1) << 8 | Int(b2)
        var listSpan = try input.sliceSpan(byteCount: listLength)
        var entries: [CertificateEntry] = []
        while !listSpan.isEmpty {
            entries.append(try CertificateEntry(parsing: &listSpan))
        }
        self.certificateList = entries
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension NewSessionTicket: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        self.ticketLifetime = try UInt32(parsingBigEndian: &input)
        self.ticketAgeAdd = try UInt32(parsingBigEndian: &input)

        let nonceLength = try UInt8(parsing: &input)
        self.ticketNonce = try Array(parsing: &input, byteCount: Int(nonceLength))

        let ticketLength = try UInt16(parsingBigEndian: &input)
        self.ticket = try Array(parsing: &input, byteCount: Int(ticketLength))

        let extensionsLength = try UInt16(parsingBigEndian: &input)
        var extSpan = try input.sliceSpan(byteCount: Int(extensionsLength))
        var exts: [TLSExtension] = []
        while !extSpan.isEmpty {
            exts.append(try TLSExtension(parsing: &extSpan))
        }
        self.extensions = exts
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension CertificateRequest: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        let contextLength = try UInt8(parsing: &input)
        self.requestContext = try Array(parsing: &input, byteCount: Int(contextLength))

        let extensionsLength = try UInt16(parsingBigEndian: &input)
        var extSpan = try input.sliceSpan(byteCount: Int(extensionsLength))
        var exts: [TLSExtension] = []
        while !extSpan.isEmpty {
            exts.append(try TLSExtension(parsing: &extSpan))
        }
        self.extensions = exts
    }
}

// MARK: - HandshakeMessage parsing and serialization

/// An error thrown when an unknown handshake type is encountered.
struct UnknownHandshakeTypeError: Error, Sendable {
    let type: HandshakeType
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension HandshakeMessage: ExpressibleByParsing {
    init(parsing input: inout ParserSpan) throws(ParsingError) {
        let msgType = try HandshakeType(parsing: &input)
        let b0 = try UInt8(parsing: &input)
        let b1 = try UInt8(parsing: &input)
        let b2 = try UInt8(parsing: &input)
        let length = Int(b0) << 16 | Int(b1) << 8 | Int(b2)
        var bodySpan = try input.sliceSpan(byteCount: length)

        switch msgType {
        case .clientHello:
            self = .clientHello(try ClientHello(parsing: &bodySpan))
        case .serverHello:
            self = .serverHello(try ServerHello(parsing: &bodySpan))
        case .encryptedExtensions:
            self = .encryptedExtensions(try EncryptedExtensions(parsing: &bodySpan))
        case .certificateRequest:
            self = .certificateRequest(try CertificateRequest(parsing: &bodySpan))
        case .certificate:
            self = .certificate(try CertificateMessage(parsing: &bodySpan))
        case .certificateVerify:
            self = .certificateVerify(try CertificateVerify(parsing: &bodySpan))
        case .finished:
            self = .finished(FinishedMessage(
                verifyData: try Array(parsing: &bodySpan, byteCount: bodySpan.count)
            ))
        case .newSessionTicket:
            self = .newSessionTicket(try NewSessionTicket(parsing: &bodySpan))
        default:
            throw ParsingError(userError: UnknownHandshakeTypeError(type: msgType))
        }
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
extension HandshakeMessage: SerializableToBytes {
    enum SerializationState {
        case header(
            FixedSizeSerializationState<4>,
            pendingBody: [UInt8]
        )
        case body(Array<UInt8>.SerializationState)
    }

    static func startSerialization(
        of value: borrowing HandshakeMessage
    ) throws(SerializationError) -> SerializationState {
        let body = serializeBody(value)
        let length = body.count
        var headerBytes = InlineArray<4, UInt8>(repeating: 0)
        headerBytes[0] = value.handshakeType.rawValue
        headerBytes[1] = UInt8(truncatingIfNeeded: length >> 16)
        headerBytes[2] = UInt8(truncatingIfNeeded: length >> 8)
        headerBytes[3] = UInt8(truncatingIfNeeded: length)
        return .header(
            FixedSizeSerializationState(bytes: headerBytes),
            pendingBody: body
        )
    }

    @discardableResult
    static func serialize(
        state: inout SerializationState,
        into output: inout OutputSpan<UInt8>
    ) -> Bool {
        switch state {
        case .header(var headerState, let pendingBody):
            if headerState.serialize(into: &output) {
                var bodyState = try! [UInt8].startSerialization(of: pendingBody)
                if [UInt8].serialize(state: &bodyState, into: &output) {
                    return true
                }
                state = .body(bodyState)
                return false
            }
            state = .header(headerState, pendingBody: pendingBody)
            return false
        case .body(var bodyState):
            let done = [UInt8].serialize(state: &bodyState, into: &output)
            if !done { state = .body(bodyState) }
            return done
        }
    }

    private static func serializeBody(
        _ message: borrowing HandshakeMessage
    ) -> [UInt8] {
        switch message {
        case .clientHello(let ch): serializeClientHello(ch)
        case .serverHello(let sh): serializeServerHello(sh)
        case .encryptedExtensions(let ee): serializeEncryptedExtensions(ee)
        case .certificateRequest(let cr): serializeCertificateRequest(cr)
        case .certificate(let cm): serializeCertificateMessage(cm)
        case .certificateVerify(let cv): serializeCertificateVerify(cv)
        case .finished(let fin): fin.verifyData
        case .newSessionTicket(let nst): serializeNewSessionTicket(nst)
        }
    }

    private static func serializeClientHello(_ ch: ClientHello) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(ch.legacyVersion.major)
        bytes.append(ch.legacyVersion.minor)
        bytes.append(contentsOf: ch.random)
        bytes.append(UInt8(ch.legacySessionID.count))
        bytes.append(contentsOf: ch.legacySessionID)
        let suitesLen = UInt16(ch.cipherSuites.count * 2)
        bytes.append(UInt8(truncatingIfNeeded: suitesLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: suitesLen))
        for suite in ch.cipherSuites {
            bytes.append(UInt8(truncatingIfNeeded: suite.rawValue >> 8))
            bytes.append(UInt8(truncatingIfNeeded: suite.rawValue))
        }
        bytes.append(UInt8(ch.legacyCompressionMethods.count))
        bytes.append(contentsOf: ch.legacyCompressionMethods)
        appendExtensionList(ch.extensions, to: &bytes)
        return bytes
    }

    private static func serializeServerHello(_ sh: ServerHello) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(sh.legacyVersion.major)
        bytes.append(sh.legacyVersion.minor)
        bytes.append(contentsOf: sh.random)
        bytes.append(UInt8(sh.legacySessionIDEcho.count))
        bytes.append(contentsOf: sh.legacySessionIDEcho)
        bytes.append(UInt8(truncatingIfNeeded: sh.cipherSuite.rawValue >> 8))
        bytes.append(UInt8(truncatingIfNeeded: sh.cipherSuite.rawValue))
        bytes.append(sh.legacyCompressionMethod)
        appendExtensionList(sh.extensions, to: &bytes)
        return bytes
    }

    private static func serializeEncryptedExtensions(
        _ ee: EncryptedExtensions
    ) -> [UInt8] {
        var bytes: [UInt8] = []
        appendExtensionList(ee.extensions, to: &bytes)
        return bytes
    }

    private static func serializeCertificateRequest(
        _ cr: CertificateRequest
    ) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(UInt8(cr.requestContext.count))
        bytes.append(contentsOf: cr.requestContext)
        appendExtensionList(cr.extensions, to: &bytes)
        return bytes
    }

    private static func serializeCertificateMessage(
        _ cm: CertificateMessage
    ) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(UInt8(cm.requestContext.count))
        bytes.append(contentsOf: cm.requestContext)
        var listBytes: [UInt8] = []
        for entry in cm.certificateList {
            let certLen = entry.certificateData.count
            listBytes.append(UInt8(truncatingIfNeeded: certLen >> 16))
            listBytes.append(UInt8(truncatingIfNeeded: certLen >> 8))
            listBytes.append(UInt8(truncatingIfNeeded: certLen))
            listBytes.append(contentsOf: entry.certificateData)
            appendExtensionList(entry.extensions, to: &listBytes)
        }
        let listLen = listBytes.count
        bytes.append(UInt8(truncatingIfNeeded: listLen >> 16))
        bytes.append(UInt8(truncatingIfNeeded: listLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: listLen))
        bytes.append(contentsOf: listBytes)
        return bytes
    }

    private static func serializeCertificateVerify(
        _ cv: CertificateVerify
    ) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.append(UInt8(truncatingIfNeeded: cv.algorithm.rawValue >> 8))
        bytes.append(UInt8(truncatingIfNeeded: cv.algorithm.rawValue))
        let sigLen = UInt16(cv.signature.count)
        bytes.append(UInt8(truncatingIfNeeded: sigLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: sigLen))
        bytes.append(contentsOf: cv.signature)
        return bytes
    }

    private static func serializeNewSessionTicket(
        _ nst: NewSessionTicket
    ) -> [UInt8] {
        var bytes: [UInt8] = []
        for shift in [24, 16, 8, 0] as [Int] {
            bytes.append(UInt8(truncatingIfNeeded: nst.ticketLifetime >> shift))
        }
        for shift in [24, 16, 8, 0] as [Int] {
            bytes.append(UInt8(truncatingIfNeeded: nst.ticketAgeAdd >> shift))
        }
        bytes.append(UInt8(nst.ticketNonce.count))
        bytes.append(contentsOf: nst.ticketNonce)
        let ticketLen = UInt16(nst.ticket.count)
        bytes.append(UInt8(truncatingIfNeeded: ticketLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: ticketLen))
        bytes.append(contentsOf: nst.ticket)
        appendExtensionList(nst.extensions, to: &bytes)
        return bytes
    }

    private static func appendExtensionList(
        _ extensions: [TLSExtension],
        to bytes: inout [UInt8]
    ) {
        var extBytes: [UInt8] = []
        for ext in extensions {
            extBytes.append(UInt8(truncatingIfNeeded: ext.type.rawValue >> 8))
            extBytes.append(UInt8(truncatingIfNeeded: ext.type.rawValue))
            let dataLen = UInt16(ext.data.count)
            extBytes.append(UInt8(truncatingIfNeeded: dataLen >> 8))
            extBytes.append(UInt8(truncatingIfNeeded: dataLen))
            extBytes.append(contentsOf: ext.data)
        }
        let listLen = UInt16(extBytes.count)
        bytes.append(UInt8(truncatingIfNeeded: listLen >> 8))
        bytes.append(UInt8(truncatingIfNeeded: listLen))
        bytes.append(contentsOf: extBytes)
    }
}
