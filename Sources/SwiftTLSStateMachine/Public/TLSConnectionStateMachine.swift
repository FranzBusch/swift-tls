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

import Crypto

/// Manages the post-handshake application data phase of a TLS 1.3 connection.
///
/// Wraps independent ``TLSReadStateMachine`` and ``TLSWriteStateMachine``
/// for use when both halves are owned by a single connection (unsplit).
/// For split usage, extract the individual state machines via
/// ``TLSApplicationStateMachines/takeReadStateMachine()`` and
/// ``TLSApplicationStateMachines/takeWriteStateMachine()`` instead.
public struct TLSConnectionStateMachine: ~Copyable {
    private var _read: Optional<TLSReadStateMachine>
    private var _write: Optional<TLSWriteStateMachine>
    private let _negotiatedALPN: String?

    /// Creates a connection state machine in the idle state (pre-handshake).
    public init() {
        self._read = nil
        self._write = nil
        self._negotiatedALPN = nil
    }

    /// Creates a connection state machine after a successful handshake.
    init(
        readProtection: TLSRecordProtection,
        writeProtection: TLSRecordProtection,
        cipherSuite: CipherSuite,
        negotiatedALPN: String?
    ) {
        self._read = TLSReadStateMachine(protection: readProtection)
        self._write = TLSWriteStateMachine(protection: writeProtection)
        self._negotiatedALPN = negotiatedALPN
    }

    /// Creates a connection state machine from pre-built application state machines.
    public init(consuming appState: inout TLSApplicationStateMachines) {
        self._read = appState.takeReadStateMachine()
        self._write = appState.takeWriteStateMachine()
        self._negotiatedALPN = appState.negotiatedALPN
    }

    // MARK: - recordReceived

    /// Processes a received TLS record, decrypting in-place.
    @_lifetime(&record)
    public mutating func recordReceived(
        _ record: inout EncryptedTLSRecordView
    ) -> RecordReceivedAction {
        guard var read = _read.take() else {
            return .error(.connectionClosed)
        }
        let action = read.recordReceived(&record)
        _read = consume read
        switch consume action {
        case .applicationData(let decrypted):
            return .applicationData(decrypted)
        case .postHandshakeMessage:
            return .postHandshakeMessage
        case .closeNotifyReceived:
            _read = nil
            return .closeNotifyReceived
        case .discardChangeCipherSpec:
            return .discardChangeCipherSpec
        case .error(let e):
            return .error(e)
        }
    }

    public enum RecordReceivedAction: ~Copyable, ~Escapable {
        case applicationData(DecryptedTLSRecordView)
        case postHandshakeMessage
        case closeNotifyReceived
        case alertReceived
        case discardChangeCipherSpec
        case error(TLSConnectionError)
    }

    // MARK: - encryptApplicationData

    /// Encrypts application data and writes the TLS record into the output.
//    public mutating func encryptApplicationData(
//        _ plaintext: borrowing Span<UInt8>,
//        output: inout OutputSpan<UInt8>
//    ) -> EncryptAction {
//        guard var write = _write.take() else {
//            return .error(.connectionClosed)
//        }
//        let action = write.encryptApplicationData(plaintext, output: &output)
//        _write = consume write
//        switch action {
//        case .ok:
//            return .ok
//        case .error(let e):
//            return .error(e)
//        }
//    }

    public enum EncryptAction: ~Copyable {
        case ok
        case error(TLSConnectionError)
    }

    // MARK: - sendCloseNotify

    /// Encrypts a close_notify alert and writes the TLS record into the output.
    public mutating func sendCloseNotify(
        output: inout OutputSpan<UInt8>
    ) -> CloseNotifyAction {
        guard var write = _write.take() else {
            return .alreadyClosed
        }
        let action = write.sendCloseNotify(output: &output)
        switch action {
        case .ok:
            _read = nil
            return .ok
        case .alreadyClosed:
            _write = consume write
            return .alreadyClosed
        }
    }

    public enum CloseNotifyAction: ~Copyable {
        case ok
        case alreadyClosed
    }

    // MARK: - Queries

    public borrowing func alpnProtocol() -> String? {
        guard _read != nil else { return nil }
        return _negotiatedALPN
    }

    public borrowing func isActive() -> Bool {
        _read != nil && _write != nil
    }
}

// MARK: - Error

public enum TLSConnectionError: Error, Sendable {
    case connectionClosed
    case unexpectedContentType
    case decryptionFailed
    case encryptionFailed
}
