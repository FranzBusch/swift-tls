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

/// Manages decryption of incoming TLS 1.3 application data records.
///
/// Owns the read traffic key and sequence number. Independent of the write
/// side — no shared mutable state. Follows SBP-008: pure state machine.
public struct TLSReadStateMachine: ~Copyable {
    var protection: TLSRecordProtection
    var sequenceNumber: UInt64
    private var closed: Bool

    init(protection: TLSRecordProtection) {
        self.protection = protection
        self.sequenceNumber = 0
        self.closed = false
    }

    /// Processes a received TLS record, decrypting in-place.
    @_lifetime(&record)
    public mutating func recordReceived(
        _ record: inout EncryptedTLSRecordView
    ) -> ReadAction {
        guard !closed else {
            return .error(.connectionClosed)
        }

        if record.contentType == .changeCipherSpec {
            return .discardChangeCipherSpec
        }
        guard record.contentType == .applicationData else {
            return .error(.unexpectedContentType)
        }

        // TODO: Handle decryption errors properly instead of using try!
        let decrypted = try! protection.decrypt(
            record: &record,
            sequenceNumber: sequenceNumber
        )
        sequenceNumber += 1

        let contentType = decrypted.contentType
        switch contentType {
        case .applicationData:
            return .applicationData(decrypted)

        case .handshake:
            // TODO: Handle KeyUpdate (RFC 8446 §4.6.3) — when implemented,
            // return .keyUpdateReceived(updateRequested:) so the caller can
            // signal the write side to respond.
            return .postHandshakeMessage

        case .alert:
            let isCloseNotify = decrypted.plaintext.count >= 2
                && decrypted.plaintext[0] == 1
                && decrypted.plaintext[1] == 0
            if isCloseNotify {
                closed = true
                return .closeNotifyReceived
            }
            return .error(.unexpectedContentType)

        default:
            return .error(.unexpectedContentType)
        }
    }

    public enum ReadAction: ~Copyable, ~Escapable {
        case applicationData(DecryptedTLSRecordView)
        case postHandshakeMessage
        case closeNotifyReceived
        case discardChangeCipherSpec
        case error(TLSConnectionError)
    }
}
