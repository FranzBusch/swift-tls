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

/// Manages encryption of outgoing TLS 1.3 application data records.
///
/// Owns the write traffic key and sequence number. Independent of the read
/// side — no shared mutable state. Follows SBP-008: pure state machine.
public struct TLSWriteStateMachine: ~Copyable {
    var protection: TLSRecordProtection
    var sequenceNumber: UInt64
    private var closed: Bool

    init(protection: TLSRecordProtection) {
        self.protection = protection
        self.sequenceNumber = 0
        self.closed = false
    }

    public mutating func encryptApplicationData(
        buffer: inout MutableSpan<UInt8>
    ) -> EncryptAction {
        guard !closed else {
            return .error(.connectionClosed)
        }

        do {
            _ = try protection.encrypt2(
                buffer: &buffer,
                contentType: .applicationData,
                sequenceNumber: sequenceNumber
            )
            sequenceNumber += 1
            return .ok
        } catch {
            return .error(.encryptionFailed)
        }
    }

    public enum EncryptAction: ~Copyable {
        case ok
        case error(TLSConnectionError)
    }

    /// Encrypts a close_notify alert and writes the TLS record into the output.
    ///
    /// Transitions to closed state. Subsequent encrypt calls return an error.
    public mutating func sendCloseNotify(
        output: inout OutputSpan<UInt8>
    ) -> CloseNotifyAction {
        guard !closed else {
            return .alreadyClosed
        }

        do {
            let alertPlaintext: [UInt8] = [1, 0]
            try alertPlaintext.withUnsafeBufferPointer { buf in
                try Self.writeEncryptedRecord(
                    plaintext: Span(_unsafeElements: buf),
                    contentType: .alert,
                    protection: protection,
                    sequenceNumber: sequenceNumber,
                    output: &output
                )
            }
            closed = true
            return .ok
        } catch {
            closed = true
            return .alreadyClosed
        }
    }

    // TODO: sendKeyUpdate — RFC 8446 §4.6.3
    // When implemented, this method will:
    // 1. Send a KeyUpdate message (update_not_requested) as a handshake record
    // 2. Derive the next write traffic secret from the current one
    // 3. Update protection and reset sequenceNumber to 0
    // Called when signaled by the read side that peer sent KeyUpdate(update_requested).

    public enum CloseNotifyAction: ~Copyable {
        case ok
        case alreadyClosed
    }

    // MARK: - Encrypt helper

    private static func writeEncryptedRecord(
        plaintext: borrowing Span<UInt8>,
        contentType: ContentType,
        protection: TLSRecordProtection,
        sequenceNumber: UInt64,
        output: inout OutputSpan<UInt8>
    ) throws {
        let plaintextLength = plaintext.count
        let fragmentLength = plaintextLength + 1 + 16

        output.append(ContentType.applicationData.rawValue)
        output.append(0x03)
        output.append(0x03)
        output.append(UInt8(truncatingIfNeeded: fragmentLength >> 8))
        output.append(UInt8(truncatingIfNeeded: fragmentLength))

        let fragmentStart = output.count
        for i in 0..<plaintextLength {
            output.append(plaintext[i])
        }
        for _ in 0..<17 {
            output.append(0)
        }

        var mspan = output.mutableSpan
        var fragmentSpan = mspan._mutatingExtracting(
            fragmentStart..<(fragmentStart + fragmentLength)
        )
        _ = try protection.encrypt(
            buffer: &fragmentSpan,
            plaintextLength: plaintextLength,
            contentType: contentType,
            sequenceNumber: sequenceNumber
        )
    }
}
