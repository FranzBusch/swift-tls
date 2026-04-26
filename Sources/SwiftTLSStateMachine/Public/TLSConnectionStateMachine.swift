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
/// Created after the handshake completes with the negotiated keys. Handles
/// record decryption dispatch, sequence number management, and close_notify
/// tracking. Follows SBP-008: pure state machine with no I/O.
public struct TLSConnectionStateMachine: ~Copyable {
    private var state: State

    private init(state: consuming State) {
        self.state = state
    }

    /// Creates a connection state machine in the idle state (pre-handshake).
    public init() {
        self.state = .idle
    }

    /// Creates a connection state machine after a successful handshake.
    init(
        readProtection: TLSRecordProtection,
        writeProtection: TLSRecordProtection,
        cipherSuite: CipherSuite,
        negotiatedALPN: String?
    ) {
        self.state = .active(ActiveState(
            readProtection: readProtection,
            writeProtection: writeProtection,
            readSequenceNumber: 0,
            writeSequenceNumber: 0,
            cipherSuite: cipherSuite,
            negotiatedALPN: negotiatedALPN
        ))
    }

    // MARK: - activate

    /// Activates the connection after a successful handshake.
    mutating func activate(
        readProtection: TLSRecordProtection,
        writeProtection: TLSRecordProtection,
        cipherSuite: CipherSuite,
        negotiatedALPN: String?
    ) {
        self.state = .active(ActiveState(
            readProtection: readProtection,
            writeProtection: writeProtection,
            readSequenceNumber: 0,
            writeSequenceNumber: 0,
            cipherSuite: cipherSuite,
            negotiatedALPN: negotiatedALPN
        ))
    }

    // MARK: - recordReceived

    /// Processes a received TLS record, decrypting in-place.
    ///
    /// Uses ``TLSRecordProtection/decrypt(record:sequenceNumber:)`` for
    /// in-place decryption. The returned action carries a
    /// ``DecryptedTLSRecordView`` for application data, or signals
    /// close_notify / post-handshake messages.
    @_lifetime(&record)
    public mutating func recordReceived(
        _ record: inout EncryptedTLSRecordView
    ) -> RecordReceivedAction {
        switch consume self.state {
        case .idle:
            self = Self(state: .error)
            return .error(.connectionClosed)

        case .active(var s):
            if record.contentType == .changeCipherSpec {
                self = Self(state: .active(s))
                return .discardChangeCipherSpec
            }
            guard record.contentType == .applicationData else {
                self = Self(state: .error)
                return .error(.unexpectedContentType)
            }

            // TODO: We should handle the error here
            let decrypted = try! s.readProtection.decrypt(
                record: &record,
                sequenceNumber: s.readSequenceNumber
            )
            s.readSequenceNumber += 1

            let contentType = decrypted.contentType
            switch contentType {
            case .applicationData:
                self = Self(state: .active(s))
                return .applicationData(decrypted)

            case .handshake:
                self = Self(state: .active(s))
                return .postHandshakeMessage

            case .alert:
                if decrypted.plaintext.count >= 2
                    && decrypted.plaintext[0] == 1
                    && decrypted.plaintext[1] == 0
                {
                    self = Self(state: .closing(ClosingState(
                        writeProtection: s.writeProtection,
                        writeSequenceNumber: s.writeSequenceNumber,
                        cipherSuite: s.cipherSuite,
                        negotiatedALPN: s.negotiatedALPN
                    )))
                    return .closeNotifyReceived
                }
                self = Self(state: .error)
                return .alertReceived

            default:
                self = Self(state: .error)
                return .error(.unexpectedContentType)
            }

        case .closing(let s):
            self = Self(state: .closing(s))
            return .error(.connectionClosed)

        case .closed:
            self = Self(state: .closed)
            return .error(.connectionClosed)

        case .error:
            self = Self(state: .error)
            return .error(.connectionClosed)
        }
    }

    public enum RecordReceivedAction: ~Copyable, ~Escapable {
        /// Application data decrypted. The ``DecryptedTLSRecordView``
        /// contains the plaintext span and inner content type.
        case applicationData(DecryptedTLSRecordView)
        /// Post-handshake message (e.g. NewSessionTicket) — skip.
        case postHandshakeMessage
        /// Peer sent close_notify.
        case closeNotifyReceived
        /// Peer sent a non-close_notify alert.
        case alertReceived
        /// ChangeCipherSpec record — discard.
        case discardChangeCipherSpec
        /// Error.
        case error(TLSConnectionError)
    }

    // MARK: - encryptApplicationData

    /// Encrypts application data and writes the TLS record into the output.
    public mutating func encryptApplicationData(
        _ plaintext: borrowing Span<UInt8>,
        output: inout OutputSpan<UInt8>
    ) -> EncryptAction {
        switch consume self.state {
        case .idle:
            self = Self(state: .error)
            return .error(.connectionClosed)

        case .active(var s):
            do {
                try Self.writeEncryptedRecord(
                    plaintext: plaintext,
                    contentType: .applicationData,
                    protection: s.writeProtection,
                    sequenceNumber: s.writeSequenceNumber,
                    output: &output
                )
                s.writeSequenceNumber += 1
                self = Self(state: .active(s))
                return .ok
            } catch {
                self = Self(state: .error)
                return .error(.encryptionFailed)
            }

        case .closing(let s):
            self = Self(state: .closing(s))
            return .error(.connectionClosed)

        case .closed:
            self = Self(state: .closed)
            return .error(.connectionClosed)

        case .error:
            self = Self(state: .error)
            return .error(.connectionClosed)
        }
    }

    public enum EncryptAction: ~Copyable {
        case ok
        case error(TLSConnectionError)
    }

    // MARK: - sendCloseNotify

    /// Encrypts a close_notify alert and writes the TLS record into the output.
    ///
    /// Transitions the connection to the closed state.
    public mutating func sendCloseNotify(
        output: inout OutputSpan<UInt8>
    ) -> CloseNotifyAction {
        switch consume self.state {
        case .idle:
            self = Self(state: .idle)
            return .alreadyClosed

        case .active(let s):
            do {
                let alertPlaintext: [UInt8] = [1, 0]
                try alertPlaintext.withUnsafeBufferPointer { buf in
                    try Self.writeEncryptedRecord(
                        plaintext: Span(_unsafeElements: buf),
                        contentType: .alert,
                        protection: s.writeProtection,
                        sequenceNumber: s.writeSequenceNumber,
                        output: &output
                    )
                }
                self = Self(state: .closed)
                return .ok
            } catch {
                self = Self(state: .closed)
                return .alreadyClosed
            }

        case .closing(let s):
            do {
                let alertPlaintext: [UInt8] = [1, 0]
                try alertPlaintext.withUnsafeBufferPointer { buf in
                    try Self.writeEncryptedRecord(
                        plaintext: Span(_unsafeElements: buf),
                        contentType: .alert,
                        protection: s.writeProtection,
                        sequenceNumber: s.writeSequenceNumber,
                        output: &output
                    )
                }
                self = Self(state: .closed)
                return .ok
            } catch {
                self = Self(state: .closed)
                return .alreadyClosed
            }

        case .closed:
            self = Self(state: .closed)
            return .alreadyClosed

        case .error:
            self = Self(state: .error)
            return .alreadyClosed
        }
    }

    public enum CloseNotifyAction: ~Copyable {
        case ok
        case alreadyClosed
    }
}

// MARK: - Encrypt helper

extension TLSConnectionStateMachine {
    /// Writes a complete encrypted TLS record (5-byte header + fragment)
    /// into the output span.
    private static func writeEncryptedRecord(
        plaintext: borrowing Span<UInt8>,
        contentType: ContentType,
        protection: TLSRecordProtection,
        sequenceNumber: UInt64,
        output: inout OutputSpan<UInt8>
    ) throws {
        let plaintextLength = plaintext.count
        let fragmentLength = plaintextLength + 1 + 16

        // Write record header
        output.append(ContentType.applicationData.rawValue)
        output.append(0x03)
        output.append(0x03)
        output.append(UInt8(truncatingIfNeeded: fragmentLength >> 8))
        output.append(UInt8(truncatingIfNeeded: fragmentLength))

        // Write plaintext into output, then encrypt in-place
        let fragmentStart = output.count
        for i in 0..<plaintextLength {
            output.append(plaintext[i])
        }
        // Reserve space for content type byte + tag
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

// MARK: - Queries

extension TLSConnectionStateMachine {
    public borrowing func alpnProtocol() -> String? {
        switch state {
        case .idle: nil
        case .active(let s): s.negotiatedALPN
        case .closing(let s): s.negotiatedALPN
        case .closed: nil
        case .error: nil
        }
    }

    public borrowing func isActive() -> Bool {
        switch state {
        case .active: true
        default: false
        }
    }
}

// MARK: - State

extension TLSConnectionStateMachine {
    private enum State: ~Copyable {
        case idle
        case active(ActiveState)
        case closing(ClosingState)
        case closed
        case error
    }

    private struct ActiveState: ~Copyable {
        var readProtection: TLSRecordProtection
        var writeProtection: TLSRecordProtection
        var readSequenceNumber: UInt64
        var writeSequenceNumber: UInt64
        let cipherSuite: CipherSuite
        let negotiatedALPN: String?
    }

    private struct ClosingState: ~Copyable {
        var writeProtection: TLSRecordProtection
        var writeSequenceNumber: UInt64
        let cipherSuite: CipherSuite
        let negotiatedALPN: String?
    }
}

// MARK: - Error

public enum TLSConnectionError: Error, Sendable {
    case connectionClosed
    case unexpectedContentType
    case decryptionFailed
    case encryptionFailed
}
