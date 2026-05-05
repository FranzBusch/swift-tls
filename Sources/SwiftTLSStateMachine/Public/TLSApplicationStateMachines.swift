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

/// Holds the independent read and write state machines produced by a
/// successful TLS 1.3 handshake.
///
/// Since both state machines are `~Copyable`, this wrapper provides
/// ``takeReadStateMachine()`` and ``takeWriteStateMachine()`` to extract
/// each side independently without consuming the whole value at once.
public struct TLSApplicationStateMachines: ~Copyable {
    private var _read: Optional<TLSReadStateMachine>
    private var _write: Optional<TLSWriteStateMachine>

    /// The ALPN protocol negotiated during the handshake, or `nil` if none.
    public let negotiatedALPN: String?

    init(
        read: consuming TLSReadStateMachine,
        write: consuming TLSWriteStateMachine,
        negotiatedALPN: String?
    ) {
        self._read = consume read
        self._write = consume write
        self.negotiatedALPN = negotiatedALPN
    }

    /// Extracts the read state machine. Can only be called once.
    public mutating func takeReadStateMachine() -> TLSReadStateMachine {
        _read.take()!
    }

    /// Extracts the write state machine. Can only be called once.
    public mutating func takeWriteStateMachine() -> TLSWriteStateMachine {
        _write.take()!
    }
}
