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
import Testing
@testable import SwiftTLSStateMachine

@Suite
struct TLSConnectionStateMachineTests {
    private func makeProtection() -> (read: TLSRecordProtection, write: TLSRecordProtection) {
        let readSecret = SymmetricKey(data: [UInt8](repeating: 0x01, count: 32))
        let writeSecret = SymmetricKey(data: [UInt8](repeating: 0x02, count: 32))
        return (
            TLSRecordProtection(trafficSecret: readSecret, cipherSuite: .TLS_AES_128_GCM_SHA256),
            TLSRecordProtection(trafficSecret: writeSecret, cipherSuite: .TLS_AES_128_GCM_SHA256)
        )
    }

    private func makeStateMachine() -> TLSConnectionStateMachine {
        let (read, write) = makeProtection()
        return TLSConnectionStateMachine(
            readProtection: read,
            writeProtection: write,
            cipherSuite: .TLS_AES_128_GCM_SHA256,
            negotiatedALPN: "h2"
        )
    }

    // MARK: - Init and queries

    @Test func initCreatesActiveState() {
        let sm = makeStateMachine()
        assert(sm.isActive())
        assert(sm.alpnProtocol() == "h2")
    }

    @Test func initWithNoALPN() {
        let (read, write) = makeProtection()
        let sm = TLSConnectionStateMachine(
            readProtection: read,
            writeProtection: write,
            cipherSuite: .TLS_AES_128_GCM_SHA256,
            negotiatedALPN: nil
        )
        assert(sm.alpnProtocol() == nil)
    }

    // MARK: - recordReceived with encrypted records

    @Test func receiveApplicationDataRecord() throws {
        var sm = makeStateMachine()
        let readSecret = SymmetricKey(data: [UInt8](repeating: 0x01, count: 32))
        let readProtection = TLSRecordProtection(
            trafficSecret: readSecret, cipherSuite: .TLS_AES_128_GCM_SHA256
        )
        let plaintext = Array("hello".utf8)
        let fragmentLength = plaintext.count + 1 + 16
        var fragment = [UInt8](repeating: 0, count: fragmentLength)
        for i in 0..<plaintext.count { fragment[i] = plaintext[i] }
        try fragment.withUnsafeMutableBufferPointer { buf in
            var span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            _ = try readProtection.encrypt(
                buffer: &span,
                plaintextLength: plaintext.count,
                contentType: .applicationData,
                sequenceNumber: 0
            )
        }

        fragment.withUnsafeMutableBufferPointer { buf in
            let span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            var view = EncryptedTLSRecordView(
                contentType: .applicationData,
                version: .tlsv12,
                fragment: span
            )
            let action = sm.recordReceived(&view)
            guard case .applicationData(let decrypted) = action else {
                Issue.record("Expected .applicationData")
                return
            }
            #expect(decrypted.plaintext.count == 5)
            #expect(decrypted.contentType == .applicationData)
            var plaintext = [UInt8](repeating: 0, count: decrypted.plaintext.count)
            for i in 0..<decrypted.plaintext.count { plaintext[i] = decrypted.plaintext[i] }
            #expect(plaintext == Array("hello".utf8))
        }
    }

    @Test func receiveCCSRecordIsDiscarded() {
        var sm = makeStateMachine()
        var fragment: [UInt8] = [1]
        fragment.withUnsafeMutableBufferPointer { buf in
            let span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            var view = EncryptedTLSRecordView(
                contentType: .changeCipherSpec,
                version: .tlsv12,
                fragment: span
            )
            let action = sm.recordReceived(&view)
            guard case .discardChangeCipherSpec = action else {
                Issue.record("Expected .discardChangeCipherSpec")
                return
            }
        }
        assert(sm.isActive())
    }

    @Test func receiveUnexpectedContentType() {
        var sm = makeStateMachine()
        var fragment: [UInt8] = [0x01, 0x00, 0x00, 0x00]
        fragment.withUnsafeMutableBufferPointer { buf in
            let span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            var view = EncryptedTLSRecordView(
                contentType: .handshake,
                version: .tlsv12,
                fragment: span
            )
            let action = sm.recordReceived(&view)
            guard case .error(.unexpectedContentType) = action else {
                Issue.record("Expected .error(.unexpectedContentType)")
                return
            }
        }
    }

    // MARK: - encryptApplicationData

    @Test func encryptProducesRecord() {
        var sm = makeStateMachine()
        let plaintext = Array("hello".utf8)
        var outputBuf = [UInt8](repeating: 0, count: 4096)
        outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            plaintext.withUnsafeBufferPointer { ptBuf in
                let action = sm.encryptApplicationData(
                    Span(_unsafeElements: ptBuf), output: &output
                )
                guard case .ok = action else {
                    Issue.record("Expected .ok"); return
                }
            }
            #expect(output.count > 0)
        }
    }

    @Test func encryptIncrementsSequenceNumber() {
        var sm = makeStateMachine()
        var outputBuf = [UInt8](repeating: 0, count: 8192)
        outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            let first = Array("first".utf8)
            first.withUnsafeBufferPointer { ptBuf in
                guard case .ok = sm.encryptApplicationData(
                    Span(_unsafeElements: ptBuf), output: &output
                ) else {
                    Issue.record("Expected .ok"); return
                }
            }
            let second = Array("second".utf8)
            second.withUnsafeBufferPointer { ptBuf in
                guard case .ok = sm.encryptApplicationData(
                    Span(_unsafeElements: ptBuf), output: &output
                ) else {
                    Issue.record("Expected .ok"); return
                }
            }
            #expect(output.count > 0)
        }
    }

    // MARK: - sendCloseNotify

    @Test func sendCloseNotifyFromActive() {
        var sm = makeStateMachine()
        var outputBuf = [UInt8](repeating: 0, count: 4096)
        outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            let action = sm.sendCloseNotify(output: &output)
            guard case .ok = action else {
                Issue.record("Expected .ok"); return
            }
            #expect(output.count > 0)
        }
        assert(!sm.isActive())
    }

    @Test func sendCloseNotifyTwice() {
        var sm = makeStateMachine()
        var outputBuf = [UInt8](repeating: 0, count: 4096)
        outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            _ = sm.sendCloseNotify(output: &output)
            let action = sm.sendCloseNotify(output: &output)
            guard case .alreadyClosed = action else {
                Issue.record("Expected .alreadyClosed"); return
            }
        }
    }

    // MARK: - Closed state

    @Test func readAfterClosedFails() {
        var sm = makeStateMachine()
        var outputBuf = [UInt8](repeating: 0, count: 4096)
        outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            _ = sm.sendCloseNotify(output: &output)
        }
        var fragment: [UInt8] = [0]
        fragment.withUnsafeMutableBufferPointer { buf in
            let span = MutableSpan<UInt8>(_unsafeStart: buf.baseAddress!, count: buf.count)
            var view = EncryptedTLSRecordView(
                contentType: .applicationData,
                version: .tlsv12,
                fragment: span
            )
            let action = sm.recordReceived(&view)
            guard case .error(.connectionClosed) = action else {
                Issue.record("Expected .error(.connectionClosed)")
                return
            }
        }
    }

    @Test func alpnAfterClosed() {
        var sm = makeStateMachine()
        var outputBuf = [UInt8](repeating: 0, count: 4096)
        outputBuf.withUnsafeMutableBufferPointer { buf in
            var output = OutputSpan<UInt8>(buffer: buf, initializedCount: 0)
            _ = sm.sendCloseNotify(output: &output)
        }
        assert(sm.alpnProtocol() == nil)
    }
}
