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

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension Array where Element == UInt8 {
    /// Creates an array by copying the bytes of the given raw span.
    ///
    /// The span must contain exactly `count` bytes.
    init(copying bytes: RawSpan) {
        self.init(capacity: bytes.byteCount) { output in
            output.append(contentsOf: bytes)
        }
    }

    /// Splits this array's storage at `index`, yielding the prefix as a
    /// `MutableRawSpan` to be updated in place and the suffix as an
    /// `OutputRawSpan` to be written into.
    ///
    /// Two disjoint mutable views into one allocation can't be expressed with
    /// the safe span APIs, so this is deliberately the only place in the record
    /// layer that reaches for pointers.
    ///
    /// The suffix is already-initialized storage, but `OutputRawSpan` can only
    /// model it as empty free capacity, so it is presented with an initialized
    /// count of zero. `body` must therefore write the suffix in full.
    mutating func withUnsafeMutableOutputSplit(
        at index: Int,
        _ body: (inout MutableRawSpan, inout OutputRawSpan) throws -> Void
    ) rethrows {
        precondition(index >= 0 && index <= self.count)
        try self.withUnsafeMutableBytes { buffer in
            let prefix = UnsafeMutableRawBufferPointer(rebasing: buffer[..<index])
            let suffix = UnsafeMutableRawBufferPointer(rebasing: buffer[index...])
            var prefixSpan = prefix.mutableBytes
            var suffixSpan = OutputRawSpan(buffer: suffix, initializedCount: 0)
            try body(&prefixSpan, &suffixSpan)
            let written = suffixSpan.finalize(for: suffix)
            precondition(
                written == suffix.count,
                "output span left \(suffix.count - written) of \(suffix.count) bytes unwritten"
            )
        }
    }
}

// Availability due to `Swift`'s `InlineArray`
@available(SwiftTLS 0.1.0, *)
extension InlineArray where Element == UInt8 {
    /// Creates an inline array by copying the bytes of the given raw span.
    ///
    /// The span must contain exactly `count` bytes.
    init(copying bytes: RawSpan) {
        precondition(count == bytes.byteCount)
        self.init { outputSpan in
            for i in 0..<count {
                outputSpan.append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
            }
        }
    }
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension Hasher {
    mutating func combine(bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.combine(bytes: buffer)
        }
    }
}

// Availability due to `Swift`'s `InlineArray`
@available(SwiftTLS 0.1.0, *)
extension InlineArray where Element: Equatable {
    static func ==(lhs: Self, rhs: Self) -> Bool {
        for i in lhs.indices {
            if lhs[i] != rhs[i] {
                return false
            }
        }

        return true
    }
}

// Availability due to `Swift`'s `OutputRawSpan`
@available(SwiftTLS 0.1.0, *)
extension OutputRawSpan {
    /// Appends the contents of the given raw span to this output span.
    mutating func append(contentsOf bytes: RawSpan) {
        for i in 0..<bytes.byteCount {
            append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
        }
    }
}

// Availability due to `Swift`'s `OutputSpan`
@available(SwiftTLS 0.1.0, *)
extension OutputSpan where Element == UInt8 {
    /// Appends the contents of the given raw span to this output span.
    mutating func append(contentsOf bytes: RawSpan) {
        for i in 0..<bytes.byteCount {
            append(bytes.unsafeLoad(fromByteOffset: i, as: UInt8.self))
        }
    }
}

// Availability due to `RawSpan`
@available(SwiftTLS 0.1.0, *)
extension RawSpan {
    subscript(index: Int) -> UInt8 {
        unsafeLoad(fromByteOffset: index, as: UInt8.self)
    }
}
