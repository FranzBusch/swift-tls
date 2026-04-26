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

import BinaryParsing
import BinarySerialization

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *)
func serializeToBytes<T: SerializableToBytes>(
    _ value: borrowing T,
    outputSpanCapacity: Int = 256
) throws -> [UInt8] {
    var state = try T.startSerialization(of: value)
    var result: [UInt8] = []
    while true {
        var done = false
        let chunk = Array<UInt8>(capacity: outputSpanCapacity) { output in
            done = T.serialize(state: &state, into: &output)
        }
        result.append(contentsOf: chunk)
        if done { break }
    }
    return result
}
