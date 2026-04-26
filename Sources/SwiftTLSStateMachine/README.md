# SwiftTLSStateMachine — Implementation Status

This module contains a clean-room TLS 1.3 state machine implementation
following the SBP-008 pattern. It is pure (no I/O), uses `ParserSpan`
for parsing and `SerializableToBytes` for serialization, and integrates
with `ParsingAsyncReader` / `SerializingAsyncWriter` from
swift-binary-parsing.

## What is implemented

### Protocol atoms
- ContentType, ProtocolVersion, HandshakeType, CipherSuite, NamedGroup,
  SignatureScheme, CertificateType, Alert, ExtensionType
- All conform to `ExpressibleByParsing` and `SerializableToBytes`

### TLS record layer
- `TLSRecord` — 5-byte header + variable fragment, parsing + serialization

### Handshake messages
- ClientHello, ServerHello, EncryptedExtensions, CertificateMessage,
  CertificateRequest, CertificateVerify, FinishedMessage, NewSessionTicket
- `HandshakeMessage` enum conforms to `ExpressibleByParsing` and
  `SerializableToBytes` (framed with 4-byte header: type + uint24 length)

### TLS extensions
- `TLSExtension` — opaque type + data with parsing/serialization
- Convenience constructors for: supported_versions, supported_groups,
  signature_algorithms, key_share (client + server), server_name, ALPN

### Key derivation
- `TLSKeyDerivation<HF>` — HKDF-Expand-Label, Derive-Secret, Extract,
  Finished verify data per RFC 8446 Section 7.1
- `TLSKeySchedule<HF>` — four-phase key schedule (early → handshake →
  master → complete)

### State machines (SBP-008)
- `ClientHandshakeStateMachine` — 7 states, 6 transition methods
- `ServerHandshakeStateMachine` — 8 states, 7 transition methods
- Both are `~Copyable` with `~Copyable` state enums, state structs,
  and action enums
- Pure: no I/O, no randomness, no serialization inside the state machine

## What is missing for a full TLS 1.3 implementation

### Cipher suite negotiation beyond P-256
- Only P-256 ECDHE key exchange is implemented
- Missing: X25519 key agreement (requires swift-crypto `Curve25519`)
- Missing: X25519MLKEM768 post-quantum hybrid
- Missing: P-384 ECDHE
- The state machines hardcode `P256.KeyAgreement`; need to abstract
  over key agreement algorithms based on negotiated group

### SHA-384 cipher suite support
- Key schedule is generic over `HashFunction` but the state machines
  hardcode `SHA256`
- `TLS_AES_256_GCM_SHA384` requires `SHA384` key schedule
- Need to select hash function based on negotiated cipher suite

### TLS record encryption/decryption
- No AEAD encryption (AES-GCM, ChaCha20-Poly1305)
- Missing: `TLSRecordProtector` that encrypts/decrypts record payloads
- Missing: nonce construction (per-record sequence number XOR with IV)
- Missing: record padding handling
- Missing: content type hiding (inner content type in encrypted records)

### Certificate verification
- `receiveCertificate` and `receiveCertificateVerify` accept the messages
  but do not verify the certificate chain or signature
- Missing: X.509 certificate chain validation
- Missing: CertificateVerify signature verification against the
  transcript hash (RFC 8446 Section 4.4.3)
- Missing: server name (SNI) validation against certificate SAN

### Finished message verification
- `receiveFinished` accepts the message but does not verify the
  verify_data HMAC against the expected value
- Need to compare received verify_data with computed
  `serverFinishedVerifyData` / `clientFinishedVerifyData`

### Pre-shared keys (PSK) and session resumption
- `TLSKeySchedule` supports PSK input but the state machines do not
  handle PSK negotiation
- Missing: pre_shared_key extension parsing and selection
- Missing: PSK binder verification
- Missing: 0-RTT / early data support
- Missing: NewSessionTicket processing for session resumption

### Hello Retry Request
- Missing: HelloRetryRequest handling (server requests different key
  share group)
- Missing: synthetic message_hash for transcript after HRR
- Missing: cookie extension

### Client certificate authentication
- Missing: server-side CertificateRequest generation with appropriate
  extensions
- Missing: client-side certificate selection and CertificateVerify
  generation in response to CertificateRequest

### Key update
- Missing: post-handshake KeyUpdate message handling
- Missing: application traffic secret rotation

### Extension parsing
- Extensions are stored as opaque `type + [UInt8]` data
- Missing: structured parsing of individual extension types into typed
  values (e.g., `SupportedVersions`, `KeyShareEntry`, `ServerNameList`)
- The convenience constructors build extensions but there are no
  corresponding typed parsers

### Alert handling
- `Alert` is a wire-format type but no logic maps `HandshakeError` to
  appropriate Alert values for sending to the peer
- Missing: alert generation on handshake failure
- Missing: close_notify exchange for graceful shutdown

### QUIC transport parameters
- Extension type is defined but no parsing or integration with QUIC

### Exporters
- `TLSKeySchedule` derives `exporterMasterSecret` but there is no
  public API for computing TLS exporters (RFC 8446 Section 7.5)

### Platform abstraction
- Hardcoded to swift-crypto; no CryptoKit abstraction for Darwin
- No SecureEnclave key support

## Test coverage

88 tests across 21 suites covering:
- Protocol atom parsing, serialization, round-trips, byte-boundary
  chunking
- TLS record parsing, serialization, round-trips, boundary tests
- Handshake message parsing and serialization round-trips for all 8
  message types
- Key derivation: length, determinism, PSK, SHA-384, full schedule
  progression
- Client state machine: start, extensions, full flow, wrong-state errors
- Server state machine: cipher selection, full flow, wrong-state errors
