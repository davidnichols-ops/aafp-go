# AAFP-Go: Independent Second Implementation

An independent implementation of the AAFP v1 protocol in Go, written
strictly from the RFC specifications (RFC-0001 through RFC-0006) without
referencing the Rust reference implementation's source code.

## Purpose

This implementation serves as a cross-validation artifact for Phase 3
of the AAFP protocol reference implementation. By building a second
implementation from the RFCs alone and verifying it produces
byte-for-byte identical wire format to the Rust implementation, we
validate that:

1. The RFCs are unambiguous enough to implement from
2. The canonical CBOR encoding rules are well-specified
3. The frame format is correctly documented
4. The handshake structures produce deterministic output

## Structure

```
aafp-go/
  go.mod                  — Go module definition
  cbor/cbor.go            — Canonical CBOR encoder/decoder (RFC 8949 §4.2.3)
  frame/frame.go          — AAFP frame format (RFC-0002 §3-4)
  errors/errors.go        — Error code registry (RFC-0005)
  identity/identity.go    — AgentId, AgentRecord, CapabilityDescriptor (RFC-0003)
  handshake/handshake.go  — ClientHello/ServerHello/ClientFinished, transcript hash, session ID (RFC-0002 §5)
  testvectors/            — Test vector verification (48 tests, all passing)
```

## Test Vector Verification

The `testvectors` package contains 48 tests that verify byte-for-byte
compatibility with the published AAFP test vectors (TEST_VECTORS.md).
These cover:

- **CBOR canonical encoding** (16 tests): unsigned/negative integers,
  booleans, null, byte/text strings, arrays, int/string maps with
  length-first canonical key ordering
- **Frame wire format** (6 tests): DATA, HANDSHAKE, RPC_REQUEST, PING
  frames with various stream IDs and flags
- **Handshake structures** (4 tests): ClientHello, ServerHello,
  ClientFinished without signatures, transcript hash initialization
- **AgentRecord** (3 tests): AgentId derivation, record with
  capabilities/endpoints, record with empty arrays
- **RPC messages** (5 tests): request/response/error/close/error_message
- **Discovery** (3 tests): lookup params, announce params with nested
  AgentRecord, announce result
- **Round-trip** (2 tests): CBOR and frame encode→decode cycles
- **Negative tests** (5 tests): oversized payload, length overflow,
  bad version, truncated CBOR, huge array
- **Error codes** (1 test): always-fatal code classification
- **Session ID** (1 test): deterministic HKDF derivation

## Running

```bash
cd aafp-go
go test ./... -v
```

All 48 tests pass.

## Security Features

- **Integer overflow protection**: Frame decoder uses checked addition
  for `ext_len + payload_len` and `header_size + total_body`
- **OOM protection**: CBOR decoder validates array/map lengths against
  available data before allocation
- **Truncation detection**: Byte/text string lengths checked against
  remaining data
- **Max frame size**: 1 MiB limit enforced on encode and decode

## What's NOT Implemented

This is a minimal implementation focused on wire-format compatibility.
The following are out of scope:

- QUIC transport (the frame format is transport-agnostic)
- ML-DSA-65 signature operations (signature verification is injected
  via a callback function)
- Actual handshake state machine
- Discovery DHT
- RPC method dispatch
- UCAN authorization

These can be added later; the wire-format layer is the foundation.
