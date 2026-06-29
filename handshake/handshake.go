// Package handshake implements AAFP handshake structures per RFC-0002 §5.
//
// This includes:
//   - ClientHello, ServerHello, ClientFinished CBOR structures
//   - Transcript hash computation (SHA-256 chain)
//   - Session ID derivation (HKDF-SHA256)
//   - Signature input construction
//
// This implementation is written from the RFC specification alone.
package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"aafp-go/cbor"
)

const (
	domainSeparator = "aafp-v1-handshake"
	sessionInfoStr  = "aafp-session-id-v1"
	dosMacInfoStr   = "aafp-v1-dos-mac-key"
)

// ExtensionEntry represents a handshake extension per RFC-0002 §6.4.
type ExtensionEntry struct {
	Type      uint64
	Data      []byte
	Critical  bool
}

func (e *ExtensionEntry) ToCBOR() cbor.Value {
	return cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(e.Type)},
		{Key: 2, Value: cbor.BStr(e.Data)},
		{Key: 3, Value: cbor.Bool(e.Critical)},
	})
}

func ExtensionFromCBOR(v *cbor.Value) (*ExtensionEntry, error) {
	if v.Kind() != cbor.KindIntMap {
		return nil, errors.New("extension: expected int map")
	}
	e := &ExtensionEntry{}
	if val := v.IntMapGet(1); val != nil && val.Kind() == cbor.KindUnsigned {
		e.Type = val.Uint()
	}
	if val := v.IntMapGet(2); val != nil && val.Kind() == cbor.KindByteString {
		e.Data = val.Bytes()
	}
	if val := v.IntMapGet(3); val != nil && val.Kind() == cbor.KindBool {
		e.Critical = val.BoolVal()
	}
	return e, nil
}

// ClientHello represents a ClientHello message per RFC-0002 §5.3.
type ClientHello struct {
	ProtocolVersion uint64
	AgentId         []byte
	PublicKey       []byte
	Nonce           []byte
	Capabilities    []cbor.Value // array of CapabilityDescriptor
	Extensions      []ExtensionEntry
	Signature       []byte
	ExpiresAt       uint64
	ReceiverMac     []byte // nil if not using DoS profile
	KeyAlgorithm    uint64
}

// ToCBORWithoutSigAndMac encodes ClientHello excluding signature (key 7)
// and receiver_mac (key 9). This is the transcript hash input per §5.6.
func (ch *ClientHello) ToCBORWithoutSigAndMac() cbor.Value {
	entries := []cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(ch.ProtocolVersion)},
		{Key: 2, Value: cbor.BStr(ch.AgentId)},
		{Key: 3, Value: cbor.BStr(ch.PublicKey)},
		{Key: 4, Value: cbor.BStr(ch.Nonce)},
		{Key: 5, Value: cbor.Arr(ch.Capabilities)},
	}
	extArr := make([]cbor.Value, len(ch.Extensions))
	for i, e := range ch.Extensions {
		extArr[i] = e.ToCBOR()
	}
	entries = append(entries, cbor.IntMapEntry{Key: 6, Value: cbor.Arr(extArr)})
	// Key 7 (signature) excluded
	entries = append(entries, cbor.IntMapEntry{Key: 8, Value: cbor.UUint(ch.ExpiresAt)})
	// Key 9 (receiver_mac) excluded
	entries = append(entries, cbor.IntMapEntry{Key: 10, Value: cbor.UUint(ch.KeyAlgorithm)})
	return cbor.IMap(entries)
}

// ToCBOR encodes the full ClientHello including signature and receiver_mac.
func (ch *ClientHello) ToCBOR() cbor.Value {
	entries := []cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(ch.ProtocolVersion)},
		{Key: 2, Value: cbor.BStr(ch.AgentId)},
		{Key: 3, Value: cbor.BStr(ch.PublicKey)},
		{Key: 4, Value: cbor.BStr(ch.Nonce)},
		{Key: 5, Value: cbor.Arr(ch.Capabilities)},
	}
	extArr := make([]cbor.Value, len(ch.Extensions))
	for i, e := range ch.Extensions {
		extArr[i] = e.ToCBOR()
	}
	entries = append(entries, cbor.IntMapEntry{Key: 6, Value: cbor.Arr(extArr)})
	entries = append(entries, cbor.IntMapEntry{Key: 7, Value: cbor.BStr(ch.Signature)})
	entries = append(entries, cbor.IntMapEntry{Key: 8, Value: cbor.UUint(ch.ExpiresAt)})
	if ch.ReceiverMac != nil {
		entries = append(entries, cbor.IntMapEntry{Key: 9, Value: cbor.BStr(ch.ReceiverMac)})
	} else {
		entries = append(entries, cbor.IntMapEntry{Key: 9, Value: cbor.Null()})
	}
	entries = append(entries, cbor.IntMapEntry{Key: 10, Value: cbor.UUint(ch.KeyAlgorithm)})
	return cbor.IMap(entries)
}

// ClientHelloFromCBOR decodes a ClientHello from CBOR.
func ClientHelloFromCBOR(v *cbor.Value) (*ClientHello, error) {
	if v.Kind() != cbor.KindIntMap {
		return nil, errors.New("ClientHello: expected int map")
	}
	ch := &ClientHello{}
	if val := v.IntMapGet(1); val != nil && val.Kind() == cbor.KindUnsigned {
		ch.ProtocolVersion = val.Uint()
	}
	if val := v.IntMapGet(2); val != nil && val.Kind() == cbor.KindByteString {
		ch.AgentId = val.Bytes()
	}
	if val := v.IntMapGet(3); val != nil && val.Kind() == cbor.KindByteString {
		ch.PublicKey = val.Bytes()
	}
	if val := v.IntMapGet(4); val != nil && val.Kind() == cbor.KindByteString {
		ch.Nonce = val.Bytes()
	}
	if val := v.IntMapGet(5); val != nil && val.Kind() == cbor.KindArray {
		ch.Capabilities = val.Arr()
	}
	if val := v.IntMapGet(6); val != nil && val.Kind() == cbor.KindArray {
		for _, eVal := range val.Arr() {
			e, err := ExtensionFromCBOR(&eVal)
			if err != nil {
				return nil, err
			}
			ch.Extensions = append(ch.Extensions, *e)
		}
	}
	if val := v.IntMapGet(7); val != nil && val.Kind() == cbor.KindByteString {
		ch.Signature = val.Bytes()
	}
	if val := v.IntMapGet(8); val != nil && val.Kind() == cbor.KindUnsigned {
		ch.ExpiresAt = val.Uint()
	}
	if val := v.IntMapGet(9); val != nil && val.Kind() == cbor.KindByteString {
		ch.ReceiverMac = val.Bytes()
	}
	if val := v.IntMapGet(10); val != nil && val.Kind() == cbor.KindUnsigned {
		ch.KeyAlgorithm = val.Uint()
	}
	return ch, nil
}

// ServerHello represents a ServerHello message per RFC-0002 §5.4.
type ServerHello struct {
	ProtocolVersion uint64
	AgentId         []byte
	PublicKey       []byte
	Nonce           []byte
	Capabilities    []cbor.Value
	Extensions      []ExtensionEntry
	SessionId       []byte
	Signature       []byte
	ExpiresAt       uint64
	KeyAlgorithm    uint64
}

// ToCBORWithoutSig encodes ServerHello excluding signature (key 8).
func (sh *ServerHello) ToCBORWithoutSig() cbor.Value {
	entries := []cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(sh.ProtocolVersion)},
		{Key: 2, Value: cbor.BStr(sh.AgentId)},
		{Key: 3, Value: cbor.BStr(sh.PublicKey)},
		{Key: 4, Value: cbor.BStr(sh.Nonce)},
		{Key: 5, Value: cbor.Arr(sh.Capabilities)},
	}
	extArr := make([]cbor.Value, len(sh.Extensions))
	for i, e := range sh.Extensions {
		extArr[i] = e.ToCBOR()
	}
	entries = append(entries, cbor.IntMapEntry{Key: 6, Value: cbor.Arr(extArr)})
	entries = append(entries, cbor.IntMapEntry{Key: 7, Value: cbor.BStr(sh.SessionId)})
	// Key 8 (signature) excluded
	entries = append(entries, cbor.IntMapEntry{Key: 9, Value: cbor.UUint(sh.ExpiresAt)})
	entries = append(entries, cbor.IntMapEntry{Key: 10, Value: cbor.UUint(sh.KeyAlgorithm)})
	return cbor.IMap(entries)
}

// ToCBOR encodes the full ServerHello.
func (sh *ServerHello) ToCBOR() cbor.Value {
	v := sh.ToCBORWithoutSig()
	entries := v.IntMap()
	// Insert signature as key 8 (will be sorted canonically on encode)
	entries = append(entries, cbor.IntMapEntry{Key: 8, Value: cbor.BStr(sh.Signature)})
	return cbor.IMap(entries)
}

// ClientFinished represents a ClientFinished message per RFC-0002 §5.5.
type ClientFinished struct {
	SessionId []byte
	Signature []byte
}

// ToCBORWithoutSig encodes ClientFinished excluding signature (key 2).
func (cf *ClientFinished) ToCBORWithoutSig() cbor.Value {
	return cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.BStr(cf.SessionId)},
	})
}

// ToCBOR encodes the full ClientFinished.
func (cf *ClientFinished) ToCBOR() cbor.Value {
	return cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.BStr(cf.SessionId)},
		{Key: 2, Value: cbor.BStr(cf.Signature)},
	})
}

// TranscriptHash implements the running SHA-256 transcript hash per §5.6.
type TranscriptHash struct {
	state []byte // current hash value (32 bytes)
}

// NewTranscriptHash initializes the transcript hash with the TLS binding.
// h = SHA-256(tls_binding)
func NewTranscriptHash(tlsBinding []byte) *TranscriptHash {
	h := sha256.Sum256(tlsBinding)
	return &TranscriptHash{state: h[:]}
}

// Update folds a CBOR encoding into the transcript hash.
// h = SHA-256(h || data)
func (t *TranscriptHash) Update(data []byte) {
	h := sha256.New()
	h.Write(t.state)
	h.Write(data)
	t.state = h.Sum(nil)
}

// Current returns the current transcript hash value.
func (t *TranscriptHash) Current() []byte {
	return t.state
}

// SignatureInput returns the bytes to sign/verify: domain_separator || h
func SignatureInput(h []byte) []byte {
	return append([]byte(domainSeparator), h...)
}

// ComputeSessionId derives the session ID per RFC-0002 §5.7:
//   prk = HKDF-Extract(salt = client_nonce || server_nonce, IKM = h_after_clienthello)
//   session_id = HKDF-Expand(prk, info = "aafp-session-id-v1", L = 32)
func ComputeSessionId(hAfterClientHello, clientNonce, serverNonce []byte) []byte {
	salt := append(clientNonce, serverNonce...)
	prk := hkdfExtract(salt, hAfterClientHello)
	return hkdfExpand(prk, []byte(sessionInfoStr), 32)
}

// HKDF-SHA256 Extract (RFC 5869)
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// HKDF-SHA256 Expand (RFC 5869)
func hkdfExpand(prk, info []byte, length int) []byte {
	hashLen := 32
	n := (length + hashLen - 1) / hashLen
	var t []byte
	var okm []byte
	for i := 1; i <= n; i++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

// ComputeReceiverMac computes the DoS mitigation MAC per RFC-0002 §5.8.
//   mac_key = HKDF(input = receiver_agent_id, info = "aafp-v1-dos-mac-key", L = 32)
//   receiver_mac = HMAC-SHA256(key = mac_key, data = CH_CBOR_without_sig_and_mac)
func ComputeReceiverMac(receiverAgentId, chCbor []byte) []byte {
	macKey := hkdfExpand(
		hkdfExtract(nil, receiverAgentId),
		[]byte(dosMacInfoStr),
		32,
	)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(chCbor)
	return mac.Sum(nil)
}

// VerifyReceiverMac verifies a DoS mitigation MAC.
func VerifyReceiverMac(receiverAgentId, chCbor, expectedMac []byte) bool {
	computed := ComputeReceiverMac(receiverAgentId, chCbor)
	if len(computed) != len(expectedMac) {
		return false
	}
	return hmac.Equal(computed, expectedMac)
}

// EncodeHandshakeMessage encodes a handshake message to canonical CBOR.
func EncodeHandshakeMessage(v cbor.Value) ([]byte, error) {
	return cbor.Encode(&v)
}

// DecodeHandshakeMessage decodes CBOR bytes into a Value.
func DecodeHandshakeMessage(data []byte) (*cbor.Value, error) {
	v, _, err := cbor.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("handshake: CBOR decode failed: %w", err)
	}
	return v, nil
}
