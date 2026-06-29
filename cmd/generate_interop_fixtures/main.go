// Command generate_interop_fixtures produces binary AAFP protocol fixtures
// using the Go independent implementation. These fixtures are consumed by
// the Rust reference implementation to verify bidirectional interoperability.
//
// Usage: go run ./cmd/generate_interop_fixtures <output_dir>
//
// All inputs are fixed (no randomness) so that the Rust implementation can
// reproduce the same logical values from the RFCs alone.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"aafp-go/cbor"
	"aafp-go/frame"
	"aafp-go/handshake"
	"aafp-go/identity"
)

// Fixed test inputs — must match the Rust generator exactly.
var (
	publicKeyA    = bytesFilled(1952, 0x42)
	publicKeyB    = bytesFilled(1952, 0x43)
	signatureA    = bytesFilled(3309, 0x44)
	nonceA        = bytesFilled(32, 0x03)
	nonceB        = bytesFilled(32, 0x04)
	tlsBinding    = bytesFilled(32, 0x05)
	sessionID     = bytesFilled(32, 0x06)
	timestampNow  = uint64(1735689600)
	timestampExp  = uint64(1736294400)
	keyAlgMLDSA65 = uint64(1)
)

func bytesFilled(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func writeFixture(dir string, name string, data []byte) {
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		panic(err)
	}
	fmt.Printf("  wrote %s (%d bytes)\n", path, len(data))
}

func writeCbor(dir, name string, v cbor.Value) {
	data, err := cbor.Encode(&v)
	if err != nil {
		panic(err)
	}
	writeFixture(dir, name, data)
}

func writeFrame(dir, name string, f *frame.Frame) {
	data, err := frame.Encode(f)
	if err != nil {
		panic(err)
	}
	writeFixture(dir, name, data)
}

func main() {
	outputDir := "go_interop_fixtures"
	if len(os.Args) > 1 {
		outputDir = os.Args[1]
	}
	fmt.Printf("Generating Go interop fixtures in: %s\n", outputDir)

	// === CBOR fixtures ===
	cborDir := filepath.Join(outputDir, "cbor")
	writeCbor(cborDir, "uint_5.bin", cbor.UUint(5))
	writeCbor(cborDir, "uint_24.bin", cbor.UUint(24))
	writeCbor(cborDir, "uint_100.bin", cbor.UUint(100))
	writeCbor(cborDir, "uint_1000.bin", cbor.UUint(1000))
	writeCbor(cborDir, "negative_1.bin", cbor.NInt(-1))
	writeCbor(cborDir, "negative_100.bin", cbor.NInt(-100))
	writeCbor(cborDir, "bool_true.bin", cbor.Bool(true))
	writeCbor(cborDir, "bool_false.bin", cbor.Bool(false))
	writeCbor(cborDir, "null.bin", cbor.Null())
	writeCbor(cborDir, "bstr_32.bin", cbor.BStr(bytesFilled(32, 0xaa)))
	writeCbor(cborDir, "tstr_hello.bin", cbor.TStr("hello"))
	writeCbor(cborDir, "empty_array.bin", cbor.Arr(nil))
	writeCbor(cborDir, "empty_map.bin", cbor.IMap(nil))
	writeCbor(cborDir, "int_map_sorted.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.TStr("a")},
		{Key: 100, Value: cbor.TStr("b")},
	}))
	writeCbor(cborDir, "int_map_same_length.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 10, Value: cbor.UUint(1)},
		{Key: 20, Value: cbor.UUint(2)},
	}))
	writeCbor(cborDir, "str_map_sorted.bin", cbor.SMap([]cbor.StrMapEntry{
		{Key: "cat", Value: cbor.UUint(1)},
		{Key: "apple", Value: cbor.UUint(2)},
		{Key: "zebra", Value: cbor.UUint(3)},
	}))

	// === Frame fixtures ===
	frameDir := filepath.Join(outputDir, "frames")
	writeFrame(frameDir, "data_empty.bin", &frame.Frame{
		Version:   frame.Version,
		FrameType: frame.TypeData,
		StreamID:  0,
		Payload:   nil,
	})
	writeFrame(frameDir, "data_stream42.bin", &frame.Frame{
		Version:   frame.Version,
		FrameType: frame.TypeData,
		StreamID:  42,
		Payload:   []byte{0xde, 0xad, 0xbe, 0xef},
	})
	writeFrame(frameDir, "handshake.bin", &frame.Frame{
		Version:   frame.Version,
		FrameType: frame.TypeHandshake,
		StreamID:  0,
		Payload:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	})
	writeFrame(frameDir, "rpc_request.bin", &frame.Frame{
		Version:   frame.Version,
		FrameType: frame.TypeRPCRequest,
		StreamID:  4,
		Payload:   []byte{0xa1, 0x01, 0x02},
	})
	writeFrame(frameDir, "ping.bin", &frame.Frame{
		Version:   frame.Version,
		FrameType: frame.TypePing,
		StreamID:  0,
	})
	writeFrame(frameDir, "data_flags_more.bin", &frame.Frame{
		Version:   frame.Version,
		FrameType: frame.TypeData,
		Flags:     frame.FlagMore,
		StreamID:  8,
		Payload:   []byte{0xff},
	})

	// === Handshake fixtures ===
	hsDir := filepath.Join(outputDir, "handshake")
	agentIdA := identity.AgentIdFromPubkey(publicKeyA)
	agentIdB := identity.AgentIdFromPubkey(publicKeyB)

	ch := &handshake.ClientHello{
		ProtocolVersion: 1,
		AgentId:         agentIdA,
		PublicKey:       publicKeyA,
		Nonce:           nonceA,
		Capabilities:    nil,
		ExpiresAt:       timestampExp,
		KeyAlgorithm:    keyAlgMLDSA65,
	}
	writeCbor(hsDir, "client_hello_without_sig.bin", ch.ToCBORWithoutSigAndMac())

	sh := &handshake.ServerHello{
		ProtocolVersion: 1,
		AgentId:         agentIdB,
		PublicKey:       publicKeyB,
		Nonce:           nonceB,
		SessionId:       sessionID,
		ExpiresAt:       timestampExp,
		KeyAlgorithm:    keyAlgMLDSA65,
	}
	writeCbor(hsDir, "server_hello_without_sig.bin", sh.ToCBORWithoutSig())

	cf := &handshake.ClientFinished{
		SessionId: sessionID,
	}
	writeCbor(hsDir, "client_finished_without_sig.bin", cf.ToCBORWithoutSig())

	// === AgentRecord fixtures ===
	arDir := filepath.Join(outputDir, "agent_record")

	recordA := &identity.AgentRecord{
		RecordType: "aafp-record-v1",
		AgentId:    agentIdA,
		PublicKey:  publicKeyA,
		Capabilities: []identity.CapabilityDescriptor{
			{
				Name: "inference",
				Metadata: map[string]cbor.Value{
					"model": cbor.TStr("test-model"),
				},
			},
		},
		Endpoints:    []string{"/ip4/127.0.0.1/tcp/4001"},
		CreatedAt:    timestampNow,
		ExpiresAt:    timestampExp,
		KeyAlgorithm: keyAlgMLDSA65,
	}
	writeCbor(arDir, "without_sig.bin", recordA.ToCBORWithoutSig())

	recordB := &identity.AgentRecord{
		RecordType:   "aafp-record-v1",
		AgentId:      agentIdB,
		PublicKey:    publicKeyB,
		Capabilities: nil,
		Endpoints:    nil,
		CreatedAt:    timestampNow,
		ExpiresAt:    timestampExp,
		KeyAlgorithm: keyAlgMLDSA65,
	}
	writeCbor(arDir, "empty_capabilities.bin", recordB.ToCBORWithoutSig())

	recordWithSig := &identity.AgentRecord{
		RecordType: "aafp-record-v1",
		AgentId:    agentIdA,
		PublicKey:  publicKeyA,
		Capabilities: []identity.CapabilityDescriptor{
			{Name: "inference"},
		},
		Endpoints:    []string{"/ip4/127.0.0.1/tcp/4001"},
		CreatedAt:    timestampNow,
		ExpiresAt:    timestampExp,
		Signature:    signatureA,
		KeyAlgorithm: keyAlgMLDSA65,
	}
	writeCbor(arDir, "with_sig.bin", recordWithSig.ToCBOR())

	// === RPC fixtures ===
	rpcDir := filepath.Join(outputDir, "rpc")
	writeCbor(rpcDir, "request_basic.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(1)},
		{Key: 2, Value: cbor.TStr("aafp.discovery.lookup")},
		{Key: 3, Value: cbor.Null()},
	}))
	writeCbor(rpcDir, "request_with_params.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(42)},
		{Key: 2, Value: cbor.TStr("aafp.discovery.lookup")},
		{Key: 3, Value: cbor.TStr("inference")},
	}))
	writeCbor(rpcDir, "response_success.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(42)},
		{Key: 2, Value: cbor.UUint(100)},
		{Key: 3, Value: cbor.Null()},
	}))
	writeCbor(rpcDir, "response_error.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(42)},
		{Key: 2, Value: cbor.Null()},
		{Key: 3, Value: cbor.IMap([]cbor.IntMapEntry{
			{Key: 1, Value: cbor.UUint(4005)},
			{Key: 2, Value: cbor.TStr("not found")},
			{Key: 3, Value: cbor.Null()},
		})},
	}))
	writeCbor(rpcDir, "close_message.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(0)},
		{Key: 2, Value: cbor.TStr("goodbye")},
	}))
	writeCbor(rpcDir, "error_message_fatal.bin", cbor.IMap([]cbor.IntMapEntry{
		{Key: 1, Value: cbor.UUint(2001)},
		{Key: 2, Value: cbor.TStr("invalid signature")},
		{Key: 3, Value: cbor.Null()},
		{Key: 4, Value: cbor.Bool(true)},
	}))

	// === Transcript hash fixtures ===
	transcriptDir := filepath.Join(outputDir, "transcript")
	th := handshake.NewTranscriptHash(tlsBinding)
	writeFixture(transcriptDir, "hash_init.bin", th.Current())

	chVal := ch.ToCBORWithoutSigAndMac()
	chCbor, _ := cbor.Encode(&chVal)
	th.Update(chCbor)
	hAfterCh := th.Current()
	writeFixture(transcriptDir, "hash_after_clienthello.bin", hAfterCh)

	shVal := sh.ToCBORWithoutSig()
	shCbor, _ := cbor.Encode(&shVal)
	th.Update(shCbor)
	writeFixture(transcriptDir, "hash_after_serverhello.bin", th.Current())

	cfVal := cf.ToCBORWithoutSig()
	cfCbor, _ := cbor.Encode(&cfVal)
	th.Update(cfCbor)
	writeFixture(transcriptDir, "hash_after_clientfinished.bin", th.Current())

	goSessionId := handshake.ComputeSessionId(hAfterCh, nonceA, nonceB)
	writeFixture(transcriptDir, "session_id.bin", goSessionId)

	// === Manifest ===
	manifest := `{"version":"aafp-v1-interop-fixtures-go-1","generated_by":"go-independent"}`
	writeFixture(outputDir, "manifest.json", []byte(manifest))

	// Print SHA-256 hashes of all fixtures for the Rust verifier to compare
	fmt.Println("\n=== Fixture hashes (SHA-256) ===")
	hashDir(outputDir)
}

func hashDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		if e.IsDir() {
			hashDir(full)
		} else if e.Name() != "manifest.json" {
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			h := sha256.Sum256(data)
			rel, _ := filepath.Rel("go_interop_fixtures", full)
			fmt.Printf("  %s  %s\n", hex.EncodeToString(h[:]), rel)
		}
	}
}
