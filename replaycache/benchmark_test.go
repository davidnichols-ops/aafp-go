// Package replaycache — benchmarks for RFC-0002 §6.7 (A-9).

package replaycache

import (
	"testing"
	"time"
)

func makeNonceBench(seed uint32) []byte {
	n := make([]byte, NonceSize)
	n[0] = byte(seed >> 24)
	n[1] = byte(seed >> 16)
	n[2] = byte(seed >> 8)
	n[3] = byte(seed)
	return n
}

func BenchmarkCheckAndInsertFresh(b *testing.B) {
	aid := agentID(1)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := New()
		n := makeNonceBench(uint32(i))
		b.StartTimer()
		_ = c.CheckAndInsert(aid, n)
	}
}

func BenchmarkCheckAndInsertReplay(b *testing.B) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	_ = c.CheckAndInsert(aid, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.CheckAndInsert(aid, n)
	}
}

func BenchmarkCheckFresh(b *testing.B) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Check(aid, n)
	}
}

func BenchmarkCheckExisting(b *testing.B) {
	c := New()
	aid := agentID(1)
	n := nonce(0x42)
	_ = c.CheckAndInsert(aid, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Check(aid, n)
	}
}

func BenchmarkCheckAndInsert100KCache(b *testing.B) {
	c := New()
	aid := agentID(1)
	for i := 0; i < 100_000; i++ {
		n := makeNonceBench(uint32(i))
		_ = c.CheckAndInsert(aid, n)
	}
	idx := uint32(100_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := makeNonceBench(idx)
		idx++
		_ = c.CheckAndInsert(aid, n)
	}
}

func BenchmarkEvictExpired10K(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := NewWithParamsUnchecked(1*time.Millisecond, 100_000)
		aid := agentID(1)
		for j := 0; j < 10_000; j++ {
			n := makeNonceBench(uint32(j))
			_ = c.CheckAndInsert(aid, n)
		}
		time.Sleep(2 * time.Millisecond)
		b.StartTimer()
		_ = c.EvictExpired()
	}
}
