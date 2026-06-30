package replaycache

import (
	"testing"
)

func TestHandshakeReplayCheckerServerSide(t *testing.T) {
	cache := New()
	checker := NewHandshakeReplayChecker(cache)
	aid := agentID(1)
	n := nonce(0x42)

	// First check: should be fresh.
	if err := checker.CheckClientHello(aid, n); err != nil {
		t.Fatalf("first check should be fresh: %v", err)
	}

	// Insert after verification.
	checker.InsertClientHello(aid, n)

	// Second check: should be replay.
	if err := checker.CheckClientHello(aid, n); err == nil {
		t.Fatal("second check should be replay")
	}
}

func TestHandshakeReplayCheckerClientSide(t *testing.T) {
	cache := New()
	checker := NewHandshakeReplayChecker(cache)
	aid := agentID(1)
	n := nonce(0x42)

	// First check: should be fresh.
	if err := checker.CheckServerHello(aid, n); err != nil {
		t.Fatalf("first check should be fresh: %v", err)
	}

	// Insert after verification.
	checker.InsertServerHello(aid, n)

	// Second check: should be replay.
	if err := checker.CheckServerHello(aid, n); err == nil {
		t.Fatal("second check should be replay")
	}
}

func TestHandshakeReplayCheckerCheckAndInsertClientHello(t *testing.T) {
	cache := New()
	checker := NewHandshakeReplayChecker(cache)
	aid := agentID(1)
	n := nonce(0x42)

	// First: fresh.
	if err := checker.CheckAndInsertClientHello(aid, n); err != nil {
		t.Fatalf("first check-and-insert: %v", err)
	}

	// Second: replay.
	if err := checker.CheckAndInsertClientHello(aid, n); err == nil {
		t.Fatal("second check-and-insert should be replay")
	}
}

func TestHandshakeReplayCheckerCheckAndInsertServerHello(t *testing.T) {
	cache := New()
	checker := NewHandshakeReplayChecker(cache)
	aid := agentID(1)
	n := nonce(0x42)

	// First: fresh.
	if err := checker.CheckAndInsertServerHello(aid, n); err != nil {
		t.Fatalf("first check-and-insert: %v", err)
	}

	// Second: replay.
	if err := checker.CheckAndInsertServerHello(aid, n); err == nil {
		t.Fatal("second check-and-insert should be replay")
	}
}

func TestHandshakeReplayCheckerWrongNonceSize(t *testing.T) {
	cache := New()
	checker := NewHandshakeReplayChecker(cache)
	aid := agentID(1)
	n := makeBytes(16, 0x42) // Wrong size

	if err := checker.CheckClientHello(aid, n); err == nil {
		t.Fatal("wrong nonce size should return error")
	}
	if err := checker.CheckServerHello(aid, n); err == nil {
		t.Fatal("wrong nonce size should return error")
	}
	if err := checker.CheckAndInsertClientHello(aid, n); err == nil {
		t.Fatal("wrong nonce size should return error")
	}
	if err := checker.CheckAndInsertServerHello(aid, n); err == nil {
		t.Fatal("wrong nonce size should return error")
	}
}

func TestHandshakeReplayCheckerCache(t *testing.T) {
	cache := New()
	checker := NewHandshakeReplayChecker(cache)
	if checker.Cache() != cache {
		t.Fatal("Cache() should return the underlying cache")
	}
}
