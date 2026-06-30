// Package replaycache provides handshake integration helpers that wrap
// the ReplayCache for server-side and client-side replay checking.
//
// This file implements the integration points defined in RFC-0002 §6.7.5
// (server-side) and §6.7.6 (client-side).

package replaycache

import (
	"errors"
	"fmt"
)

// HandshakeReplayChecker wraps a ReplayCache for use in handshake flows.
//
// It enforces the normative invariants from §6.7.4:
// - Check-before-verify (Invariant 1)
// - Insert-after-verify (Invariants 2, 3)
// - Atomicity (Invariant 4)
type HandshakeReplayChecker struct {
	cache *ReplayCache
}

// NewHandshakeReplayChecker creates a new checker wrapping the given cache.
func NewHandshakeReplayChecker(cache *ReplayCache) *HandshakeReplayChecker {
	return &HandshakeReplayChecker{cache: cache}
}

// CheckClientHello performs the server-side replay check for a ClientHello
// (RFC-0002 §6.7.5, steps 1-3).
//
// This MUST be called BEFORE signature verification (Invariant 1).
// Returns nil if the nonce is fresh (proceed to verification).
// Returns ErrNonceReuse if the nonce is a replay (send ERROR 2008, close).
func (h *HandshakeReplayChecker) CheckClientHello(agentID, clientNonce []byte) error {
	if len(clientNonce) != NonceSize {
		return fmt.Errorf("client_nonce must be %d bytes, got %d", NonceSize, len(clientNonce))
	}
	if h.cache.Check(agentID, clientNonce) {
		return ErrNonceReuse
	}
	return nil
}

// InsertClientHello inserts a verified ClientHello nonce into the cache
// (RFC-0002 §6.7.5, step 5).
//
// This MUST be called AFTER signature verification succeeds (Invariant 2)
// and BEFORE the ServerHello is sent.
func (h *HandshakeReplayChecker) InsertClientHello(agentID, clientNonce []byte) {
	if len(clientNonce) != NonceSize {
		return
	}
	h.cache.Insert(agentID, clientNonce)
}

// CheckAndInsertClientHello atomically checks and inserts a ClientHello
// nonce. This is used when the caller wants to combine the check and
// insert into a single operation (e.g., after verification succeeds).
//
// Returns nil if fresh (inserted), ErrNonceReuse if replay.
func (h *HandshakeReplayChecker) CheckAndInsertClientHello(agentID, clientNonce []byte) error {
	if len(clientNonce) != NonceSize {
		return fmt.Errorf("client_nonce must be %d bytes, got %d", NonceSize, len(clientNonce))
	}
	return h.cache.CheckAndInsert(agentID, clientNonce)
}

// CheckServerHello performs the client-side replay check for a ServerHello
// (RFC-0002 §6.7.6, steps 1-3).
//
// This MUST be called BEFORE signature verification (Invariant 1).
// Returns nil if the nonce is fresh (proceed to verification).
// Returns ErrNonceReuse if the nonce is a replay (send ERROR 2008, close).
func (h *HandshakeReplayChecker) CheckServerHello(agentID, serverNonce []byte) error {
	if len(serverNonce) != NonceSize {
		return fmt.Errorf("server_nonce must be %d bytes, got %d", NonceSize, len(serverNonce))
	}
	if h.cache.Check(agentID, serverNonce) {
		return ErrNonceReuse
	}
	return nil
}

// InsertServerHello inserts a verified ServerHello nonce into the cache
// (RFC-0002 §6.7.6, step 5).
//
// This MUST be called AFTER signature verification succeeds (Invariant 3)
// and BEFORE the ClientFinished is sent.
func (h *HandshakeReplayChecker) InsertServerHello(agentID, serverNonce []byte) {
	if len(serverNonce) != NonceSize {
		return
	}
	h.cache.Insert(agentID, serverNonce)
}

// CheckAndInsertServerHello atomically checks and inserts a ServerHello
// nonce.
//
// Returns nil if fresh (inserted), ErrNonceReuse if replay.
func (h *HandshakeReplayChecker) CheckAndInsertServerHello(agentID, serverNonce []byte) error {
	if len(serverNonce) != NonceSize {
		return fmt.Errorf("server_nonce must be %d bytes, got %d", NonceSize, len(serverNonce))
	}
	return h.cache.CheckAndInsert(agentID, serverNonce)
}

// Cache returns the underlying ReplayCache.
func (h *HandshakeReplayChecker) Cache() *ReplayCache {
	return h.cache
}

// Ensure ErrNonceReuse is defined as a sentinel error.
var _ = errors.Is // ensure errors import is used
