// Package replaycache implements the normative nonce replay detection
// defined in RFC-0002 §6.7 (Rev 6 A-9).
//
// The ReplayCache is a time-bounded set of observed handshake nonces,
// keyed by (agent_id, nonce). It is the single authority for
// cross-connection nonce uniqueness. The handshake state machine consults
// it upon receipt of a ClientHello (server side) or ServerHello (client
// side) to reject replayed handshakes before signature verification.
//
// # Design
//
// The ReplayCache is transport-agnostic and synchronous. It does not own
// timers or background tasks. The caller is responsible for:
//
//  1. Calling EvictExpired() periodically (or relying on lazy eviction
//     on Check/Insert).
//  2. Configuring Retention and MaxEntries appropriately for the
//     deployment.
//
// Thread safety: ReplayCache uses internal synchronization (a sync.Mutex)
// and is safe to share across goroutines. The CheckAndInsert operation is
// atomic under the lock, satisfying §6.7.4 Invariant 4.
package replaycache

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultRetention is the default retention window (RFC-0002 §6.7.3).
const DefaultRetention = 300 * time.Second

// MinRetention is the minimum retention window (RFC-0002 §6.7.3).
const MinRetention = 60 * time.Second

// MaxRetention is the maximum retention window (RFC-0002 §6.7.3).
const MaxRetention = 3600 * time.Second

// DefaultMaxEntries is the default maximum number of entries (RFC-0002 §6.7.3).
const DefaultMaxEntries = 100_000

// MinMaxEntries is the minimum maximum entries (RFC-0002 §6.7.3).
const MinMaxEntries = 1_000

// MaxMaxEntries is the maximum maximum entries (RFC-0002 §6.7.3).
const MaxMaxEntries = 10_000_000

// NonceSize is the nonce size in bytes (RFC-0002 §5.3-5.4).
const NonceSize = 32

// AgentIDSize is the AgentId size in bytes (RFC-0002 §5.3).
const AgentIDSize = 32

// ErrNonceReuse is returned by CheckAndInsert when a replay is detected.
var ErrNonceReuse = errors.New("nonce reuse detected: replay attack")

// ErrRetentionOutOfRange is returned by NewWithParams when retention is
// out of the valid range.
var ErrRetentionOutOfRange = errors.New("retention out of range")

// ErrMaxEntriesOutOfRange is returned by NewWithParams when maxEntries is
// out of the valid range.
var ErrMaxEntriesOutOfRange = errors.New("max_entries out of range")

// entry is a single replay cache entry (RFC-0002 §6.7.2).
type entry struct {
	expiresAt    time.Time
	lastAccessed time.Time
}

func (e *entry) isExpired(now time.Time) bool {
	return !now.Before(e.expiresAt)
}

// cacheKey is the (agent_id, nonce) tuple as a 64-byte array.
// We use a fixed-size array to avoid heap allocation per lookup.
type cacheKey [AgentIDSize + NonceSize]byte

func makeKey(agentID []byte, nonce []byte) cacheKey {
	var key cacheKey
	idLen := len(agentID)
	if idLen > AgentIDSize {
		idLen = AgentIDSize
	}
	copy(key[:idLen], agentID[:idLen])
	copy(key[AgentIDSize:], nonce)
	return key
}

// ReplayCache is the normative nonce replay cache (RFC-0002 §6.7).
//
// A time-bounded set of observed (agent_id, nonce) pairs. The cache
// rejects replays before signature verification, conserving CPU and
// preventing session-ID collisions.
//
// Thread-safe via internal sync.Mutex. The CheckAndInsert operation is
// atomic under the lock.
type ReplayCache struct {
	mu         sync.Mutex
	entries    map[cacheKey]*entry
	retention  time.Duration
	maxEntries int
}

// New creates a new ReplayCache with default parameters.
func New() *ReplayCache {
	return &ReplayCache{
		entries:    make(map[cacheKey]*entry),
		retention:  DefaultRetention,
		maxEntries: DefaultMaxEntries,
	}
}

// NewWithParams creates a ReplayCache with custom retention and maxEntries.
//
// Returns an error if parameters are out of range (§6.7.3).
func NewWithParams(retention time.Duration, maxEntries int) (*ReplayCache, error) {
	if retention < MinRetention || retention > MaxRetention {
		return nil, fmt.Errorf("%w: got %v, min %v, max %v",
			ErrRetentionOutOfRange, retention, MinRetention, MaxRetention)
	}
	if maxEntries < MinMaxEntries || maxEntries > MaxMaxEntries {
		return nil, fmt.Errorf("%w: got %d, min %d, max %d",
			ErrMaxEntriesOutOfRange, maxEntries, MinMaxEntries, MaxMaxEntries)
	}
	return &ReplayCache{
		entries:    make(map[cacheKey]*entry),
		retention:  retention,
		maxEntries: maxEntries,
	}, nil
}

// NewWithCapacity creates a ReplayCache with custom parameters and
// pre-allocated capacity.
func NewWithCapacity(retention time.Duration, maxEntries, capacity int) (*ReplayCache, error) {
	cache, err := NewWithParams(retention, maxEntries)
	if err != nil {
		return nil, err
	}
	cap := capacity
	if cap > maxEntries {
		cap = maxEntries
	}
	cache.entries = make(map[cacheKey]*entry, cap)
	return cache, nil
}

// NewWithParamsUnchecked creates a ReplayCache with custom parameters,
// bypassing validation.
//
// For testing only. This constructor does not enforce the RFC
// minimum/maximum parameter ranges, allowing tests to use short
// retention durations and small maxEntries for fast eviction tests.
func NewWithParamsUnchecked(retention time.Duration, maxEntries int) *ReplayCache {
	return &ReplayCache{
		entries:    make(map[cacheKey]*entry),
		retention:  retention,
		maxEntries: maxEntries,
	}
}

// ── Queries ────────────────────────────────────────────────────────

// Retention returns the configured retention duration.
func (c *ReplayCache) Retention() time.Duration {
	return c.retention
}

// MaxEntries returns the configured max entries.
func (c *ReplayCache) MaxEntries() int {
	return c.maxEntries
}

// Len returns the current number of entries (including expired, not yet swept).
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// IsEmpty returns whether the cache is empty.
func (c *ReplayCache) IsEmpty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries) == 0
}

// ── Core operations ────────────────────────────────────────────────

// Check returns true if (agentID, nonce) is a replay (non-expired entry
// exists). Does NOT insert.
//
// This is a read-only query. Use CheckAndInsert for the atomic
// check-and-insert operation used in handshake integration.
func (c *ReplayCache) Check(agentID []byte, nonce []byte) bool {
	if len(nonce) != NonceSize {
		return false
	}
	now := time.Now()
	key := makeKey(agentID, nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lazyEvict(now)
	if e, ok := c.entries[key]; ok {
		if e.isExpired(now) {
			delete(c.entries, key)
			return false
		}
		e.lastAccessed = now
		return true
	}
	return false
}

// CheckAndInsert atomically checks and inserts (RFC-0002 §6.7.4 Invariant 4).
//
// Returns nil if the nonce is fresh (inserted into cache).
// Returns ErrNonceReuse if the nonce is a replay (already present and
// non-expired).
//
// This is the primary entry point for handshake integration
// (§6.7.5 step 3-5, §6.7.6 step 3-5). It combines the replay check
// and cache insertion into a single atomic operation.
func (c *ReplayCache) CheckAndInsert(agentID []byte, nonce []byte) error {
	if len(nonce) != NonceSize {
		return fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	now := time.Now()
	key := makeKey(agentID, nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lazyEvict(now)

	// Check for existing non-expired entry.
	if e, ok := c.entries[key]; ok {
		if !e.isExpired(now) {
			return ErrNonceReuse
		}
		// Expired: remove and re-insert below.
		delete(c.entries, key)
	}

	// Enforce maxEntries with LRU eviction if needed.
	if len(c.entries) >= c.maxEntries {
		c.evictLRU(now)
	}

	// Insert new entry.
	c.entries[key] = &entry{
		expiresAt:    now.Add(c.retention),
		lastAccessed: now,
	}
	return nil
}

// Insert inserts a nonce without checking. Used when the caller has already
// verified uniqueness via Check().
//
// If the entry already exists (non-expired), this is a no-op.
// If the entry exists but is expired, it is refreshed.
func (c *ReplayCache) Insert(agentID []byte, nonce []byte) {
	if len(nonce) != NonceSize {
		return
	}
	now := time.Now()
	key := makeKey(agentID, nonce)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lazyEvict(now)

	// Enforce maxEntries with LRU eviction if needed.
	if _, ok := c.entries[key]; !ok && len(c.entries) >= c.maxEntries {
		c.evictLRU(now)
	}

	c.entries[key] = &entry{
		expiresAt:    now.Add(c.retention),
		lastAccessed: now,
	}
}

// EvictExpired removes all expired entries. Returns the number evicted.
//
// This is a full sweep. For lazy eviction (small batch), the
// Check/Insert/CheckAndInsert methods already perform partial sweeps
// on each access.
func (c *ReplayCache) EvictExpired() int {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	before := len(c.entries)
	for key, e := range c.entries {
		if e.isExpired(now) {
			delete(c.entries, key)
		}
	}
	return before - len(c.entries)
}

// Clear removes all entries.
func (c *ReplayCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[cacheKey]*entry)
}

// ── Internal helpers ───────────────────────────────────────────────

// lazyEvict scans a small batch of entries and removes expired ones.
// This bounds the per-call work to O(batchSize) (§6.7.4 Invariant 6).
func (c *ReplayCache) lazyEvict(now time.Time) {
	if len(c.entries) <= c.maxEntries/2 {
		// Cache is small; skip lazy eviction for efficiency.
		return
	}
	const batchSize = 64
	checked := 0
	var toRemove []cacheKey
	for key, e := range c.entries {
		if checked >= batchSize {
			break
		}
		if e.isExpired(now) {
			toRemove = append(toRemove, key)
		}
		checked++
	}
	for _, key := range toRemove {
		delete(c.entries, key)
	}
}

// evictLRU evicts the least-recently-used non-expired entry (§6.7.7).
func (c *ReplayCache) evictLRU(now time.Time) {
	// First try to evict expired entries.
	for key, e := range c.entries {
		if e.isExpired(now) {
			delete(c.entries, key)
			return
		}
	}

	// No expired entries: evict LRU.
	var lruKey cacheKey
	var hasLRU bool
	var lruTime time.Time
	for key, e := range c.entries {
		if !hasLRU || e.lastAccessed.Before(lruTime) {
			lruTime = e.lastAccessed
			lruKey = key
			hasLRU = true
		}
	}
	if hasLRU {
		delete(c.entries, lruKey)
	}
}
