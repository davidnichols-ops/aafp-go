package closemanager

import (
	"strings"
	"testing"
	"time"
)

// Property-based tests for CLOSE frame semantics (RFC-0002 §6.6, A-8).
// These tests run 100,000+ randomized shutdown sequences.

// Simple deterministic PRNG (xorshift64) for reproducible property tests.
type rng struct {
	state uint64
}

func newRng(seed uint64) *rng {
	if seed == 0 {
		seed = 1
	}
	return &rng{state: seed}
}

func (r *rng) nextU64() uint64 {
	x := r.state
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.state = x
	return x
}

func (r *rng) nextU32() uint32 {
	return uint32(r.nextU64())
}

func (r *rng) nextBool() bool {
	return r.nextU64()&1 == 1
}

func (r *rng) nextRange(max uint64) uint64 {
	if max == 0 {
		return 0
	}
	return r.nextU64() % max
}

// Random event to apply to a CloseManager.
type closeEvent int

const (
	evtInitiateClose closeEvent = iota
	evtOnCloseReceived
	evtRespondClose
	evtOnTimeout
	evtOnFatalError
	evtOnTransportReset
	evtAbort
	evtCheckTimer
)

func randomEvent(r *rng) closeEvent {
	return closeEvent(r.nextRange(8))
}

func (e closeEvent) apply(cm *CloseManager, r *rng) CloseAction {
	switch e {
	case evtInitiateClose:
		return cm.InitiateClose(r.nextU32(), "x")
	case evtOnCloseReceived:
		return cm.OnCloseReceived(r.nextU32(), "x")
	case evtRespondClose:
		return cm.RespondClose(r.nextU32(), "x")
	case evtOnTimeout:
		return cm.OnTimeout()
	case evtOnFatalError:
		return cm.OnFatalErrorReceived()
	case evtOnTransportReset:
		return cm.OnTransportReset()
	case evtAbort:
		return cm.Abort()
	case evtCheckTimer:
		var now time.Time
		if r.nextBool() {
			now = time.Now().Add(time.Duration(r.nextRange(10)) * time.Second)
		} else {
			now = time.Now().Add(-time.Duration(r.nextRange(10)) * time.Second)
		}
		return cm.CheckTimer(now)
	default:
		return None()
	}
}

// ── Property 1: Closed state is terminal ──────────────────────────

func TestPropClosedIsAlwaysTerminal(t *testing.T) {
	r := newRng(42)
	for i := 0; i < 100000; i++ {
		cm := New()
		for j := 0; j < 20; j++ {
			evt := randomEvent(r)
			evt.apply(cm, r)
			if cm.IsClosed() {
				for k := 0; k < 10; k++ {
					evt := randomEvent(r)
					evt.apply(cm, r)
					if !cm.IsClosed() {
						t.Errorf("iteration %d: state leaked from Closed: %s", i, cm.State())
					}
				}
				break
			}
		}
	}
}

// ── Property 2: At most one SendCloseFrame from InitiateClose ─────

func TestPropInitiateCloseSendsAtMostOne(t *testing.T) {
	r := newRng(123)
	for i := 0; i < 100000; i++ {
		cm := New()
		sendCount := 0
		for j := 0; j < 20; j++ {
			action := cm.InitiateClose(r.nextU32(), "x")
			if action.Kind == ActionSendCloseFrame {
				sendCount++
			}
		}
		if sendCount > 1 {
			t.Errorf("iteration %d: InitiateClose sent %d frames (max 1)", i, sendCount)
		}
	}
}

// ── Property 3: At most one SendCloseFrame from RespondClose ──────

func TestPropRespondCloseSendsAtMostOne(t *testing.T) {
	r := newRng(456)
	for i := 0; i < 100000; i++ {
		cm := New()
		cm.OnCloseReceived(0, "peer")
		sendCount := 0
		for j := 0; j < 20; j++ {
			action := cm.RespondClose(r.nextU32(), "x")
			if action.Kind == ActionSendCloseFrame {
				sendCount++
			}
		}
		if sendCount > 1 {
			t.Errorf("iteration %d: RespondClose sent %d frames (max 1)", i, sendCount)
		}
	}
}

// ── Property 4: can_send is false for data frames after close sent ─

func TestPropNoDataAfterCloseSent(t *testing.T) {
	r := newRng(789)
	dataFrameTypes := []byte{0x01, 0x03, 0x04, 0x07, 0x08}
	for i := 0; i < 100000; i++ {
		cm := New()
		for j := 0; j < 10; j++ {
			randomEvent(r).apply(cm, r)
		}
		if cm.State() == StateLocalCloseSent {
			for _, ft := range dataFrameTypes {
				if cm.CanSend(ft) {
					t.Errorf("iteration %d: CanSend(0x%02X) true in LocalCloseSent", i, ft)
				}
			}
		}
	}
}

// ── Property 5: Frame disposition never returns RejectWithError ───

func TestPropDispositionNeverRejectWithError(t *testing.T) {
	r := newRng(321)
	for i := 0; i < 100000; i++ {
		cm := New()
		for j := 0; j < 10; j++ {
			randomEvent(r).apply(cm, r)
		}
		for ft := 0; ft <= 255; ft++ {
			d := cm.FrameDisposition(byte(ft))
			if d != DispositionAccept && d != DispositionDiscardSilently {
				t.Errorf("iteration %d: invalid disposition for 0x%02X in %s: %s",
					i, ft, cm.State(), d)
			}
		}
	}
}

// ── Property 6: Timer only active in LocalCloseSent or RemoteCloseReceived ─

func TestPropTimerOnlyActiveInClosingStates(t *testing.T) {
	r := newRng(654)
	for i := 0; i < 100000; i++ {
		cm := New()
		for j := 0; j < 10; j++ {
			randomEvent(r).apply(cm, r)
		}
		if cm.TimerActive() {
			s := cm.State()
			if s != StateLocalCloseSent && s != StateRemoteCloseReceived {
				t.Errorf("iteration %d: timer active in %s", i, s)
			}
		}
	}
}

// ── Property 7: State machine has exactly 5 states ────────────────

func TestPropOnlyFiveStatesReachable(t *testing.T) {
	r := newRng(987)
	validStates := map[CloseState]bool{
		StateOpen:                true,
		StateLocalCloseSent:      true,
		StateRemoteCloseReceived: true,
		StateCloseReceived:       true,
		StateClosed:              true,
	}
	for i := 0; i < 100000; i++ {
		cm := New()
		for j := 0; j < 10; j++ {
			randomEvent(r).apply(cm, r)
		}
		if !validStates[cm.State()] {
			t.Errorf("iteration %d: invalid state: %s", i, cm.State())
		}
	}
}

// ── Property 8: Once closed, no action returns CloseQuic ──────────

func TestPropNoCloseQuicAfterClosed(t *testing.T) {
	r := newRng(111)
	for i := 0; i < 100000; i++ {
		cm := New()
		cm.Abort()
		for j := 0; j < 10; j++ {
			action := randomEvent(r).apply(cm, r)
			if action.Kind == ActionCloseQuic {
				t.Errorf("iteration %d: CloseQuic returned after already Closed", i)
			}
		}
	}
}

// ── Property 9: Message always truncated to <= 256 bytes ──────────

func TestPropMessageAlwaysTruncated(t *testing.T) {
	r := newRng(222)
	for i := 0; i < 100000; i++ {
		cm := New()
		length := int(r.nextRange(1000))
		msg := strings.Repeat("x", length)
		action := cm.InitiateClose(0, msg)
		if len(action.Message) > MaxCloseMessageLen {
			t.Errorf("iteration %d: message len %d > %d", i, len(action.Message), MaxCloseMessageLen)
		}
	}
}

// ── Property 10: Crossed close always results in Closed ───────────

func TestPropCrossedCloseAlwaysClosed(t *testing.T) {
	for i := 0; i < 100000; i++ {
		cm := New()
		cm.InitiateClose(0, "local")
		action := cm.OnCloseReceived(0, "peer")
		if action.Kind != ActionCloseQuic {
			t.Errorf("iteration %d: expected CloseQuic, got %s", i, action)
		}
		if cm.State() != StateClosed {
			t.Errorf("iteration %d: expected Closed, got %s", i, cm.State())
		}
	}
}
