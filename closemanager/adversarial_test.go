package closemanager

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Adversarial tests for CLOSE frame semantics (RFC-0002 §6.6, A-8).

// ── CLOSE frame flooding ──────────────────────────────────────────

func TestAdvCloseFlood1000CloseFrames(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "first")
	for i := 1; i < 1000; i++ {
		action := cm.OnCloseReceived(uint32(i), fmt.Sprintf("flood-%d", i))
		if action.Kind != ActionNone {
			t.Errorf("flood CLOSE #%d should be no-op, got %s", i, action)
		}
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
	code, _ := cm.RemoteCode()
	if code != 0 {
		t.Fatalf("first code should be preserved, got %d", code)
	}
}

func TestAdvCloseFloodAfterLocalClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnCloseReceived(0, "peer first")
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	for i := 1; i < 1000; i++ {
		action := cm.OnCloseReceived(uint32(i), fmt.Sprintf("flood-%d", i))
		if action.Kind != ActionNone {
			t.Errorf("flood CLOSE #%d should be no-op", i)
		}
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvCloseFloodMixedFrameTypes(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	frameTypes := []byte{0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08}
	for i := 0; i < 1000; i++ {
		ft := frameTypes[i%len(frameTypes)]
		if cm.FrameDisposition(ft) != DispositionDiscardSilently {
			t.Errorf("frame 0x%02X should be DiscardSilently", ft)
		}
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
}

// ── Truncated / oversized messages ────────────────────────────────

func TestAdvOversizedMessageTruncated(t *testing.T) {
	cm := New()
	huge := strings.Repeat("A", 100_000)
	action := cm.InitiateClose(0, huge)
	if len(action.Message) > MaxCloseMessageLen {
		t.Fatalf("message not truncated: %d", len(action.Message))
	}
}

func TestAdvOversizedRemoteMessageTruncated(t *testing.T) {
	cm := New()
	huge := strings.Repeat("B", 100_000)
	cm.OnCloseReceived(0, huge)
	msg, _ := cm.RemoteMessage()
	if len(msg) > MaxCloseMessageLen {
		t.Fatalf("remote message not truncated: %d", len(msg))
	}
}

func TestAdvEmptyMessageAccepted(t *testing.T) {
	cm := New()
	action := cm.InitiateClose(0, "")
	if action.Message != "" {
		t.Fatalf("expected empty message, got %q", action.Message)
	}
}

func TestAdvEmptyRemoteMessageAccepted(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "")
	msg, _ := cm.RemoteMessage()
	if msg != "" {
		t.Fatalf("expected empty message, got %q", msg)
	}
}

func TestAdvMultibyteUTF8MessageTruncatedSafely(t *testing.T) {
	cm := New()
	msg := strings.Repeat("🎉", 65) // 4 bytes each = 260 > 256
	action := cm.InitiateClose(0, msg)
	if len(action.Message) > MaxCloseMessageLen {
		t.Fatalf("message not truncated: %d", len(action.Message))
	}
}

// ── Out-of-order events ───────────────────────────────────────────

func TestAdvTimeoutAfterClosed(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnCloseReceived(0, "peer")
	action := cm.OnTimeout()
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvFatalErrorAfterClosed(t *testing.T) {
	cm := New()
	cm.Abort()
	action := cm.OnFatalErrorReceived()
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvTransportResetAfterClosed(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnCloseReceived(0, "peer")
	action := cm.OnTransportReset()
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvInitiateAfterAbort(t *testing.T) {
	cm := New()
	cm.Abort()
	action := cm.InitiateClose(0, "late")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvRespondCloseAfterTimeout(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	cm.OnTimeout()
	action := cm.RespondClose(0, "late")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── Late CLOSE frames ─────────────────────────────────────────────

func TestAdvLateCloseAfterAbort(t *testing.T) {
	cm := New()
	cm.Abort()
	action := cm.OnCloseReceived(0, "late")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvLateCloseAfterTimeout(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnTimeout()
	action := cm.OnCloseReceived(0, "late")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvLateCloseAfterFatalError(t *testing.T) {
	cm := New()
	cm.OnFatalErrorReceived()
	action := cm.OnCloseReceived(0, "late")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── Rapid cycles ──────────────────────────────────────────────────

func TestAdvRapidInitiateAbortCycles(t *testing.T) {
	for i := 0; i < 1000; i++ {
		cm := New()
		cm.InitiateClose(0, fmt.Sprintf("cycle-%d", i))
		cm.Abort()
		if cm.State() != StateClosed {
			t.Fatalf("cycle %d: expected Closed, got %s", i, cm.State())
		}
	}
}

func TestAdvRapidInitiatePeerCloseCycles(t *testing.T) {
	for i := 0; i < 1000; i++ {
		cm := New()
		cm.InitiateClose(0, fmt.Sprintf("cycle-%d", i))
		action := cm.OnCloseReceived(0, "peer")
		if action.Kind != ActionCloseQuic {
			t.Fatalf("cycle %d: expected CloseQuic, got %s", i, action)
		}
		if cm.State() != StateClosed {
			t.Fatalf("cycle %d: expected Closed", i)
		}
	}
}

// ── State corruption attempts ─────────────────────────────────────

func TestAdvNoStateCorruptionFromFlood(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	for ft := 0; ft <= 255; ft++ {
		cm.FrameDisposition(byte(ft))
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
	if !cm.TimerActive() {
		t.Fatal("timer should still be active")
	}
}

func TestAdvNoStateCorruptionFromRandomEvents(t *testing.T) {
	cm := New()
	for i := 0; i < 10000; i++ {
		switch i % 6 {
		case 0:
			cm.InitiateClose(uint32(i), "x")
		case 1:
			cm.OnCloseReceived(uint32(i), "x")
		case 2:
			cm.OnTimeout()
		case 3:
			cm.OnFatalErrorReceived()
		case 4:
			cm.OnTransportReset()
		default:
			cm.Abort()
		}
		if cm.IsClosed() {
			break
		}
	}
	// No panic = no state corruption.
}

// ── Timer manipulation ────────────────────────────────────────────

func TestAdvCheckTimerWithPastTime(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	past := time.Now().Add(-60 * time.Second)
	action := cm.CheckTimer(past)
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
}

func TestAdvCheckTimerWithFutureTime(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	future := time.Now().Add(60 * time.Second)
	action := cm.CheckTimer(future)
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAdvCheckTimerNoTimerRunning(t *testing.T) {
	cm := New()
	action := cm.CheckTimer(time.Now())
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateOpen {
		t.Fatalf("expected Open, got %s", cm.State())
	}
}

// ── Extreme close codes ───────────────────────────────────────────

func TestAdvMaxCloseCode(t *testing.T) {
	cm := New()
	action := cm.InitiateClose(^uint32(0), "max code")
	if action.Code != ^uint32(0) {
		t.Fatalf("expected max uint32, got %d", action.Code)
	}
}

func TestAdvZeroCloseCode(t *testing.T) {
	cm := New()
	action := cm.InitiateClose(0, "zero code")
	if action.Code != 0 {
		t.Fatalf("expected 0, got %d", action.Code)
	}
}

func TestAdvRemoteMaxCloseCode(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(^uint32(0), "max")
	code, _ := cm.RemoteCode()
	if code != ^uint32(0) {
		t.Fatalf("expected max uint32, got %d", code)
	}
}

// ── Concurrent close race simulation ──────────────────────────────

func TestAdvSimulatedRaceInitiateVsReceive(t *testing.T) {
	cm1 := New()
	cm1.InitiateClose(0, "local")
	a := cm1.OnCloseReceived(0, "peer")
	if a.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", a)
	}

	cm2 := New()
	cm2.OnCloseReceived(0, "peer")
	a = cm2.InitiateClose(0, "local")
	if a.Kind != ActionNone {
		t.Fatalf("expected None, got %s", a)
	}
	a = cm2.RespondClose(0, "ack")
	if a.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", a)
	}

	if cm1.State() != StateClosed || cm2.State() != StateClosed {
		t.Fatal("both should be Closed")
	}
}
