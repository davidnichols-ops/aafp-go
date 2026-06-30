package closemanager

import (
	"strings"
	"testing"
	"time"
)

// ── Basic state transitions ───────────────────────────────────────

func TestNewManagerStartsOpen(t *testing.T) {
	cm := New()
	if cm.State() != StateOpen {
		t.Fatalf("expected Open, got %s", cm.State())
	}
	if cm.IsClosed() {
		t.Fatal("should not be closed")
	}
	if cm.IsClosing() {
		t.Fatal("should not be closing")
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
	if cm.CloseTimeout() != DefaultCloseTimeout {
		t.Fatalf("expected default timeout %v, got %v", DefaultCloseTimeout, cm.CloseTimeout())
	}
}

func TestWithCustomTimeout(t *testing.T) {
	cm, err := NewWithTimeout(10 * time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cm.CloseTimeout() != 10*time.Second {
		t.Fatalf("expected 10s, got %v", cm.CloseTimeout())
	}
}

func TestWithTimeoutBelowMinimumFails(t *testing.T) {
	_, err := NewWithTimeout(500 * time.Millisecond)
	if err == nil {
		t.Fatal("expected error for too-short timeout")
	}
	if !strings.Contains(err.Error(), "1s") {
		t.Fatalf("error should mention 1s: %v", err)
	}
}

func TestWithTimeoutExactlyMinimum(t *testing.T) {
	cm, err := NewWithTimeout(MinCloseTimeout)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cm.CloseTimeout() != MinCloseTimeout {
		t.Fatalf("expected %v, got %v", MinCloseTimeout, cm.CloseTimeout())
	}
}

// ── InitiateClose ─────────────────────────────────────────────────

func TestInitiateCloseFromOpen(t *testing.T) {
	cm := New()
	action := cm.InitiateClose(0, "goodbye")
	if action.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", action)
	}
	if action.Code != 0 || action.Message != "goodbye" {
		t.Fatalf("unexpected action content: %s", action)
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
	if !cm.TimerActive() {
		t.Fatal("timer should be active")
	}
	if !cm.IsClosing() {
		t.Fatal("should be closing")
	}
}

func TestInitiateCloseIdempotent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "first")
	action := cm.InitiateClose(0, "second")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
}

func TestInitiateCloseAfterRemoteCloseIsNoop(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	action := cm.InitiateClose(0, "local")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
}

// ── OnCloseReceived ───────────────────────────────────────────────

func TestOnCloseReceivedFromOpen(t *testing.T) {
	cm := New()
	action := cm.OnCloseReceived(1000, "going away")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
	code, ok := cm.RemoteCode()
	if !ok || code != 1000 {
		t.Fatalf("expected remote code 1000, got %d (ok=%v)", code, ok)
	}
	msg, ok := cm.RemoteMessage()
	if !ok || msg != "going away" {
		t.Fatalf("expected remote message 'going away', got %q (ok=%v)", msg, ok)
	}
	if !cm.TimerActive() {
		t.Fatal("timer should be active")
	}
}

func TestOnCloseReceivedFromLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.OnCloseReceived(0, "ack")
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

func TestOnCloseReceivedDuplicateInRemoteClose(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "first")
	action := cm.OnCloseReceived(0, "second")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
	// First message is preserved.
	msg, _ := cm.RemoteMessage()
	if msg != "first" {
		t.Fatalf("expected 'first', got %q", msg)
	}
}

func TestOnCloseReceivedInClosedIsNoop(t *testing.T) {
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

// ── RespondClose ──────────────────────────────────────────────────

func TestRespondCloseFromRemoteCloseReceived(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	action := cm.RespondClose(0, "ack")
	if action.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", action)
	}
	if action.Code != 0 || action.Message != "ack" {
		t.Fatalf("unexpected action content: %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

func TestRespondCloseFromOpenIsNoop(t *testing.T) {
	cm := New()
	action := cm.RespondClose(0, "ack")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateOpen {
		t.Fatalf("expected Open, got %s", cm.State())
	}
}

func TestRespondCloseFromLocalCloseSentIsNoop(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.RespondClose(0, "ack")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
}

// ── Crossed close ─────────────────────────────────────────────────

func TestCrossedClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "local")
	action := cm.OnCloseReceived(0, "peer")
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

// ── OnFatalErrorReceived ──────────────────────────────────────────

func TestOnFatalErrorFromOpen(t *testing.T) {
	cm := New()
	action := cm.OnFatalErrorReceived()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestOnFatalErrorFromLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.OnFatalErrorReceived()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

// ── OnTransportReset ──────────────────────────────────────────────

func TestOnTransportResetFromOpen(t *testing.T) {
	cm := New()
	action := cm.OnTransportReset()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestOnTransportResetFromLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.OnTransportReset()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

// ── OnTimeout ─────────────────────────────────────────────────────

func TestOnTimeoutFromLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.OnTimeout()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

func TestOnTimeoutFromRemoteCloseReceived(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	action := cm.OnTimeout()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestOnTimeoutFromOpenIsNoop(t *testing.T) {
	cm := New()
	action := cm.OnTimeout()
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateOpen {
		t.Fatalf("expected Open, got %s", cm.State())
	}
}

func TestOnTimeoutFromClosedIsNoop(t *testing.T) {
	cm := New()
	cm.Abort()
	action := cm.OnTimeout()
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── CheckTimer ────────────────────────────────────────────────────

func TestCheckTimerNotExpired(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	deadline, _ := cm.Deadline()
	now := deadline.Add(-100 * time.Millisecond)
	action := cm.CheckTimer(now)
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
}

func TestCheckTimerExpired(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	deadline, _ := cm.Deadline()
	now := deadline.Add(time.Millisecond)
	action := cm.CheckTimer(now)
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── Abort ─────────────────────────────────────────────────────────

func TestAbortFromOpen(t *testing.T) {
	cm := New()
	action := cm.Abort()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestAbortFromLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.Abort()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

// ── CanSend ───────────────────────────────────────────────────────

func TestCanSendInOpen(t *testing.T) {
	cm := New()
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		if !cm.CanSend(ft) {
			t.Errorf("should be able to send 0x%02X in Open", ft)
		}
	}
}

func TestCanSendInLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08} {
		if cm.CanSend(ft) {
			t.Errorf("should NOT be able to send 0x%02X in LocalCloseSent", ft)
		}
	}
	if !cm.CanSend(0x06) {
		t.Error("fatal ERROR should be sendable in LocalCloseSent")
	}
}

func TestCanSendInRemoteCloseReceived(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	if !cm.CanSend(0x05) {
		t.Error("CLOSE should be sendable in RemoteCloseReceived")
	}
	if !cm.CanSend(0x06) {
		t.Error("ERROR should be sendable in RemoteCloseReceived")
	}
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x07, 0x08} {
		if cm.CanSend(ft) {
			t.Errorf("should NOT be able to send 0x%02X in RemoteCloseReceived", ft)
		}
	}
}

func TestCanSendInClosed(t *testing.T) {
	cm := New()
	cm.Abort()
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		if cm.CanSend(ft) {
			t.Errorf("should NOT send 0x%02X in Closed", ft)
		}
	}
}

// ── FrameDisposition ──────────────────────────────────────────────

func TestFrameDispositionInOpen(t *testing.T) {
	cm := New()
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		if cm.FrameDisposition(ft) != DispositionAccept {
			t.Errorf("0x%02X should be Accept in Open", ft)
		}
	}
}

func TestFrameDispositionInLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	if cm.FrameDisposition(0x05) != DispositionAccept {
		t.Error("CLOSE should be Accept in LocalCloseSent")
	}
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08} {
		if cm.FrameDisposition(ft) != DispositionDiscardSilently {
			t.Errorf("0x%02X should be DiscardSilently in LocalCloseSent", ft)
		}
	}
}

func TestFrameDispositionInRemoteCloseReceived(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		if cm.FrameDisposition(ft) != DispositionDiscardSilently {
			t.Errorf("0x%02X should be DiscardSilently in RemoteCloseReceived", ft)
		}
	}
}

func TestFrameDispositionInClosed(t *testing.T) {
	cm := New()
	cm.Abort()
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		if cm.FrameDisposition(ft) != DispositionDiscardSilently {
			t.Errorf("0x%02X should be DiscardSilently in Closed", ft)
		}
	}
}

// ── Message truncation ────────────────────────────────────────────

func TestTruncateMessageShort(t *testing.T) {
	if got := truncateMessage("hello"); got != "hello" {
		t.Fatalf("expected 'hello', got %q", got)
	}
}

func TestTruncateMessageExactLimit(t *testing.T) {
	s := strings.Repeat("x", MaxCloseMessageLen)
	if got := truncateMessage(s); got != s {
		t.Fatalf("expected unchanged, got len %d", len(got))
	}
}

func TestTruncateMessageOverLimit(t *testing.T) {
	s := strings.Repeat("x", MaxCloseMessageLen+100)
	got := truncateMessage(s)
	if len(got) > MaxCloseMessageLen {
		t.Fatalf("truncated message too long: %d", len(got))
	}
}

func TestTruncateMessageUTF8Safe(t *testing.T) {
	// Each 'é' is 2 bytes. 130 'é' = 260 bytes > 256.
	s := strings.Repeat("é", 130)
	got := truncateMessage(s)
	if len(got) > MaxCloseMessageLen {
		t.Fatalf("truncated message too long: %d", len(got))
	}
	// Verify it's valid UTF-8 by checking it doesn't contain invalid bytes.
	// Go strings are always valid UTF-8 if constructed properly, but
	// truncation could break a multi-byte rune.
	for _, r := range got {
		if r == 0xFFFD {
			t.Fatal("truncated message contains replacement character")
		}
	}
}

// ── Full lifecycle scenarios ──────────────────────────────────────

func TestFullGracefulCloseLifecycle(t *testing.T) {
	cm := New()
	a1 := cm.InitiateClose(0, "goodbye")
	if a1.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", a1)
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
	a2 := cm.OnCloseReceived(0, "ack")
	if a2.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", a2)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestFullRemoteInitiatedCloseLifecycle(t *testing.T) {
	cm := New()
	a1 := cm.OnCloseReceived(0, "peer goodbye")
	if a1.Kind != ActionNone {
		t.Fatalf("expected None, got %s", a1)
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
	a2 := cm.RespondClose(0, "ack")
	if a2.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", a2)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestFullTimeoutLifecycle(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.OnTimeout()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestClosedStateIsTrulyTerminal(t *testing.T) {
	cm := New()
	cm.Abort()
	// All events are no-ops.
	if cm.InitiateClose(0, "x").Kind != ActionNone {
		t.Error("InitiateClose should be None in Closed")
	}
	if cm.OnCloseReceived(0, "x").Kind != ActionNone {
		t.Error("OnCloseReceived should be None in Closed")
	}
	if cm.RespondClose(0, "x").Kind != ActionNone {
		t.Error("RespondClose should be None in Closed")
	}
	if cm.OnFatalErrorReceived().Kind != ActionNone {
		t.Error("OnFatalErrorReceived should be None in Closed")
	}
	if cm.OnTransportReset().Kind != ActionNone {
		t.Error("OnTransportReset should be None in Closed")
	}
	if cm.OnTimeout().Kind != ActionNone {
		t.Error("OnTimeout should be None in Closed")
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── State string representation ───────────────────────────────────

func TestStateString(t *testing.T) {
	tests := []struct {
		state CloseState
		want  string
	}{
		{StateOpen, "Open"},
		{StateLocalCloseSent, "LocalCloseSent"},
		{StateRemoteCloseReceived, "RemoteCloseReceived"},
		{StateCloseReceived, "CloseReceived"},
		{StateClosed, "Closed"},
	}
	for _, tc := range tests {
		if got := tc.state.String(); got != tc.want {
			t.Errorf("expected %q, got %q", tc.want, got)
		}
	}
}

func TestStateIsTerminal(t *testing.T) {
	if StateOpen.IsTerminal() {
		t.Error("Open should not be terminal")
	}
	if StateLocalCloseSent.IsTerminal() {
		t.Error("LocalCloseSent should not be terminal")
	}
	if StateRemoteCloseReceived.IsTerminal() {
		t.Error("RemoteCloseReceived should not be terminal")
	}
	if StateCloseReceived.IsTerminal() {
		t.Error("CloseReceived should not be terminal")
	}
	if !StateClosed.IsTerminal() {
		t.Error("Closed should be terminal")
	}
}

func TestStateIsClosing(t *testing.T) {
	if StateOpen.IsClosing() {
		t.Error("Open should not be closing")
	}
	if !StateLocalCloseSent.IsClosing() {
		t.Error("LocalCloseSent should be closing")
	}
	if !StateRemoteCloseReceived.IsClosing() {
		t.Error("RemoteCloseReceived should be closing")
	}
	if !StateCloseReceived.IsClosing() {
		t.Error("CloseReceived should be closing")
	}
	if StateClosed.IsClosing() {
		t.Error("Closed should not be closing")
	}
}
