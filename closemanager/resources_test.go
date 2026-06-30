package closemanager

import (
	"fmt"
	"testing"
	"time"
)

// Resource verification tests for CloseManager (RFC-0002 §6.6.7, A-8).

// ── Timer resource verification ───────────────────────────────────

func TestResourceTimerStartedOnInitiate(t *testing.T) {
	cm := New()
	if cm.TimerActive() {
		t.Fatal("timer should not be active initially")
	}
	if _, ok := cm.Deadline(); ok {
		t.Fatal("deadline should not be set initially")
	}
	cm.InitiateClose(0, "bye")
	if !cm.TimerActive() {
		t.Fatal("timer should be active after initiate")
	}
	if _, ok := cm.Deadline(); !ok {
		t.Fatal("deadline should be set after initiate")
	}
}

func TestResourceTimerStartedOnRemoteClose(t *testing.T) {
	cm := New()
	if cm.TimerActive() {
		t.Fatal("timer should not be active initially")
	}
	cm.OnCloseReceived(0, "peer")
	if !cm.TimerActive() {
		t.Fatal("timer should be active after remote close")
	}
}

func TestResourceTimerStoppedOnPeerClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	if !cm.TimerActive() {
		t.Fatal("timer should be active")
	}
	cm.OnCloseReceived(0, "ack")
	if cm.TimerActive() {
		t.Fatal("timer should be stopped")
	}
	if _, ok := cm.Deadline(); ok {
		t.Fatal("deadline should be cleared")
	}
}

func TestResourceTimerStoppedOnRespond(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	if !cm.TimerActive() {
		t.Fatal("timer should be active")
	}
	cm.RespondClose(0, "ack")
	if cm.TimerActive() {
		t.Fatal("timer should be stopped")
	}
}

func TestResourceTimerStoppedOnTimeout(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnTimeout()
	if cm.TimerActive() {
		t.Fatal("timer should be stopped")
	}
}

func TestResourceTimerStoppedOnAbort(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.Abort()
	if cm.TimerActive() {
		t.Fatal("timer should be stopped")
	}
}

func TestResourceTimerStoppedOnFatalError(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnFatalErrorReceived()
	if cm.TimerActive() {
		t.Fatal("timer should be stopped")
	}
}

func TestResourceTimerStoppedOnTransportReset(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnTransportReset()
	if cm.TimerActive() {
		t.Fatal("timer should be stopped")
	}
}

func TestResourceNoTimerInOpenState(t *testing.T) {
	cm := New()
	if cm.TimerActive() {
		t.Fatal("timer should not be active in Open")
	}
}

func TestResourceNoTimerInClosedState(t *testing.T) {
	cm := New()
	cm.Abort()
	if cm.TimerActive() {
		t.Fatal("timer should not be active in Closed")
	}
}

// ── Remote state tracking ─────────────────────────────────────────

func TestResourceRemoteCodeRecorded(t *testing.T) {
	cm := New()
	if _, ok := cm.RemoteCode(); ok {
		t.Fatal("remote code should not be set initially")
	}
	cm.OnCloseReceived(42, "answer")
	code, ok := cm.RemoteCode()
	if !ok || code != 42 {
		t.Fatalf("expected remote code 42, got %d (ok=%v)", code, ok)
	}
}

func TestResourceRemoteMessageRecorded(t *testing.T) {
	cm := New()
	if _, ok := cm.RemoteMessage(); ok {
		t.Fatal("remote message should not be set initially")
	}
	cm.OnCloseReceived(0, "goodbye")
	msg, ok := cm.RemoteMessage()
	if !ok || msg != "goodbye" {
		t.Fatalf("expected 'goodbye', got %q (ok=%v)", msg, ok)
	}
}

func TestResourceRemoteStateNotClearedOnDuplicate(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(1, "first")
	cm.OnCloseReceived(2, "second")
	code, _ := cm.RemoteCode()
	if code != 1 {
		t.Fatalf("first code should be preserved, got %d", code)
	}
	msg, _ := cm.RemoteMessage()
	if msg != "first" {
		t.Fatalf("first message should be preserved, got %q", msg)
	}
}

func TestResourceRemoteStateRecordedInCrossedClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "local")
	cm.OnCloseReceived(99, "peer")
	code, _ := cm.RemoteCode()
	if code != 99 {
		t.Fatalf("expected 99, got %d", code)
	}
	msg, _ := cm.RemoteMessage()
	if msg != "peer" {
		t.Fatalf("expected 'peer', got %q", msg)
	}
}

// ── No resource leak after close ──────────────────────────────────

func TestResourceNoLeakAfterGracefulClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnCloseReceived(0, "ack")
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestResourceNoLeakAfterTimeout(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	cm.OnTimeout()
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

func TestResourceNoLeakAfterAbort(t *testing.T) {
	cm := New()
	cm.Abort()
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

func TestResourceNoLeakAfterFatalError(t *testing.T) {
	cm := New()
	cm.OnFatalErrorReceived()
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

func TestResourceNoLeakAfterTransportReset(t *testing.T) {
	cm := New()
	cm.OnTransportReset()
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

// ── CloseManager is reusable (drop and recreate) ──────────────────

func TestResourceDropAndRecreate(t *testing.T) {
	for i := 0; i < 1000; i++ {
		cm := New()
		cm.InitiateClose(0, fmt.Sprintf("cycle-%d", i))
		cm.OnCloseReceived(0, "ack")
	}
	// No panic, no resource exhaustion.
}

// ── Timer deadline is in the future ───────────────────────────────

func TestResourceDeadlineInFutureOnInitiate(t *testing.T) {
	cm := New()
	before := time.Now()
	cm.InitiateClose(0, "bye")
	deadline, ok := cm.Deadline()
	if !ok {
		t.Fatal("deadline should be set")
	}
	if !deadline.After(before) {
		t.Fatal("deadline should be in the future")
	}
	if deadline.After(before.Add(6 * time.Second)) {
		t.Fatal("deadline should be ~5s from now")
	}
}

func TestResourceDeadlineInFutureOnRemoteClose(t *testing.T) {
	cm := New()
	before := time.Now()
	cm.OnCloseReceived(0, "peer")
	deadline, ok := cm.Deadline()
	if !ok {
		t.Fatal("deadline should be set")
	}
	if !deadline.After(before) {
		t.Fatal("deadline should be in the future")
	}
	if deadline.After(before.Add(6 * time.Second)) {
		t.Fatal("deadline should be ~5s from now")
	}
}

// ── Custom timeout affects deadline ───────────────────────────────

func TestResourceCustomTimeoutAffectsDeadline(t *testing.T) {
	cm, _ := NewWithTimeout(10 * time.Second)
	before := time.Now()
	cm.InitiateClose(0, "bye")
	deadline, _ := cm.Deadline()
	if !deadline.After(before.Add(9 * time.Second)) {
		t.Fatal("deadline should be ~10s from now")
	}
	if deadline.After(before.Add(11 * time.Second)) {
		t.Fatal("deadline should be ~10s from now")
	}
}

// ── State queries are consistent ──────────────────────────────────

func TestResourceStateQueriesConsistent(t *testing.T) {
	cm := New()
	if cm.IsClosed() || cm.IsClosing() {
		t.Fatal("should be neither closed nor closing initially")
	}

	cm.InitiateClose(0, "bye")
	if cm.IsClosed() || !cm.IsClosing() {
		t.Fatal("should be closing but not closed after initiate")
	}

	cm.OnCloseReceived(0, "ack")
	if !cm.IsClosed() || cm.IsClosing() {
		t.Fatal("should be closed but not closing after peer CLOSE")
	}
}

// ── CloseTimeout configuration is preserved ───────────────────────

func TestResourceTimeoutPreservedThroughLifecycle(t *testing.T) {
	cm, _ := NewWithTimeout(3 * time.Second)
	if cm.CloseTimeout() != 3*time.Second {
		t.Fatalf("expected 3s, got %v", cm.CloseTimeout())
	}
	cm.InitiateClose(0, "bye")
	if cm.CloseTimeout() != 3*time.Second {
		t.Fatalf("expected 3s, got %v", cm.CloseTimeout())
	}
	cm.OnCloseReceived(0, "ack")
	if cm.CloseTimeout() != 3*time.Second {
		t.Fatalf("expected 3s, got %v", cm.CloseTimeout())
	}
}
