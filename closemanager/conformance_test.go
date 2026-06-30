package closemanager

import (
	"strings"
	"testing"
	"time"
)

// Conformance tests for normative CLOSE frame semantics (RFC-0002 §6.6, A-8).
// Each test is tagged with its source section.

// ── §6.6.1 State Machine Transition Table ─────────────────────────

func TestR2_300_OpenToLocalCloseSentOnInitiate(t *testing.T) {
	cm := New()
	action := cm.InitiateClose(0, "goodbye")
	if action.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", action)
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
	if !cm.TimerActive() {
		t.Fatal("timer must be started on entering LocalCloseSent")
	}
}

func TestR2_301_OpenToRemoteCloseReceivedOnReceive(t *testing.T) {
	cm := New()
	action := cm.OnCloseReceived(0, "peer")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
	if !cm.TimerActive() {
		t.Fatal("timer must be started on entering RemoteCloseReceived")
	}
}

func TestR2_302_LocalCloseSentToClosedOnPeerClose(t *testing.T) {
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
		t.Fatal("timer must be stopped")
	}
}

func TestR2_303_LocalCloseSentToClosedOnTimeout(t *testing.T) {
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

func TestR2_304_LocalCloseSentDiscardNonClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08} {
		if cm.FrameDisposition(ft) != DispositionDiscardSilently {
			t.Errorf("0x%02X should be DiscardSilently", ft)
		}
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
}

func TestR2_305_RemoteCloseReceivedToClosedOnRespond(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	action := cm.RespondClose(0, "ack")
	if action.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
	if cm.TimerActive() {
		t.Fatal("timer should not be active")
	}
}

func TestR2_306_RemoteCloseReceivedToClosedOnTimeout(t *testing.T) {
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

func TestR2_307_RemoteCloseReceivedDiscardDuplicateClose(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "first")
	action := cm.OnCloseReceived(0, "second")
	if action.Kind != ActionNone {
		t.Fatalf("expected None, got %s", action)
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
}

func TestR2_308_ClosedIsTerminal(t *testing.T) {
	cm := New()
	cm.Abort()
	if cm.InitiateClose(0, "x").Kind != ActionNone {
		t.Error("InitiateClose should be None in Closed")
	}
	if cm.OnCloseReceived(0, "x").Kind != ActionNone {
		t.Error("OnCloseReceived should be None in Closed")
	}
	if cm.RespondClose(0, "x").Kind != ActionNone {
		t.Error("RespondClose should be None in Closed")
	}
	if cm.OnTimeout().Kind != ActionNone {
		t.Error("OnTimeout should be None in Closed")
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── §6.6.1 Invariants ─────────────────────────────────────────────

func TestR2_310_Invariant1AtMostOneOutboundClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "first")
	if cm.InitiateClose(0, "second").Kind != ActionNone {
		t.Error("second InitiateClose should be None")
	}
	if cm.State() != StateLocalCloseSent {
		t.Fatalf("expected LocalCloseSent, got %s", cm.State())
	}
}

func TestR2_311_Invariant2AtMostOneRespondingClose(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	a1 := cm.RespondClose(0, "ack")
	if a1.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", a1)
	}
	a2 := cm.RespondClose(0, "again")
	if a2.Kind != ActionNone {
		t.Fatalf("expected None, got %s", a2)
	}
}

func TestR2_312_Invariant3NoDataAfterCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	for _, ft := range []byte{0x01, 0x03, 0x04, 0x07, 0x08} {
		if cm.CanSend(ft) {
			t.Errorf("0x%02X must not be sendable after CLOSE sent", ft)
		}
	}
}

func TestR2_313_Invariant4TerminalIrreversible(t *testing.T) {
	cm := New()
	cm.Abort()
	cm.InitiateClose(0, "x")
	cm.OnCloseReceived(0, "x")
	cm.OnFatalErrorReceived()
	cm.OnTransportReset()
	cm.OnTimeout()
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_314_Invariant5TimerDiscipline(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	if !cm.TimerActive() {
		t.Error("timer should be active in LocalCloseSent")
	}
	cm.OnCloseReceived(0, "ack")
	if cm.TimerActive() {
		t.Error("timer should be stopped after peer CLOSE")
	}

	cm2 := New()
	cm2.OnCloseReceived(0, "peer")
	if !cm2.TimerActive() {
		t.Error("timer should be active in RemoteCloseReceived")
	}
	cm2.RespondClose(0, "ack")
	if cm2.TimerActive() {
		t.Error("timer should be stopped after respond_close")
	}
}

// ── §6.6.2 Close Initiation ───────────────────────────────────────

func TestR2_320_InitiateCloseWithCodeZero(t *testing.T) {
	cm := New()
	action := cm.InitiateClose(0, "normal shutdown")
	if action.Code != 0 || action.Message != "normal shutdown" {
		t.Fatalf("unexpected action: %s", action)
	}
}

func TestR2_321_InitiateCloseWithNonzeroCode(t *testing.T) {
	cm := New()
	action := cm.InitiateClose(1000, "going away")
	if action.Code != 1000 || action.Message != "going away" {
		t.Fatalf("unexpected action: %s", action)
	}
}

func TestR2_322_InitiateCloseTruncatesLongMessage(t *testing.T) {
	cm := New()
	longMsg := strings.Repeat("x", MaxCloseMessageLen+100)
	action := cm.InitiateClose(0, longMsg)
	if len(action.Message) > MaxCloseMessageLen {
		t.Fatalf("message not truncated: %d", len(action.Message))
	}
}

// ── §6.6.3 Close Reception ────────────────────────────────────────

func TestR2_330_ReceiveCloseFromOpenRecordsRemote(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(42, "peer reason")
	code, ok := cm.RemoteCode()
	if !ok || code != 42 {
		t.Fatalf("expected remote code 42, got %d (ok=%v)", code, ok)
	}
	msg, ok := cm.RemoteMessage()
	if !ok || msg != "peer reason" {
		t.Fatalf("expected 'peer reason', got %q (ok=%v)", msg, ok)
	}
	if cm.State() != StateRemoteCloseReceived {
		t.Fatalf("expected RemoteCloseReceived, got %s", cm.State())
	}
}

func TestR2_331_ReceiveCloseFromLocalCloseSentIsCrossed(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "local")
	cm.OnCloseReceived(0, "peer")
	code, ok := cm.RemoteCode()
	if !ok || code != 0 {
		t.Fatalf("expected remote code 0, got %d", code)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_332_ReceiveCloseDuplicatePreservesFirst(t *testing.T) {
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

// ── §6.6.4 Crossed Close ──────────────────────────────────────────

func TestR2_340_CrossedCloseGraceful(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "local")
	action := cm.OnCloseReceived(0, "peer")
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── §6.6.5 Close Timeout ──────────────────────────────────────────

func TestR2_350_DefaultTimeoutIs5s(t *testing.T) {
	cm := New()
	if cm.CloseTimeout() != 5*time.Second {
		t.Fatalf("expected 5s, got %v", cm.CloseTimeout())
	}
}

func TestR2_351_MinTimeoutIs1s(t *testing.T) {
	cm, err := NewWithTimeout(1 * time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cm.CloseTimeout() != 1*time.Second {
		t.Fatalf("expected 1s, got %v", cm.CloseTimeout())
	}
}

func TestR2_352_TimeoutBelowMinimumRejected(t *testing.T) {
	_, err := NewWithTimeout(999 * time.Millisecond)
	if err == nil {
		t.Fatal("expected error for sub-1s timeout")
	}
}

func TestR2_353_TimeoutInLocalCloseSentForcesClose(t *testing.T) {
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

func TestR2_354_TimeoutInRemoteCloseReceivedForcesClose(t *testing.T) {
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

// ── §6.6.6 Frame Disposition ──────────────────────────────────────

func TestR2_360_DispositionOpenAcceptsAll(t *testing.T) {
	cm := New()
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		if cm.FrameDisposition(ft) != DispositionAccept {
			t.Errorf("0x%02X should be Accept in Open", ft)
		}
	}
}

func TestR2_361_DispositionLocalCloseSentAcceptsOnlyClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	if cm.FrameDisposition(0x05) != DispositionAccept {
		t.Error("CLOSE should be Accept")
	}
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08} {
		if cm.FrameDisposition(ft) != DispositionDiscardSilently {
			t.Errorf("0x%02X should be DiscardSilently", ft)
		}
	}
}

func TestR2_362_DispositionNeverRejectsWithError(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
		d := cm.FrameDisposition(ft)
		if d != DispositionAccept && d != DispositionDiscardSilently {
			t.Errorf("disposition must not be RejectWithError during close (0x%02X)", ft)
		}
	}
}

// ── §6.6.8 Fatal ERROR vs CLOSE ───────────────────────────────────

func TestR2_370_FatalErrorBypassesGracefulPath(t *testing.T) {
	cm := New()
	action := cm.OnFatalErrorReceived()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_371_FatalErrorDuringLocalCloseSent(t *testing.T) {
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

// ── §6.6.9 Transport Reset ────────────────────────────────────────

func TestR2_380_TransportResetFromOpen(t *testing.T) {
	cm := New()
	action := cm.OnTransportReset()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_381_TransportResetFromLocalCloseSent(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "bye")
	action := cm.OnTransportReset()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_382_TransportResetFromRemoteCloseReceived(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	action := cm.OnTransportReset()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── §6.6.12 Security Considerations ───────────────────────────────

func TestR2_390_NoCloseAmplification(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "peer")
	a1 := cm.RespondClose(0, "ack")
	if a1.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", a1)
	}
	a2 := cm.RespondClose(0, "again")
	if a2.Kind != ActionNone {
		t.Fatalf("expected None, got %s", a2)
	}
}

func TestR2_391_DuplicateCloseNoAmplification(t *testing.T) {
	cm := New()
	cm.OnCloseReceived(0, "first")
	cm.OnCloseReceived(0, "second")
	cm.OnCloseReceived(0, "third")
	action := cm.RespondClose(0, "ack")
	if action.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", action)
	}
}

func TestR2_392_MessageTruncationUTF8Safe(t *testing.T) {
	cm := New()
	longMsg := strings.Repeat("é", 130)
	action := cm.InitiateClose(0, longMsg)
	if len(action.Message) > MaxCloseMessageLen {
		t.Fatalf("message not truncated: %d", len(action.Message))
	}
}

func TestR2_393_CloseTimerBoundsClosingDuration(t *testing.T) {
	cm, _ := NewWithTimeout(2 * time.Second)
	cm.InitiateClose(0, "bye")
	if cm.CloseTimeout() != 2*time.Second {
		t.Fatalf("expected 2s, got %v", cm.CloseTimeout())
	}
	action := cm.OnTimeout()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

// ── Full lifecycle scenarios ──────────────────────────────────────

func TestR2_395_FullClientInitiatedGracefulClose(t *testing.T) {
	cm := New()
	a1 := cm.InitiateClose(0, "goodbye")
	if a1.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", a1)
	}
	a2 := cm.OnCloseReceived(0, "ack")
	if a2.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", a2)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_396_FullServerInitiatedGracefulClose(t *testing.T) {
	cm := New()
	a1 := cm.OnCloseReceived(0, "server goodbye")
	if a1.Kind != ActionNone {
		t.Fatalf("expected None, got %s", a1)
	}
	a2 := cm.RespondClose(0, "client ack")
	if a2.Kind != ActionSendCloseFrame {
		t.Fatalf("expected SendCloseFrame, got %s", a2)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_397_FullCrossedClose(t *testing.T) {
	cm := New()
	cm.InitiateClose(0, "local")
	action := cm.OnCloseReceived(0, "peer")
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}

func TestR2_398_FullTimeoutClose(t *testing.T) {
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

func TestR2_399_FullAbortClose(t *testing.T) {
	cm := New()
	action := cm.Abort()
	if action.Kind != ActionCloseQuic {
		t.Fatalf("expected CloseQuic, got %s", action)
	}
	if cm.State() != StateClosed {
		t.Fatalf("expected Closed, got %s", cm.State())
	}
}
