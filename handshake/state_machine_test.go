package handshake

import (
	"testing"
	"time"
)

// === Client state machine tests ===

func TestClientInitialState(t *testing.T) {
	m := NewClientHandshakeMachine()
	if m.State() != ClientIdle {
		t.Fatalf("expected ClientIdle, got %s", m.State())
	}
	if m.IsTerminal() {
		t.Fatal("Idle should not be terminal")
	}
}

func TestClientNormalProgression(t *testing.T) {
	m := NewClientHandshakeMachine()
	steps := []ClientHandshakeState{
		ClientConnecting, ClientChSent, ClientShVerified,
		ClientCfSent, ClientAuthorized, ClientMessaging,
		ClientClosing, ClientClosed,
	}
	for _, next := range steps {
		if err := m.TransitionTo(next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if !m.IsTerminal() {
		t.Fatal("expected terminal after full progression")
	}
}

func TestClientIllegalSkipTransition(t *testing.T) {
	m := NewClientHandshakeMachine()
	err := m.TransitionTo(ClientChSent)
	if err == nil {
		t.Fatal("expected error skipping from Idle to ChSent")
	}
	hse, ok := err.(*HandshakeStateError)
	if !ok {
		t.Fatalf("expected HandshakeStateError, got %T", err)
	}
	if hse.Role != RoleClient {
		t.Fatalf("expected RoleClient, got %s", hse.Role)
	}
}

func TestClientIllegalBackwardTransition(t *testing.T) {
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	_ = m.TransitionTo(ClientChSent)
	err := m.TransitionTo(ClientConnecting)
	if err == nil {
		t.Fatal("expected error going backward")
	}
}

func TestClientAbortFromAnyState(t *testing.T) {
	// From Connecting
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	if err := m.Abort(); err != nil {
		t.Fatalf("abort from Connecting: %v", err)
	}
	if m.State() != ClientClosed {
		t.Fatalf("expected Closed, got %s", m.State())
	}

	// From ChSent
	m = NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	_ = m.TransitionTo(ClientChSent)
	if err := m.Abort(); err != nil {
		t.Fatalf("abort from ChSent: %v", err)
	}
	if m.State() != ClientClosed {
		t.Fatalf("expected Closed, got %s", m.State())
	}

	// From CfSent
	m = NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	_ = m.TransitionTo(ClientChSent)
	_ = m.TransitionTo(ClientShVerified)
	_ = m.TransitionTo(ClientCfSent)
	if err := m.Abort(); err != nil {
		t.Fatalf("abort from CfSent: %v", err)
	}
	if m.State() != ClientClosed {
		t.Fatalf("expected Closed, got %s", m.State())
	}
}

func TestClientGracefulCloseFromMessaging(t *testing.T) {
	m := NewClientHandshakeMachine()
	advanceToMessaging(t, m)
	if err := m.TransitionTo(ClientClosing); err != nil {
		t.Fatalf("transition to Closing: %v", err)
	}
	if m.State() != ClientClosing {
		t.Fatalf("expected Closing, got %s", m.State())
	}
}

func TestClientCloseFromHandshakeState(t *testing.T) {
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	if err := m.TransitionTo(ClientClosing); err != nil {
		t.Fatalf("graceful close from Connecting: %v", err)
	}
	if m.State() != ClientClosing {
		t.Fatalf("expected Closing, got %s", m.State())
	}
}

func TestClientDuplicateServerHello(t *testing.T) {
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	_ = m.TransitionTo(ClientChSent)
	if err := m.OnServerHelloReceived(); err != nil {
		t.Fatalf("first ServerHello: %v", err)
	}
	err := m.OnServerHelloReceived()
	if err == nil {
		t.Fatal("expected duplicate ServerHello error")
	}
	dup, ok := err.(*DuplicateHandshakeMessageError)
	if !ok {
		t.Fatalf("expected DuplicateHandshakeMessageError, got %T", err)
	}
	if dup.MessageType != "ServerHello" {
		t.Fatalf("expected ServerHello, got %s", dup.MessageType)
	}
}

func TestClientUnexpectedFrameInIdle(t *testing.T) {
	m := NewClientHandshakeMachine()
	err := m.CheckFrameType(0x01)
	if err == nil {
		t.Fatal("expected error for frame in Idle state")
	}
}

func TestClientAllowedFramesInMessaging(t *testing.T) {
	m := NewClientHandshakeMachine()
	advanceToMessaging(t, m)

	allowed := []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	for _, ft := range allowed {
		if err := m.CheckFrameType(ft); err != nil {
			t.Fatalf("frame 0x%02X should be allowed in Messaging: %v", ft, err)
		}
	}

	// HANDSHAKE not allowed in messaging
	err := m.CheckFrameType(0x02)
	if err == nil {
		t.Fatal("HANDSHAKE should not be allowed in Messaging")
	}
}

func TestClientHandshakeFrameOnlyInChSent(t *testing.T) {
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	_ = m.TransitionTo(ClientChSent)

	if err := m.CheckFrameType(0x02); err != nil {
		t.Fatalf("HANDSHAKE should be allowed in ChSent: %v", err)
	}

	err := m.CheckFrameType(0x01)
	if err == nil {
		t.Fatal("DATA should not be allowed in ChSent")
	}
}

func TestClientClosingOnlyAllowsClose(t *testing.T) {
	m := NewClientHandshakeMachine()
	advanceToMessaging(t, m)
	_ = m.TransitionTo(ClientClosing)

	if err := m.CheckFrameType(0x05); err != nil {
		t.Fatalf("CLOSE should be allowed in Closing: %v", err)
	}

	err := m.CheckFrameType(0x01)
	if err == nil {
		t.Fatal("DATA should not be allowed in Closing")
	}
}

func TestClientTimeoutValidation(t *testing.T) {
	m := NewClientHandshakeMachine()
	m.handshakeTimeout = 1 * time.Millisecond
	_ = m.TransitionTo(ClientConnecting)
	_ = m.TransitionTo(ClientChSent)

	time.Sleep(10 * time.Millisecond)

	err := m.CheckTimeout()
	if err == nil {
		t.Fatal("expected timeout error")
	}
	hte, ok := err.(*HandshakeTimeoutError)
	if !ok {
		t.Fatalf("expected HandshakeTimeoutError, got %T", err)
	}
	if hte.State != "C_CH_SENT" {
		t.Fatalf("expected C_CH_SENT, got %s", hte.State)
	}
}

func TestClientCustomTimeouts(t *testing.T) {
	m := NewClientHandshakeMachine().
		WithHandshakeTimeout(60 * time.Second).
		WithCloseTimeout(10 * time.Second)
	if m.handshakeTimeout != 60*time.Second {
		t.Fatalf("expected 60s, got %v", m.handshakeTimeout)
	}
	if m.closeTimeout != 10*time.Second {
		t.Fatalf("expected 10s, got %v", m.closeTimeout)
	}
}

func TestClientMinHandshakeTimeoutPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for too-short handshake timeout")
		}
	}()
	NewClientHandshakeMachine().WithHandshakeTimeout(5 * time.Second)
}

func TestClientMinCloseTimeoutPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for too-short close timeout")
		}
	}()
	NewClientHandshakeMachine().WithCloseTimeout(500 * time.Millisecond)
}

// === Server state machine tests ===

func TestServerInitialState(t *testing.T) {
	m := NewServerHandshakeMachine()
	if m.State() != ServerListening {
		t.Fatalf("expected ServerListening, got %s", m.State())
	}
	if m.IsTerminal() {
		t.Fatal("Listening should not be terminal")
	}
}

func TestServerNormalProgression(t *testing.T) {
	m := NewServerHandshakeMachine()
	steps := []ServerHandshakeState{
		ServerTransportReady, ServerChVerified, ServerShSent,
		ServerCfVerified, ServerAuthorized, ServerMessaging,
		ServerClosing, ServerClosed,
	}
	for _, next := range steps {
		if err := m.TransitionTo(next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if !m.IsTerminal() {
		t.Fatal("expected terminal after full progression")
	}
}

func TestServerIllegalSkipTransition(t *testing.T) {
	m := NewServerHandshakeMachine()
	err := m.TransitionTo(ServerChVerified)
	if err == nil {
		t.Fatal("expected error skipping from Listening to ChVerified")
	}
}

func TestServerAbortFromAnyState(t *testing.T) {
	m := NewServerHandshakeMachine()
	_ = m.TransitionTo(ServerTransportReady)
	if err := m.Abort(); err != nil {
		t.Fatalf("abort from TransportReady: %v", err)
	}
	if m.State() != ServerClosed {
		t.Fatalf("expected Closed, got %s", m.State())
	}

	m = NewServerHandshakeMachine()
	_ = m.TransitionTo(ServerTransportReady)
	_ = m.TransitionTo(ServerChVerified)
	_ = m.TransitionTo(ServerShSent)
	if err := m.Abort(); err != nil {
		t.Fatalf("abort from ShSent: %v", err)
	}
	if m.State() != ServerClosed {
		t.Fatalf("expected Closed, got %s", m.State())
	}
}

func TestServerDuplicateClientHello(t *testing.T) {
	m := NewServerHandshakeMachine()
	_ = m.TransitionTo(ServerTransportReady)
	if err := m.OnClientHelloReceived(); err != nil {
		t.Fatalf("first ClientHello: %v", err)
	}
	err := m.OnClientHelloReceived()
	if err == nil {
		t.Fatal("expected duplicate ClientHello error")
	}
}

func TestServerDuplicateClientFinished(t *testing.T) {
	m := NewServerHandshakeMachine()
	_ = m.TransitionTo(ServerTransportReady)
	_ = m.TransitionTo(ServerChVerified)
	_ = m.TransitionTo(ServerShSent)
	if err := m.OnClientFinishedReceived(); err != nil {
		t.Fatalf("first ClientFinished: %v", err)
	}
	err := m.OnClientFinishedReceived()
	if err == nil {
		t.Fatal("expected duplicate ClientFinished error")
	}
}

func TestServerHandshakeFrameOnlyInTransportReady(t *testing.T) {
	m := NewServerHandshakeMachine()
	_ = m.TransitionTo(ServerTransportReady)

	if err := m.CheckFrameType(0x02); err != nil {
		t.Fatalf("HANDSHAKE should be allowed in TransportReady: %v", err)
	}

	err := m.CheckFrameType(0x01)
	if err == nil {
		t.Fatal("DATA should not be allowed in TransportReady")
	}
}

func TestServerMessagingAllowedFrames(t *testing.T) {
	m := NewServerHandshakeMachine()
	advanceServerToMessaging(t, m)

	allowed := []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	for _, ft := range allowed {
		if err := m.CheckFrameType(ft); err != nil {
			t.Fatalf("frame 0x%02X should be allowed in Messaging: %v", ft, err)
		}
	}

	err := m.CheckFrameType(0x02)
	if err == nil {
		t.Fatal("HANDSHAKE should not be allowed in Messaging")
	}
}

func TestServerClosingOnlyAllowsClose(t *testing.T) {
	m := NewServerHandshakeMachine()
	advanceServerToMessaging(t, m)
	_ = m.TransitionTo(ServerClosing)

	if err := m.CheckFrameType(0x05); err != nil {
		t.Fatalf("CLOSE should be allowed in Closing: %v", err)
	}

	err := m.CheckFrameType(0x01)
	if err == nil {
		t.Fatal("DATA should not be allowed in Closing")
	}
}

func TestServerTimeoutValidation(t *testing.T) {
	m := NewServerHandshakeMachine()
	m.handshakeTimeout = 1 * time.Millisecond
	_ = m.TransitionTo(ServerTransportReady)

	time.Sleep(10 * time.Millisecond)

	err := m.CheckTimeout()
	if err == nil {
		t.Fatal("expected timeout error")
	}
	hte, ok := err.(*HandshakeTimeoutError)
	if !ok {
		t.Fatalf("expected HandshakeTimeoutError, got %T", err)
	}
	if hte.State != "S_TRANSPORT_READY" {
		t.Fatalf("expected S_TRANSPORT_READY, got %s", hte.State)
	}
}

// === State display tests ===

func TestClientStateDisplay(t *testing.T) {
	if ClientIdle.String() != "C_IDLE" {
		t.Fatalf("expected C_IDLE, got %s", ClientIdle.String())
	}
	if ClientChSent.String() != "C_CH_SENT" {
		t.Fatalf("expected C_CH_SENT, got %s", ClientChSent.String())
	}
	if ClientClosed.String() != "C_CLOSED" {
		t.Fatalf("expected C_CLOSED, got %s", ClientClosed.String())
	}
}

func TestServerStateDisplay(t *testing.T) {
	if ServerListening.String() != "S_LISTENING" {
		t.Fatalf("expected S_LISTENING, got %s", ServerListening.String())
	}
	if ServerTransportReady.String() != "S_TRANSPORT_READY" {
		t.Fatalf("expected S_TRANSPORT_READY, got %s", ServerTransportReady.String())
	}
	if ServerClosed.String() != "S_CLOSED" {
		t.Fatalf("expected S_CLOSED, got %s", ServerClosed.String())
	}
}

// === State property tests ===

func TestClientIsIdentityVerified(t *testing.T) {
	if ClientIdle.IsIdentityVerified() {
		t.Fatal("Idle should not be identity verified")
	}
	if ClientConnecting.IsIdentityVerified() {
		t.Fatal("Connecting should not be identity verified")
	}
	if ClientChSent.IsIdentityVerified() {
		t.Fatal("ChSent should not be identity verified")
	}
	if !ClientShVerified.IsIdentityVerified() {
		t.Fatal("ShVerified should be identity verified")
	}
	if !ClientCfSent.IsIdentityVerified() {
		t.Fatal("CfSent should be identity verified")
	}
	if !ClientMessaging.IsIdentityVerified() {
		t.Fatal("Messaging should be identity verified")
	}
}

func TestServerIsIdentityVerified(t *testing.T) {
	if ServerListening.IsIdentityVerified() {
		t.Fatal("Listening should not be identity verified")
	}
	if ServerTransportReady.IsIdentityVerified() {
		t.Fatal("TransportReady should not be identity verified")
	}
	if !ServerChVerified.IsIdentityVerified() {
		t.Fatal("ChVerified should be identity verified")
	}
	if !ServerShSent.IsIdentityVerified() {
		t.Fatal("ShSent should be identity verified")
	}
	if !ServerMessaging.IsIdentityVerified() {
		t.Fatal("Messaging should be identity verified")
	}
}

// === Helpers ===

func advanceToMessaging(t *testing.T, m *ClientHandshakeMachine) {
	t.Helper()
	steps := []ClientHandshakeState{
		ClientConnecting, ClientChSent, ClientShVerified,
		ClientCfSent, ClientAuthorized, ClientMessaging,
	}
	for _, s := range steps {
		if err := m.TransitionTo(s); err != nil {
			t.Fatalf("advance to %s: %v", s, err)
		}
	}
}

func advanceServerToMessaging(t *testing.T, m *ServerHandshakeMachine) {
	t.Helper()
	steps := []ServerHandshakeState{
		ServerTransportReady, ServerChVerified, ServerShSent,
		ServerCfVerified, ServerAuthorized, ServerMessaging,
	}
	for _, s := range steps {
		if err := m.TransitionTo(s); err != nil {
			t.Fatalf("advance to %s: %v", s, err)
		}
	}
}

// === §5.10.7 Full Frame Matrix ===

var allFrameTypes = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

const unknownFrameType byte = 0x0A

func TestR2_180ClientFullFrameMatrix(t *testing.T) {
	cases := []struct {
		state   ClientHandshakeState
		allowed []byte
	}{
		{ClientIdle, []byte{}},
		{ClientConnecting, []byte{}},
		{ClientChSent, []byte{0x02, 0x06}},
		{ClientShVerified, []byte{0x06}},
		{ClientCfSent, []byte{0x06}},
		{ClientAuthorized, []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{ClientMessaging, []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{ClientClosing, []byte{0x05}},
		{ClientClosed, []byte{}},
	}

	for _, c := range cases {
		allowed := c.state.AllowedFrameTypes()
		for _, ft := range allFrameTypes {
			expected := containsByte(c.allowed, ft)
			actual := containsByte(allowed, ft)
			if expected != actual {
				t.Errorf("client state %s: frame 0x%02X allowed mismatch: expected %v, got %v",
					c.state, ft, expected, actual)
			}
		}
		if containsByte(allowed, unknownFrameType) {
			t.Errorf("client state %s: unknown frame type should not be allowed", c.state)
		}
	}
}

func TestR2_181ServerFullFrameMatrix(t *testing.T) {
	cases := []struct {
		state   ServerHandshakeState
		allowed []byte
	}{
		{ServerListening, []byte{}},
		{ServerTransportReady, []byte{0x02, 0x06}},
		{ServerChVerified, []byte{0x02, 0x06}},
		{ServerShSent, []byte{0x02, 0x06}},
		{ServerCfVerified, []byte{0x06}},
		{ServerAuthorized, []byte{0x06}},
		{ServerMessaging, []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{ServerClosing, []byte{0x05}},
		{ServerClosed, []byte{}},
	}

	for _, c := range cases {
		allowed := c.state.AllowedFrameTypes()
		for _, ft := range allFrameTypes {
			expected := containsByte(c.allowed, ft)
			actual := containsByte(allowed, ft)
			if expected != actual {
				t.Errorf("server state %s: frame 0x%02X allowed mismatch: expected %v, got %v",
					c.state, ft, expected, actual)
			}
		}
		if containsByte(allowed, unknownFrameType) {
			t.Errorf("server state %s: unknown frame type should not be allowed", c.state)
		}
	}
}

// === §5.10.7 Frame Disposition ===

func TestR2_182ClientFrameDispositionClosing(t *testing.T) {
	m := NewClientHandshakeMachine()
	advanceToMessaging(t, m)
	if err := m.TransitionTo(ClientClosing); err != nil {
		t.Fatalf("transition to Closing: %v", err)
	}

	if m.FrameDisposition(0x05) != FrameAccept {
		t.Fatal("CLOSE should be Accept in Closing")
	}
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, unknownFrameType} {
		if m.FrameDisposition(ft) != FrameDiscardSilently {
			t.Errorf("frame 0x%02X should be DiscardSilently in Closing", ft)
		}
	}
}

func TestR2_183ServerFrameDispositionClosing(t *testing.T) {
	m := NewServerHandshakeMachine()
	advanceServerToMessaging(t, m)
	if err := m.TransitionTo(ServerClosing); err != nil {
		t.Fatalf("transition to Closing: %v", err)
	}

	if m.FrameDisposition(0x05) != FrameAccept {
		t.Fatal("CLOSE should be Accept in Closing")
	}
	for _, ft := range []byte{0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, unknownFrameType} {
		if m.FrameDisposition(ft) != FrameDiscardSilently {
			t.Errorf("frame 0x%02X should be DiscardSilently in Closing", ft)
		}
	}
}

func TestR2_184ClientFrameDispositionChSent(t *testing.T) {
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientConnecting)
	_ = m.TransitionTo(ClientChSent)

	if m.FrameDisposition(0x02) != FrameAccept {
		t.Fatal("HANDSHAKE should be Accept in ChSent")
	}
	if m.FrameDisposition(0x06) != FrameAccept {
		t.Fatal("ERROR should be Accept in ChSent")
	}
	for _, ft := range []byte{0x01, 0x03, 0x04, 0x05, 0x07, 0x08, unknownFrameType} {
		if m.FrameDisposition(ft) != FrameRejectWithError {
			t.Errorf("frame 0x%02X should be RejectWithError in ChSent", ft)
		}
	}
}

func TestR2_185ClientFrameDispositionClosed(t *testing.T) {
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientClosed)

	for _, ft := range allFrameTypes {
		if m.FrameDisposition(ft) != FrameDiscardSilently {
			t.Errorf("frame 0x%02X should be DiscardSilently in Closed", ft)
		}
	}
}

func TestR2_186ServerFrameDispositionClosed(t *testing.T) {
	m := NewServerHandshakeMachine()
	_ = m.TransitionTo(ServerClosed)

	for _, ft := range allFrameTypes {
		if m.FrameDisposition(ft) != FrameDiscardSilently {
			t.Errorf("frame 0x%02X should be DiscardSilently in Closed", ft)
		}
	}
}

// === §5.10 Terminal State Immutability ===

func TestR2_190ClientClosedNoTransitions(t *testing.T) {
	m := NewClientHandshakeMachine()
	_ = m.TransitionTo(ClientClosed)
	if !m.IsTerminal() {
		t.Fatal("Closed should be terminal")
	}

	allStates := []ClientHandshakeState{
		ClientIdle, ClientConnecting, ClientChSent, ClientShVerified,
		ClientCfSent, ClientAuthorized, ClientMessaging, ClientClosing,
	}
	for _, next := range allStates {
		if err := m.TransitionTo(next); err == nil {
			t.Errorf("transition from Closed to %s should fail", next)
		}
	}
	if err := m.TransitionTo(ClientClosed); err == nil {
		t.Fatal("Closed → Closed should fail")
	}
}

func TestR2_191ServerClosedNoTransitions(t *testing.T) {
	m := NewServerHandshakeMachine()
	_ = m.TransitionTo(ServerClosed)
	if !m.IsTerminal() {
		t.Fatal("Closed should be terminal")
	}

	allStates := []ServerHandshakeState{
		ServerListening, ServerTransportReady, ServerChVerified, ServerShSent,
		ServerCfVerified, ServerAuthorized, ServerMessaging, ServerClosing,
	}
	for _, next := range allStates {
		if err := m.TransitionTo(next); err == nil {
			t.Errorf("transition from Closed to %s should fail", next)
		}
	}
	if err := m.TransitionTo(ServerClosed); err == nil {
		t.Fatal("Closed → Closed should fail")
	}
}

// === §5.10 Property Tests: Random Transition Sequences ===

// Deterministic LCG PRNG (no external deps)
type lcg struct {
	state uint64
}

func newLCG(seed uint64) *lcg { return &lcg{state: seed} }

func (l *lcg) next() uint64 {
	l.state = l.state*6364136223846793005 + 1442695040888963407
	return l.state >> 33
}

func TestR2_200ClientPropertyRandomTransitions(t *testing.T) {
	allClientStates := []ClientHandshakeState{
		ClientIdle, ClientConnecting, ClientChSent, ClientShVerified,
		ClientCfSent, ClientAuthorized, ClientMessaging, ClientClosing,
		ClientClosed,
	}
	r := newLCG(0x1234567890ABCDEF)

	for i := 0; i < 100000; i++ {
		m := NewClientHandshakeMachine()
		numOps := int(r.next() % 20)
		for j := 0; j < numOps; j++ {
			next := allClientStates[r.next()%uint64(len(allClientStates))]
			_ = m.TransitionTo(next) // must never panic
		}
		if m.State() == ClientClosed {
			if !m.IsTerminal() {
				t.Fatal("Closed should be terminal")
			}
			for _, next := range allClientStates {
				if err := m.TransitionTo(next); err == nil {
					t.Fatal("transition from Closed should fail")
				}
			}
		}
	}
}

func TestR2_201ServerPropertyRandomTransitions(t *testing.T) {
	allServerStates := []ServerHandshakeState{
		ServerListening, ServerTransportReady, ServerChVerified, ServerShSent,
		ServerCfVerified, ServerAuthorized, ServerMessaging, ServerClosing,
		ServerClosed,
	}
	r := newLCG(0xFEDCBA0987654321)

	for i := 0; i < 100000; i++ {
		m := NewServerHandshakeMachine()
		numOps := int(r.next() % 20)
		for j := 0; j < numOps; j++ {
			next := allServerStates[r.next()%uint64(len(allServerStates))]
			_ = m.TransitionTo(next)
		}
		if m.State() == ServerClosed {
			if !m.IsTerminal() {
				t.Fatal("Closed should be terminal")
			}
			for _, next := range allServerStates {
				if err := m.TransitionTo(next); err == nil {
					t.Fatal("transition from Closed should fail")
				}
			}
		}
	}
}

func TestR2_202ClientPropertyRandomFrames(t *testing.T) {
	r := newLCG(0xDEADBEEFCAFEBABE)
	allFrames := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A}
	progression := []ClientHandshakeState{
		ClientConnecting, ClientChSent, ClientShVerified,
		ClientCfSent, ClientAuthorized, ClientMessaging,
		ClientClosing, ClientClosed,
	}

	for i := 0; i < 100000; i++ {
		m := NewClientHandshakeMachine()
		numTransitions := int(r.next() % 8)
		for j := 0; j < numTransitions; j++ {
			_ = m.TransitionTo(progression[j])
		}
		for j := 0; j < 10; j++ {
			ft := allFrames[r.next()%uint64(len(allFrames))]
			_ = m.CheckFrameType(ft)   // must never panic
			_ = m.FrameDisposition(ft) // must never panic
		}
	}
}

func TestR2_203ServerPropertyRandomFrames(t *testing.T) {
	r := newLCG(0xABCDEF0123456789)
	allFrames := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0A}
	progression := []ServerHandshakeState{
		ServerTransportReady, ServerChVerified, ServerShSent,
		ServerCfVerified, ServerAuthorized, ServerMessaging,
		ServerClosing, ServerClosed,
	}

	for i := 0; i < 100000; i++ {
		m := NewServerHandshakeMachine()
		numTransitions := int(r.next() % 8)
		for j := 0; j < numTransitions; j++ {
			_ = m.TransitionTo(progression[j])
		}
		for j := 0; j < 10; j++ {
			ft := allFrames[r.next()%uint64(len(allFrames))]
			_ = m.CheckFrameType(ft)
			_ = m.FrameDisposition(ft)
		}
	}
}

func TestR2_204PropertyDuplicateDetectionIdempotent(t *testing.T) {
	for i := 0; i < 10000; i++ {
		m := NewClientHandshakeMachine()
		_ = m.TransitionTo(ClientConnecting)
		_ = m.TransitionTo(ClientChSent)
		_ = m.OnServerHelloReceived()
		if err := m.OnServerHelloReceived(); err == nil {
			t.Fatal("second OnServerHelloReceived should fail")
		}
	}
	for i := 0; i < 10000; i++ {
		m := NewServerHandshakeMachine()
		_ = m.TransitionTo(ServerTransportReady)
		_ = m.OnClientHelloReceived()
		if err := m.OnClientHelloReceived(); err == nil {
			t.Fatal("second OnClientHelloReceived should fail")
		}
	}
}

// === Helpers ===

func containsByte(slice []byte, b byte) bool {
	for _, v := range slice {
		if v == b {
			return true
		}
	}
	return false
}
