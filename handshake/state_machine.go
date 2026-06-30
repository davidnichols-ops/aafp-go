// Package handshake implements AAFP handshake structures per RFC-0002 §5.
//
// This file implements the normative handshake state machine defined in
// RFC-0002 §5.10 (Rev 6 A-6). It tracks handshake sub-states for both
// client and server roles, enforces allowed transitions, rejects forbidden
// transitions, and handles timeouts, duplicates, and unexpected frames.
package handshake

import (
	"fmt"
	"time"
)

// Default timeouts per RFC-0002 §5.10.8.
const (
	DefaultHandshakeTimeout = 30 * time.Second
	DefaultCloseTimeout     = 5 * time.Second
	MinHandshakeTimeout     = 10 * time.Second
	MinCloseTimeout         = 1 * time.Second
)

// ClientHandshakeState represents the client-side handshake states
// per RFC-0002 §5.10.1.
type ClientHandshakeState int

const (
	ClientIdle ClientHandshakeState = iota
	ClientConnecting
	ClientChSent
	ClientShVerified
	ClientCfSent
	ClientAuthorized
	ClientMessaging
	ClientClosing
	ClientClosed
)

// String returns the RFC name for the state.
func (s ClientHandshakeState) String() string {
	switch s {
	case ClientIdle:
		return "C_IDLE"
	case ClientConnecting:
		return "C_CONNECTING"
	case ClientChSent:
		return "C_CH_SENT"
	case ClientShVerified:
		return "C_SH_VERIFIED"
	case ClientCfSent:
		return "C_CF_SENT"
	case ClientAuthorized:
		return "C_AUTHORIZED"
	case ClientMessaging:
		return "C_MESSAGING"
	case ClientClosing:
		return "C_CLOSING"
	case ClientClosed:
		return "C_CLOSED"
	default:
		return fmt.Sprintf("ClientHandshakeState(%d)", int(s))
	}
}

// IsTerminal returns true if the state is terminal (no further transitions).
func (s ClientHandshakeState) IsTerminal() bool {
	return s == ClientClosed
}

// IsHandshakeComplete returns true if the handshake is complete (post-ClientFinished).
func (s ClientHandshakeState) IsHandshakeComplete() bool {
	switch s {
	case ClientCfSent, ClientAuthorized, ClientMessaging, ClientClosing:
		return true
	}
	return false
}

// IsMessagingActive returns true if application data can flow.
func (s ClientHandshakeState) IsMessagingActive() bool {
	return s == ClientMessaging
}

// IsIdentityVerified returns true if the peer's identity has been verified.
func (s ClientHandshakeState) IsIdentityVerified() bool {
	switch s {
	case ClientShVerified, ClientCfSent, ClientAuthorized, ClientMessaging, ClientClosing:
		return true
	}
	return false
}

// CanTransitionTo checks whether a transition from s to next is valid.
func (s ClientHandshakeState) CanTransitionTo(next ClientHandshakeState) bool {
	// Forward transitions
	switch {
	case s == ClientIdle && next == ClientConnecting:
		return true
	case s == ClientConnecting && next == ClientChSent:
		return true
	case s == ClientChSent && next == ClientShVerified:
		return true
	case s == ClientShVerified && next == ClientCfSent:
		return true
	case s == ClientCfSent && next == ClientAuthorized:
		return true
	case s == ClientAuthorized && next == ClientMessaging:
		return true
	case s == ClientMessaging && next == ClientClosing:
		return true
	case s == ClientClosing && next == ClientClosed:
		return true
	}

	// Graceful shutdown from active states
	switch s {
	case ClientConnecting, ClientChSent, ClientShVerified, ClientCfSent, ClientAuthorized:
		if next == ClientClosing {
			return true
		}
	}

	// Abort from any non-terminal state
	switch s {
	case ClientIdle, ClientConnecting, ClientChSent, ClientShVerified,
		ClientCfSent, ClientAuthorized, ClientMessaging:
		if next == ClientClosed {
			return true
		}
	}

	return false
}

// AllowedFrameTypes returns the frame type bytes allowed in this state.
//
// Per RFC-0002 §5.10.7. ERROR frames are allowed in all non-terminal,
// non-idle states because the peer may send an error at any time.
// In Closing state, only CLOSE is accepted; all other frames are
// silently discarded (use FrameDisposition to distinguish).
func (s ClientHandshakeState) AllowedFrameTypes() []byte {
	switch s {
	case ClientChSent:
		return []byte{0x02, 0x06} // HANDSHAKE, ERROR
	case ClientShVerified, ClientCfSent:
		return []byte{0x06} // ERROR
	case ClientAuthorized, ClientMessaging:
		return []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} // DATA, RPC_REQ, RPC_RESP, CLOSE, ERROR, PING, PONG
	case ClientClosing:
		return []byte{0x05} // CLOSE
	default:
		return nil
	}
}

// ServerHandshakeState represents the server-side handshake states
// per RFC-0002 §5.10.2.
type ServerHandshakeState int

const (
	ServerListening ServerHandshakeState = iota
	ServerTransportReady
	ServerChVerified
	ServerShSent
	ServerCfVerified
	ServerAuthorized
	ServerMessaging
	ServerClosing
	ServerClosed
)

// String returns the RFC name for the state.
func (s ServerHandshakeState) String() string {
	switch s {
	case ServerListening:
		return "S_LISTENING"
	case ServerTransportReady:
		return "S_TRANSPORT_READY"
	case ServerChVerified:
		return "S_CH_VERIFIED"
	case ServerShSent:
		return "S_SH_SENT"
	case ServerCfVerified:
		return "S_CF_VERIFIED"
	case ServerAuthorized:
		return "S_AUTHORIZED"
	case ServerMessaging:
		return "S_MESSAGING"
	case ServerClosing:
		return "S_CLOSING"
	case ServerClosed:
		return "S_CLOSED"
	default:
		return fmt.Sprintf("ServerHandshakeState(%d)", int(s))
	}
}

// IsTerminal returns true if the state is terminal (no further transitions).
func (s ServerHandshakeState) IsTerminal() bool {
	return s == ServerClosed
}

// IsHandshakeComplete returns true if the handshake is complete (post-ClientFinished).
func (s ServerHandshakeState) IsHandshakeComplete() bool {
	switch s {
	case ServerCfVerified, ServerAuthorized, ServerMessaging, ServerClosing:
		return true
	}
	return false
}

// IsMessagingActive returns true if application data can flow.
func (s ServerHandshakeState) IsMessagingActive() bool {
	return s == ServerMessaging
}

// IsIdentityVerified returns true if the peer's identity has been verified.
func (s ServerHandshakeState) IsIdentityVerified() bool {
	switch s {
	case ServerChVerified, ServerShSent, ServerCfVerified,
		ServerAuthorized, ServerMessaging, ServerClosing:
		return true
	}
	return false
}

// CanTransitionTo checks whether a transition from s to next is valid.
func (s ServerHandshakeState) CanTransitionTo(next ServerHandshakeState) bool {
	// Forward transitions
	switch {
	case s == ServerListening && next == ServerTransportReady:
		return true
	case s == ServerTransportReady && next == ServerChVerified:
		return true
	case s == ServerChVerified && next == ServerShSent:
		return true
	case s == ServerShSent && next == ServerCfVerified:
		return true
	case s == ServerCfVerified && next == ServerAuthorized:
		return true
	case s == ServerAuthorized && next == ServerMessaging:
		return true
	case s == ServerMessaging && next == ServerClosing:
		return true
	case s == ServerClosing && next == ServerClosed:
		return true
	}

	// Graceful shutdown from active states
	switch s {
	case ServerTransportReady, ServerChVerified, ServerShSent,
		ServerCfVerified, ServerAuthorized:
		if next == ServerClosing {
			return true
		}
	}

	// Abort from any non-terminal state
	switch s {
	case ServerListening, ServerTransportReady, ServerChVerified,
		ServerShSent, ServerCfVerified, ServerAuthorized, ServerMessaging:
		if next == ServerClosed {
			return true
		}
	}

	return false
}

// AllowedFrameTypes returns the frame type bytes allowed in this state.
//
// Per RFC-0002 §5.10.7. ERROR frames are allowed in all non-terminal,
// non-listening states because the peer may send an error at any time.
// In Closing state, only CLOSE is accepted; all other frames are
// silently discarded (use FrameDisposition to distinguish).
func (s ServerHandshakeState) AllowedFrameTypes() []byte {
	switch s {
	case ServerTransportReady:
		return []byte{0x02, 0x06} // HANDSHAKE, ERROR
	case ServerChVerified, ServerShSent:
		return []byte{0x02, 0x06} // HANDSHAKE, ERROR
	case ServerCfVerified, ServerAuthorized:
		return []byte{0x06} // ERROR
	case ServerMessaging:
		return []byte{0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	case ServerClosing:
		return []byte{0x05} // CLOSE
	default:
		return nil
	}
}

// HandshakeRole indicates whether the state machine owner is client or server.
type HandshakeRole int

const (
	RoleClient HandshakeRole = iota
	RoleServer
)

func (r HandshakeRole) String() string {
	if r == RoleClient {
		return "client"
	}
	return "server"
}

// FrameDisposition represents the disposition of a frame received in a
// given state (RFC-0002 §5.10.7).
type FrameDisposition int

const (
	// FrameAccept: frame is allowed and should be processed.
	FrameAccept FrameDisposition = iota
	// FrameRejectWithError: frame is not allowed; send ERROR 2008 and close.
	FrameRejectWithError
	// FrameDiscardSilently: frame is not allowed but should be silently
	// discarded (Closing state). No error should be sent.
	FrameDiscardSilently
)

func (d FrameDisposition) String() string {
	switch d {
	case FrameAccept:
		return "Accept"
	case FrameRejectWithError:
		return "RejectWithError"
	case FrameDiscardSilently:
		return "DiscardSilently"
	default:
		return fmt.Sprintf("FrameDisposition(%d)", int(d))
	}
}

// HandshakeStateError is returned when an illegal state transition is attempted.
type HandshakeStateError struct {
	Role      HandshakeRole
	FromState string
	ToState   string
	Reason    string
}

func (e *HandshakeStateError) Error() string {
	return fmt.Sprintf("illegal %s handshake transition: %s → %s (%s)",
		e.Role, e.FromState, e.ToState, e.Reason)
}

// UnexpectedFrameError is returned when an unexpected frame is received.
type UnexpectedFrameError struct {
	CurrentState string
	FrameType    byte
	Allowed      []byte
}

func (e *UnexpectedFrameError) Error() string {
	return fmt.Sprintf("unexpected frame type 0x%02X in state %s (allowed: %v)",
		e.FrameType, e.CurrentState, e.Allowed)
}

// HandshakeTimeoutError is returned when a timeout occurs.
type HandshakeTimeoutError struct {
	State   string
	Elapsed time.Duration
	Limit   time.Duration
}

func (e *HandshakeTimeoutError) Error() string {
	return fmt.Sprintf("handshake timeout in state %s (%s > %s limit)",
		e.State, e.Elapsed, e.Limit)
}

// DuplicateHandshakeMessageError is returned when a duplicate handshake message is received.
type DuplicateHandshakeMessageError struct {
	State       string
	MessageType string
}

func (e *DuplicateHandshakeMessageError) Error() string {
	return fmt.Sprintf("duplicate %s received in state %s", e.MessageType, e.State)
}

// ClientHandshakeMachine tracks the client-side handshake state machine.
type ClientHandshakeMachine struct {
	state               ClientHandshakeState
	deadline            time.Time
	hasDeadline         bool
	handshakeTimeout    time.Duration
	closeTimeout        time.Duration
	serverHelloReceived bool
}

// NewClientHandshakeMachine creates a new client state machine in the Idle state.
func NewClientHandshakeMachine() *ClientHandshakeMachine {
	return &ClientHandshakeMachine{
		state:            ClientIdle,
		handshakeTimeout: DefaultHandshakeTimeout,
		closeTimeout:     DefaultCloseTimeout,
	}
}

// WithHandshakeTimeout sets the handshake timeout (must be >= 10s).
func (m *ClientHandshakeMachine) WithHandshakeTimeout(d time.Duration) *ClientHandshakeMachine {
	if d < MinHandshakeTimeout {
		panic("handshake timeout must be >= 10s")
	}
	m.handshakeTimeout = d
	return m
}

// WithCloseTimeout sets the close timeout (must be >= 1s).
func (m *ClientHandshakeMachine) WithCloseTimeout(d time.Duration) *ClientHandshakeMachine {
	if d < MinCloseTimeout {
		panic("close timeout must be >= 1s")
	}
	m.closeTimeout = d
	return m
}

// State returns the current state.
func (m *ClientHandshakeMachine) State() ClientHandshakeState {
	return m.state
}

// IsTerminal returns true if the state machine is in a terminal state.
func (m *ClientHandshakeMachine) IsTerminal() bool {
	return m.state.IsTerminal()
}

// TransitionTo transitions to a new state. Returns error if invalid.
func (m *ClientHandshakeMachine) TransitionTo(next ClientHandshakeState) error {
	if !m.state.CanTransitionTo(next) {
		return &HandshakeStateError{
			Role:      RoleClient,
			FromState: m.state.String(),
			ToState:   next.String(),
			Reason:    "transition not allowed",
		}
	}

	// Set deadline when entering a waiting state
	switch next {
	case ClientConnecting, ClientChSent:
		m.deadline = time.Now().Add(m.handshakeTimeout)
		m.hasDeadline = true
	case ClientClosing:
		m.deadline = time.Now().Add(m.closeTimeout)
		m.hasDeadline = true
	case ClientClosed:
		m.hasDeadline = false
	}

	// Reset duplicate tracking on state change
	if next == ClientChSent {
		m.serverHelloReceived = false
	}

	m.state = next
	return nil
}

// CheckTimeout returns an error if the current state has timed out.
func (m *ClientHandshakeMachine) CheckTimeout() error {
	if !m.hasDeadline {
		return nil
	}
	if time.Now().After(m.deadline) {
		limit := m.handshakeTimeout
		if m.state == ClientClosing {
			limit = m.closeTimeout
		}
		return &HandshakeTimeoutError{
			State:   m.state.String(),
			Elapsed: time.Since(m.deadline.Add(-limit)),
			Limit:   limit,
		}
	}
	return nil
}

// CheckFrameType checks if a frame type is allowed in the current state.
func (m *ClientHandshakeMachine) CheckFrameType(ft byte) error {
	allowed := m.state.AllowedFrameTypes()
	if len(allowed) == 0 {
		return &UnexpectedFrameError{
			CurrentState: m.state.String(),
			FrameType:    ft,
			Allowed:      allowed,
		}
	}
	for _, a := range allowed {
		if a == ft {
			return nil
		}
	}
	return &UnexpectedFrameError{
		CurrentState: m.state.String(),
		FrameType:    ft,
		Allowed:      allowed,
	}
}

// FrameDisposition determines the disposition of a frame in the current
// state (RFC-0002 §5.10.7).
//
// In Closing state, non-CLOSE frames are silently discarded (not errored).
// In all other states, non-allowed frames are rejected with ERROR 2008.
func (m *ClientHandshakeMachine) FrameDisposition(ft byte) FrameDisposition {
	// In Closing state, only CLOSE is accepted; everything else is discarded
	if m.state == ClientClosing {
		if ft == 0x05 {
			return FrameAccept
		}
		return FrameDiscardSilently
	}

	// In Closed state, everything is discarded silently
	if m.state == ClientClosed {
		return FrameDiscardSilently
	}

	// In other states, use AllowedFrameTypes
	allowed := m.state.AllowedFrameTypes()
	for _, a := range allowed {
		if a == ft {
			return FrameAccept
		}
	}
	return FrameRejectWithError
}

// OnServerHelloReceived marks that a ServerHello has been received.
// Returns error if a ServerHello was already received.
func (m *ClientHandshakeMachine) OnServerHelloReceived() error {
	if m.serverHelloReceived {
		return &DuplicateHandshakeMessageError{
			State:       m.state.String(),
			MessageType: "ServerHello",
		}
	}
	m.serverHelloReceived = true
	return nil
}

// Abort transitions to Closed immediately.
func (m *ClientHandshakeMachine) Abort() error {
	return m.TransitionTo(ClientClosed)
}

// ServerHandshakeMachine tracks the server-side handshake state machine.
type ServerHandshakeMachine struct {
	state                  ServerHandshakeState
	deadline               time.Time
	hasDeadline            bool
	handshakeTimeout       time.Duration
	closeTimeout           time.Duration
	clientHelloReceived    bool
	clientFinishedReceived bool
}

// NewServerHandshakeMachine creates a new server state machine in the Listening state.
func NewServerHandshakeMachine() *ServerHandshakeMachine {
	return &ServerHandshakeMachine{
		state:            ServerListening,
		handshakeTimeout: DefaultHandshakeTimeout,
		closeTimeout:     DefaultCloseTimeout,
	}
}

// WithHandshakeTimeout sets the handshake timeout (must be >= 10s).
func (m *ServerHandshakeMachine) WithHandshakeTimeout(d time.Duration) *ServerHandshakeMachine {
	if d < MinHandshakeTimeout {
		panic("handshake timeout must be >= 10s")
	}
	m.handshakeTimeout = d
	return m
}

// WithCloseTimeout sets the close timeout (must be >= 1s).
func (m *ServerHandshakeMachine) WithCloseTimeout(d time.Duration) *ServerHandshakeMachine {
	if d < MinCloseTimeout {
		panic("close timeout must be >= 1s")
	}
	m.closeTimeout = d
	return m
}

// State returns the current state.
func (m *ServerHandshakeMachine) State() ServerHandshakeState {
	return m.state
}

// IsTerminal returns true if the state machine is in a terminal state.
func (m *ServerHandshakeMachine) IsTerminal() bool {
	return m.state.IsTerminal()
}

// TransitionTo transitions to a new state. Returns error if invalid.
func (m *ServerHandshakeMachine) TransitionTo(next ServerHandshakeState) error {
	if !m.state.CanTransitionTo(next) {
		return &HandshakeStateError{
			Role:      RoleServer,
			FromState: m.state.String(),
			ToState:   next.String(),
			Reason:    "transition not allowed",
		}
	}

	// Set deadline when entering a waiting state
	switch next {
	case ServerTransportReady, ServerShSent:
		m.deadline = time.Now().Add(m.handshakeTimeout)
		m.hasDeadline = true
	case ServerClosing:
		m.deadline = time.Now().Add(m.closeTimeout)
		m.hasDeadline = true
	case ServerClosed:
		m.hasDeadline = false
	}

	// Reset duplicate tracking on state change
	if next == ServerTransportReady {
		m.clientHelloReceived = false
		m.clientFinishedReceived = false
	}

	m.state = next
	return nil
}

// CheckTimeout returns an error if the current state has timed out.
func (m *ServerHandshakeMachine) CheckTimeout() error {
	if !m.hasDeadline {
		return nil
	}
	if time.Now().After(m.deadline) {
		limit := m.handshakeTimeout
		if m.state == ServerClosing {
			limit = m.closeTimeout
		}
		return &HandshakeTimeoutError{
			State:   m.state.String(),
			Elapsed: time.Since(m.deadline.Add(-limit)),
			Limit:   limit,
		}
	}
	return nil
}

// CheckFrameType checks if a frame type is allowed in the current state.
func (m *ServerHandshakeMachine) CheckFrameType(ft byte) error {
	allowed := m.state.AllowedFrameTypes()
	if len(allowed) == 0 {
		return &UnexpectedFrameError{
			CurrentState: m.state.String(),
			FrameType:    ft,
			Allowed:      allowed,
		}
	}
	for _, a := range allowed {
		if a == ft {
			return nil
		}
	}
	return &UnexpectedFrameError{
		CurrentState: m.state.String(),
		FrameType:    ft,
		Allowed:      allowed,
	}
}

// FrameDisposition determines the disposition of a frame in the current
// state (RFC-0002 §5.10.7).
//
// In Closing state, non-CLOSE frames are silently discarded (not errored).
// In all other states, non-allowed frames are rejected with ERROR 2008.
func (m *ServerHandshakeMachine) FrameDisposition(ft byte) FrameDisposition {
	// In Closing state, only CLOSE is accepted; everything else is discarded
	if m.state == ServerClosing {
		if ft == 0x05 {
			return FrameAccept
		}
		return FrameDiscardSilently
	}

	// In Closed state, everything is discarded silently
	if m.state == ServerClosed {
		return FrameDiscardSilently
	}

	// In other states, use AllowedFrameTypes
	allowed := m.state.AllowedFrameTypes()
	for _, a := range allowed {
		if a == ft {
			return FrameAccept
		}
	}
	return FrameRejectWithError
}

// OnClientHelloReceived marks that a ClientHello has been received.
// Returns error if a ClientHello was already received.
func (m *ServerHandshakeMachine) OnClientHelloReceived() error {
	if m.clientHelloReceived {
		return &DuplicateHandshakeMessageError{
			State:       m.state.String(),
			MessageType: "ClientHello",
		}
	}
	m.clientHelloReceived = true
	return nil
}

// OnClientFinishedReceived marks that a ClientFinished has been received.
// Returns error if a ClientFinished was already received.
func (m *ServerHandshakeMachine) OnClientFinishedReceived() error {
	if m.clientFinishedReceived {
		return &DuplicateHandshakeMessageError{
			State:       m.state.String(),
			MessageType: "ClientFinished",
		}
	}
	m.clientFinishedReceived = true
	return nil
}

// Abort transitions to Closed immediately.
func (m *ServerHandshakeMachine) Abort() error {
	return m.TransitionTo(ServerClosed)
}
