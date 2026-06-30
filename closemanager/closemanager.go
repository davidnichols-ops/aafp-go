// Package closemanager implements the normative CLOSE frame semantics
// defined in RFC-0002 §6.6 (Rev 6 A-8).
//
// The CloseManager is the single authority for all close-related state
// transitions on a connection. It tracks five states (Open,
// LocalCloseSent, RemoteCloseReceived, CloseReceived, Closed), enforces
// the five normative invariants from §6.6.1, and returns CloseAction
// values that tell the caller what to do (send a CLOSE frame, close the
// QUIC connection, or do nothing).
//
// # Design
//
// The CloseManager is transport-agnostic and synchronous. It does not
// own timers, QUIC connections, or streams. The caller is responsible
// for:
//
//  1. Calling OnTimeout() when the close timer fires.
//  2. Sending CLOSE frames when CloseActionSendCloseFrame is returned.
//  3. Closing the QUIC connection when CloseActionCloseQuic is returned.
//  4. Cleaning up outstanding RPCs, streams, and buffers on CloseQuic.
//
// This separation makes the CloseManager trivially testable: every
// state transition is a pure function of the current state and the
// incoming event.
package closemanager

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultCloseTimeout is the default close timeout (RFC-0002 §6.6.5).
const DefaultCloseTimeout = 5 * time.Second

// MinCloseTimeout is the minimum close timeout (RFC-0002 §6.6.5).
const MinCloseTimeout = 1 * time.Second

// MaxCloseMessageLen is the maximum close message length (RFC-0002 §6.6.12).
const MaxCloseMessageLen = 256

// CloseState represents the state of a CloseManager (RFC-0002 §6.6.1).
type CloseState int

const (
	// StateOpen: no CLOSE sent or received. Application data flows normally.
	StateOpen CloseState = iota
	// StateLocalCloseSent: local agent has sent a CLOSE frame. Awaiting peer CLOSE or timeout.
	StateLocalCloseSent
	// StateRemoteCloseReceived: remote agent has sent a CLOSE frame. Local agent should respond.
	StateRemoteCloseReceived
	// StateCloseReceived: both sides have exchanged CLOSE frames. Connection is being torn down.
	StateCloseReceived
	// StateClosed: terminal. QUIC connection has been closed.
	StateClosed
)

// String returns the RFC-0002 §6.6.1 state name.
func (s CloseState) String() string {
	switch s {
	case StateOpen:
		return "Open"
	case StateLocalCloseSent:
		return "LocalCloseSent"
	case StateRemoteCloseReceived:
		return "RemoteCloseReceived"
	case StateCloseReceived:
		return "CloseReceived"
	case StateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("CloseState(%d)", int(s))
	}
}

// IsTerminal returns true if the state is terminal (Closed).
func (s CloseState) IsTerminal() bool {
	return s == StateClosed
}

// IsClosing returns true if the connection is in any closing state
// (LocalCloseSent, RemoteCloseReceived, or CloseReceived).
func (s CloseState) IsClosing() bool {
	return s == StateLocalCloseSent ||
		s == StateRemoteCloseReceived ||
		s == StateCloseReceived
}

// CloseActionKind identifies the type of action the caller should take.
type CloseActionKind int

const (
	// ActionNone: no action needed (e.g., duplicate event, already closed).
	ActionNone CloseActionKind = iota
	// ActionSendCloseFrame: encode and send a CLOSE frame.
	ActionSendCloseFrame
	// ActionCloseQuic: close the QUIC connection.
	ActionCloseQuic
)

// CloseAction tells the caller what to do after a CloseManager event
// (RFC-0002 §6.6.10).
type CloseAction struct {
	Kind    CloseActionKind
	Code    uint32 // valid when Kind == ActionSendCloseFrame
	Message string // valid when Kind == ActionSendCloseFrame
}

// None returns a no-op CloseAction.
func None() CloseAction {
	return CloseAction{Kind: ActionNone}
}

// SendCloseFrame returns a SendCloseFrame action.
func SendCloseFrame(code uint32, message string) CloseAction {
	return CloseAction{Kind: ActionSendCloseFrame, Code: code, Message: message}
}

// CloseQuic returns a CloseQuic action.
func CloseQuic() CloseAction {
	return CloseAction{Kind: ActionCloseQuic}
}

// String returns a human-readable description of the action.
func (a CloseAction) String() string {
	switch a.Kind {
	case ActionNone:
		return "None"
	case ActionSendCloseFrame:
		return fmt.Sprintf("SendCloseFrame(code=%d, msg=%q)", a.Code, a.Message)
	case ActionCloseQuic:
		return "CloseQuic"
	default:
		return fmt.Sprintf("CloseAction(%d)", int(a.Kind))
	}
}

// CloseFrameDisposition determines how to handle an incoming frame
// during close (RFC-0002 §6.6.6).
type CloseFrameDisposition int

const (
	// DispositionAccept: frame is allowed and should be processed.
	DispositionAccept CloseFrameDisposition = iota
	// DispositionDiscardSilently: frame should be silently discarded (no ERROR sent).
	DispositionDiscardSilently
)

// String returns the disposition name.
func (d CloseFrameDisposition) String() string {
	switch d {
	case DispositionAccept:
		return "Accept"
	case DispositionDiscardSilently:
		return "DiscardSilently"
	default:
		return fmt.Sprintf("Disposition(%d)", int(d))
	}
}

// CloseManager is the normative CLOSE frame lifecycle manager
// (RFC-0002 §6.6).
//
// It is the single authority for all close-related state transitions on
// a connection. Transport-agnostic and synchronous.
type CloseManager struct {
	state         CloseState
	remoteCode    *uint32
	remoteMessage *string
	closeTimeout  time.Duration
	deadline      *time.Time
}

// New creates a new CloseManager in Open state with the default timeout.
func New() *CloseManager {
	return &CloseManager{
		state:        StateOpen,
		closeTimeout: DefaultCloseTimeout,
	}
}

// NewWithTimeout creates a CloseManager with a custom close timeout.
//
// Returns an error if the timeout is less than 1 second (§6.6.5).
func NewWithTimeout(closeTimeout time.Duration) (*CloseManager, error) {
	if closeTimeout < MinCloseTimeout {
		return nil, fmt.Errorf("close timeout must be >= 1s, got %v", closeTimeout)
	}
	return &CloseManager{
		state:        StateOpen,
		closeTimeout: closeTimeout,
	}, nil
}

// ── Queries ────────────────────────────────────────────────────────

// State returns the current state.
func (cm *CloseManager) State() CloseState {
	return cm.state
}

// IsClosed returns true if the connection is fully closed (terminal).
func (cm *CloseManager) IsClosed() bool {
	return cm.state == StateClosed
}

// IsClosing returns true if the connection is in any closing state.
func (cm *CloseManager) IsClosing() bool {
	return cm.state.IsClosing()
}

// RemoteCode returns the close code from the peer's CLOSE frame, if any.
func (cm *CloseManager) RemoteCode() (uint32, bool) {
	if cm.remoteCode != nil {
		return *cm.remoteCode, true
	}
	return 0, false
}

// RemoteMessage returns the close message from the peer's CLOSE frame, if any.
func (cm *CloseManager) RemoteMessage() (string, bool) {
	if cm.remoteMessage != nil {
		return *cm.remoteMessage, true
	}
	return "", false
}

// CloseTimeout returns the configured close timeout.
func (cm *CloseManager) CloseTimeout() time.Duration {
	return cm.closeTimeout
}

// Deadline returns the close timer deadline, if a timer is running.
func (cm *CloseManager) Deadline() (time.Time, bool) {
	if cm.deadline != nil {
		return *cm.deadline, true
	}
	return time.Time{}, false
}

// TimerActive returns true if the close timer is active.
func (cm *CloseManager) TimerActive() bool {
	return cm.deadline != nil
}

// CanSend returns whether a frame of the given type can be sent in the
// current state (RFC-0002 §6.6.1 Invariant 3, §6.6.6).
//
// Frame type constants: 0x01=DATA, 0x02=HANDSHAKE, 0x03=RPC_REQUEST,
// 0x04=RPC_RESPONSE, 0x05=CLOSE, 0x06=ERROR, 0x07=PING, 0x08=PONG.
func (cm *CloseManager) CanSend(frameType byte) bool {
	switch cm.state {
	case StateOpen:
		return true
	case StateLocalCloseSent:
		// Invariant 3: no data after CLOSE sent.
		// Only fatal ERROR is allowed as an emergency signal.
		return frameType == 0x06
	case StateRemoteCloseReceived:
		// We can send a responding CLOSE or a fatal ERROR.
		return frameType == 0x05 || frameType == 0x06
	case StateCloseReceived, StateClosed:
		return false
	default:
		return false
	}
}

// FrameDisposition returns the disposition for an incoming frame
// (RFC-0002 §6.6.6).
//
// This method never returns RejectWithError — during close, no ERROR
// frames are sent.
func (cm *CloseManager) FrameDisposition(frameType byte) CloseFrameDisposition {
	switch cm.state {
	case StateOpen:
		return DispositionAccept
	case StateLocalCloseSent:
		if frameType == 0x05 {
			return DispositionAccept
		}
		return DispositionDiscardSilently
	case StateRemoteCloseReceived:
		return DispositionDiscardSilently
	case StateCloseReceived, StateClosed:
		return DispositionDiscardSilently
	default:
		return DispositionDiscardSilently
	}
}

// ── Commands ───────────────────────────────────────────────────────

// InitiateClose starts a graceful close (RFC-0002 §6.6.2).
//
// Returns SendCloseFrame if this is the first close initiation,
// None if the close is already in progress (idempotent).
func (cm *CloseManager) InitiateClose(code uint32, message string) CloseAction {
	if cm.state != StateOpen {
		return None()
	}
	cm.state = StateLocalCloseSent
	d := time.Now().Add(cm.closeTimeout)
	cm.deadline = &d
	return SendCloseFrame(code, truncateMessage(message))
}

// OnCloseReceived processes a received CLOSE frame (RFC-0002 §6.6.3).
//
// Returns the action the caller should take.
func (cm *CloseManager) OnCloseReceived(code uint32, message string) CloseAction {
	msg := truncateMessage(message)
	switch cm.state {
	case StateOpen:
		// §6.6.3 case 1: first CLOSE from peer.
		cm.remoteCode = &code
		cm.remoteMessage = &msg
		cm.state = StateRemoteCloseReceived
		d := time.Now().Add(cm.closeTimeout)
		cm.deadline = &d
		// Caller SHOULD call RespondClose() next.
		return None()

	case StateLocalCloseSent:
		// §6.6.3 case 2: peer's responding CLOSE (or crossed CLOSE).
		cm.remoteCode = &code
		cm.remoteMessage = &msg
		cm.deadline = nil // stop timer
		cm.state = StateCloseReceived
		cm.state = StateClosed
		return CloseQuic()

	case StateRemoteCloseReceived:
		// §6.6.3 case 3: duplicate CLOSE. Silently discard.
		return None()

	case StateCloseReceived, StateClosed:
		// §6.6.3 case 4: already closed. No-op.
		return None()

	default:
		return None()
	}
}

// RespondClose sends a responding CLOSE frame after receiving the peer's
// CLOSE (RFC-0002 §6.6.3 case 1d).
//
// Only valid in RemoteCloseReceived state. Returns SendCloseFrame and
// transitions to CloseReceived → Closed.
func (cm *CloseManager) RespondClose(code uint32, message string) CloseAction {
	if cm.state != StateRemoteCloseReceived {
		return None()
	}
	cm.deadline = nil // stop timer
	cm.state = StateCloseReceived
	cm.state = StateClosed
	return SendCloseFrame(code, truncateMessage(message))
}

// OnFatalErrorReceived processes a received fatal ERROR frame
// (RFC-0002 §6.6.8).
//
// Transitions directly to Closed. No responding CLOSE is sent.
// In Closed state, this is a no-op.
func (cm *CloseManager) OnFatalErrorReceived() CloseAction {
	if cm.state == StateClosed {
		return None()
	}
	cm.deadline = nil
	cm.state = StateClosed
	return CloseQuic()
}

// OnTransportReset processes a transport reset / EOF
// (RFC-0002 §6.6.9).
//
// Transitions directly to Closed. No CLOSE is sent (transport gone).
// In Closed state, this is a no-op.
func (cm *CloseManager) OnTransportReset() CloseAction {
	if cm.state == StateClosed {
		return None()
	}
	cm.deadline = nil
	cm.state = StateClosed
	return CloseQuic()
}

// OnTimeout processes a close timer expiry (RFC-0002 §6.6.5).
//
// Force-closes the QUIC connection. Only meaningful in
// LocalCloseSent or RemoteCloseReceived states.
func (cm *CloseManager) OnTimeout() CloseAction {
	switch cm.state {
	case StateLocalCloseSent, StateRemoteCloseReceived:
		cm.deadline = nil
		cm.state = StateClosed
		return CloseQuic()
	default:
		return None()
	}
}

// Abort closes the connection immediately (RFC-0002 §5.10.10).
//
// This is an ungraceful close initiated locally. No CLOSE frame is sent.
// Transitions directly to Closed. In Closed state, this is a no-op.
func (cm *CloseManager) Abort() CloseAction {
	if cm.state == StateClosed {
		return None()
	}
	cm.deadline = nil
	cm.state = StateClosed
	return CloseQuic()
}

// CheckTimer checks if the close timer has expired and fires it if so.
//
// Convenience method for callers that poll. Returns CloseQuic if the
// timer fired, None otherwise.
func (cm *CloseManager) CheckTimer(now time.Time) CloseAction {
	if cm.deadline != nil && !now.Before(*cm.deadline) {
		return cm.OnTimeout()
	}
	return None()
}

// truncateMessage truncates a close message to MaxCloseMessageLen bytes
// (UTF-8 safe). RFC-0002 §6.6.12: implementations MAY truncate messages
// longer than 256 bytes.
func truncateMessage(s string) string {
	if len(s) <= MaxCloseMessageLen {
		return s
	}
	// Find the largest rune boundary <= MaxCloseMessageLen.
	end := MaxCloseMessageLen
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	// Verify the truncated string is valid UTF-8.
	truncated := s[:end]
	if !utf8.ValidString(truncated) {
		// Fall back to a simpler truncation.
		runes := []rune(s)
		result := make([]rune, 0, len(runes))
		total := 0
		for _, r := range runes {
			l := utf8.RuneLen(r)
			if total+l > MaxCloseMessageLen {
				break
			}
			total += l
			result = append(result, r)
		}
		return string(result)
	}
	return truncated
}

// Ensure the strings import is used (for future string utilities).
var _ = strings.HasPrefix
