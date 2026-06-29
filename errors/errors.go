// Package errors defines AAFP protocol error codes per RFC-0005.
package errors

// Error codes from RFC-0005 §3.
const (
	OK                          = 0
	Partial                     = 1
	NotFound                    = 2

	ConnectionReset             = 1001
	ConnectionTimeout           = 1002
	StreamClosed                = 1003
	StreamReset                 = 1004
	FlowControlError            = 1005
	TransportUnreachable        = 1006
	TransportRefused            = 1007

	InvalidSignature            = 2001
	IdentityExpired             = 2002
	UnknownAgent                = 2003
	VersionMismatch              = 2004
	UnsupportedExtensions       = 2005
	HandshakeFailed             = 2006
	InvalidAgentId              = 2007
	NonceReuse                  = 2008
	ReceiverMacInvalid          = 2009
	UnsupportedAlgorithm        = 2010

	Unauthorized                = 3001
	InsufficientCapability      = 3002
	DelegationChainInvalid      = 3003
	TokenExpired                = 3004
	TokenRevoked                = 3005
	DelegationDepthExceeded     = 3006

	DhtError                    = 4001
	BootstrapFailed             = 4002
	RecordInvalid               = 4003
	RecordExpired               = 4004
	CapabilityNotFound          = 4005
	AnnouncementRejected        = 4006

	MalformedFrame              = 5001
	UnknownMethod               = 5002
	SerializationError          = 5003
	MethodParamsInvalid         = 5004
	MessageTooLarge             = 5005
	StreamNotFound              = 5006

	NegotiationFailed           = 6001
	Incompatible                = 6002
	UnsupportedCapability       = 6003
	CapabilityOverloaded        = 6004

	FrameTooLarge               = 8001
	UnexpectedCompression       = 8002
	HandshakeOnWrongStream      = 8003
	UnknownCriticalFrameType    = 8004
	UnknownCriticalExtension    = 8005
	InvalidVersion              = 8006
	InvalidFlags                = 8007
	ReservedFieldNonzero        = 8008
	ProtocolViolation           = 8009
)

// IsAlwaysFatal returns true for error codes that are always fatal per
// RFC-0005 §4.4.
func IsAlwaysFatal(code uint32) bool {
	// All 2xxx (Authentication) errors are always fatal
	if code >= 2000 && code <= 2999 {
		return true
	}
	switch code {
	case UnknownCriticalFrameType,
		UnknownCriticalExtension,
		InvalidVersion,
		ProtocolViolation:
		return true
	}
	return false
}
