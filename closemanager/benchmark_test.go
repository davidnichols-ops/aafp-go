package closemanager

import (
	"fmt"
	"testing"
)

func BenchmarkInitiateClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.InitiateClose(0, "goodbye")
	}
}

func BenchmarkGracefulCloseFull(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.InitiateClose(0, "goodbye")
		cm.OnCloseReceived(0, "ack")
	}
}

func BenchmarkForcedCloseAbort(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.Abort()
	}
}

func BenchmarkCloseUnderFlood1000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.InitiateClose(0, "bye")
		for j := 0; j < 1000; j++ {
			cm.OnCloseReceived(uint32(j), "flood")
		}
	}
}

func BenchmarkFrameDispositionDuringClose(b *testing.B) {
	cm := New()
	cm.InitiateClose(0, "bye")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for ft := 0; ft <= 255; ft++ {
			cm.FrameDisposition(byte(ft))
		}
	}
}

func BenchmarkCanSendDuringClose(b *testing.B) {
	cm := New()
	cm.InitiateClose(0, "bye")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for ft := 0; ft <= 255; ft++ {
			cm.CanSend(byte(ft))
		}
	}
}

func BenchmarkRespondClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.OnCloseReceived(0, "peer")
		cm.RespondClose(0, "ack")
	}
}

func BenchmarkCrossedClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.InitiateClose(0, "local")
		cm.OnCloseReceived(0, "peer")
	}
}

func BenchmarkTimeoutClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.InitiateClose(0, "bye")
		cm.OnTimeout()
	}
}

// BenchmarkCloseManagerAllocs checks allocation per graceful close.
func BenchmarkCloseManagerAllocs(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cm := New()
		cm.InitiateClose(0, fmt.Sprintf("close-%d", i))
		cm.OnCloseReceived(0, "ack")
	}
}
