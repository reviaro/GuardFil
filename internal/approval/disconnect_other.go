//go:build !linux

package approval

import (
	"context"
	"net"
)

// The supported executor is Linux. Other platforms retain request/session
// cancellation and queue limits without confusing a half-close with a hangup.
func connectionContext(parent context.Context, _ net.Conn) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
