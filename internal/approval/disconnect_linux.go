//go:build linux

package approval

import (
	"context"
	"net"
	"syscall"
)

// Unix clients may half-close their write side to delimit a request. Only a
// full hangup cancels a hold; treating ordinary read EOF as disconnect would
// break those clients. epoll observes hangup without consuming protocol bytes.
func connectionContext(parent context.Context, conn net.Conn) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return ctx, cancel
	}
	raw, err := u.SyscallConn()
	if err != nil {
		cancel()
		return ctx, cancel
	}
	ep, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		cancel()
		return ctx, cancel
	}
	var ctlErr error
	err = raw.Control(func(fd uintptr) {
		ctlErr = syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, int(fd), &syscall.EpollEvent{Events: syscall.EPOLLHUP | syscall.EPOLLERR, Fd: int32(fd)})
	})
	if err != nil || ctlErr != nil {
		syscall.Close(ep)
		cancel()
		return ctx, cancel
	}
	go func() {
		defer syscall.Close(ep)
		events := make([]syscall.EpollEvent, 1)
		for ctx.Err() == nil {
			n, err := syscall.EpollWait(ep, events, 50)
			if err == syscall.EINTR {
				continue
			}
			if err != nil || n > 0 {
				cancel()
				return
			}
		}
	}()
	return ctx, cancel
}
