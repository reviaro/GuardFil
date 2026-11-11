package playground

import (
	"errors"
	"net"
	"strconv"
)

var (
	// ErrInvalidAddress indicates an unparseable or out-of-range address.
	ErrInvalidAddress = errors.New("invalid address")
	// ErrNonLoopbackAddress indicates a non-loopback address when loopback is required.
	ErrNonLoopbackAddress = errors.New("non-loopback listen address disallowed without -allow-non-loopback")
)

// CheckListenAddr validates that addr is a well-formed host:port,
// and enforces loopback unless allowNonLoopback is true.
func CheckListenAddr(addr string, allowNonLoopback bool) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return ErrInvalidAddress
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return ErrInvalidAddress
	}

	if host == "" {
		if !allowNonLoopback {
			return ErrNonLoopbackAddress
		}
		return nil
	}

	if host == "localhost" {
		return nil
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() {
			return nil
		}
		if !allowNonLoopback {
			return ErrNonLoopbackAddress
		}
		return nil
	}

	if !allowNonLoopback {
		return ErrNonLoopbackAddress
	}
	return nil
}

// DisplayURL formats addr as an HTTP URL, replacing unspecified host
// bindings (empty, 0.0.0.0, or ::) with 127.0.0.1.
func DisplayURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	} else if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}
