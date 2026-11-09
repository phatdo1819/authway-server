//go:build !linux

package network

import (
	"errors"
	"log/slog"
)

// NewSystem works only on Linux: elsewhere, run with -fake-network to try the web pages.
func NewSystem(log *slog.Logger) (Network, error) {
	return nil, errors.New("the WireGuard tunnels need Linux: on this system only -fake-network works")
}
