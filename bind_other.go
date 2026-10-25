//go:build !windows

package main

import (
	"errors"
	"net"
	"syscall"
)

const bindSupported = false

func bindControl(int) func(string, string, syscall.RawConn) error { return nil }

func physicalInterface() (*net.Interface, error) {
	return nil, errors.New("not supported on this OS")
}
