//go:build linux && arm64

package main

import (
	"syscall"
)

func Dup(from, to int) error {
	return syscall.Dup3(from, to, 0)
}
