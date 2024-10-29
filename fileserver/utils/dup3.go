//go:build linux && arm64

package utils

import (
	"syscall"
)

func Dup(from, to int) error {
	return syscall.Dup3(from, to, 0)
}
