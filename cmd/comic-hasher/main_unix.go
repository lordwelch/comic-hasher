//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func Notify(sig chan os.Signal) {
	signal.Notify(sig, os.Interrupt, syscall.SIGABRT, syscall.SIGQUIT, syscall.SIGTERM)
}
