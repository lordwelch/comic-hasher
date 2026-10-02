//go:build !unix

package main

import (
	"os"
	"os/signal"
)

func Notify(sig chan os.Signal) {
	signal.Notify(sig, os.Interrupt, os.Kill)
}
