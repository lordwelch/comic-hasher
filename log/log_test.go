package log

import (
	"bytes"
	"context"
	stdlog "log"
	"maps"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestFlagGroupNameSelectsEveryMember(t *testing.T) {
	oldLevels := maps.Clone(LogLevels)
	oldAliases := maps.Clone(LoggerAliases)
	t.Cleanup(func() {
		LogLevels = oldLevels
		LoggerAliases = oldAliases
	})
	metron := NewLogger("test-metron", "test-downloads")
	comicvine := NewLogger("test-comicvine", "test-downloads")

	var f Flag
	if err := f.Set("test-downloads:trace"); err != nil {
		t.Fatal(err)
	}
	for name, logger := range map[string]Logger{"metron": metron, "comicvine": comicvine} {
		if got := LogLevels[logger]; got != Trace {
			t.Fatalf("expected the downloads group to set %s to trace, got %v", name, got)
		}
	}

	// A more specific name overrides the group for that logger only.
	if err := f.Set("test-metron:standard"); err != nil {
		t.Fatal(err)
	}
	if got := LogLevels[metron]; got != Standard {
		t.Fatalf("expected metron to be standard, got %v", got)
	}
	if got := LogLevels[comicvine]; got != Trace {
		t.Fatalf("expected comicvine to stay at trace, got %v", got)
	}
}

func TestFlagALLLogger(t *testing.T) {
	oldLevels := maps.Clone(LogLevels)
	oldAliases := maps.Clone(LoggerAliases)
	t.Cleanup(func() {
		LogLevels = oldLevels
		LoggerAliases = oldAliases
	})
	_ = NewLogger("test-metron", "test-downloads")
	_ = NewLogger("test-comicvine", "test-downloads")
	var f Flag
	if err := f.Set("verbose,main:standard"); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(map[Logger]Level{defaultLogger: Standard, "test-comicvine": Verbose, "test-metron": Verbose}, LogLevels); diff != "" {
		t.Fatalf("expected ALL to set all loggers to verbose (and main set to standard),  (-want +got):\n%s", diff)
	}
}

func TestLoggerOutputChangesWithLevelAsync(t *testing.T) {
	// Snapshot the package state and restore
	synctest.Test(t, func(t *testing.T) {
		oldLevels := maps.Clone(LogLevels)
		oldAliases := maps.Clone(LoggerAliases)
		oldLogFormat := LogFormat
		oldOutput := stdlog.Writer()
		oldFlags := stdlog.Flags()
		ctx, cancel := context.WithCancel(t.Context())

		EnableNonBlocking(ctx, 15)
		t.Cleanup(func() {
			cancel()
			Diode = nil
			LogLevels = oldLevels
			LoggerAliases = oldAliases
			LogFormat = oldLogFormat
			stdlog.SetOutput(oldOutput)
			stdlog.SetFlags(oldFlags)
		})
		logger := NewLogger(t.Name())

		// Capture output of the standard logger
		var buf bytes.Buffer
		stdlog.SetOutput(&buf)
		stdlog.SetFlags(0) // Disable date/time output

		LogFormat = "{logger}: {message}"

		assertOutput := func(want string) {
			synctest.Sleep(time.Millisecond * 10) // async logger checks every 10 milliseconds
			t.Helper()
			if diff := cmp.Diff(want, buf.String()); diff != "" {
				t.Errorf("unexpected log output (-want +got):\n%s", diff)
			}
			buf.Reset()
		}
		checkLogs(t, logger, assertOutput)
	})
}

func TestLoggerOutputChangesWithLevel(t *testing.T) {
	// Snapshot the package state and restore
	oldLevels := maps.Clone(LogLevels)
	oldAliases := maps.Clone(LoggerAliases)
	oldLogFormat := LogFormat
	oldOutput := stdlog.Writer()
	oldFlags := stdlog.Flags()
	t.Cleanup(func() {
		LogLevels = oldLevels
		LoggerAliases = oldAliases
		LogFormat = oldLogFormat
		stdlog.SetOutput(oldOutput)
		stdlog.SetFlags(oldFlags)
	})

	logger := NewLogger(t.Name())

	// Capture output of the standard logger
	var buf bytes.Buffer
	stdlog.SetOutput(&buf)
	stdlog.SetFlags(0) // Disable date/time output

	LogFormat = "{logger}: {message}"

	assertOutput := func(want string) {
		t.Helper()
		if diff := cmp.Diff(want, buf.String()); diff != "" {
			t.Errorf("unexpected log output (-want +got):\n%s", diff)
		}
		buf.Reset()
	}
	checkLogs(t, logger, assertOutput)
}

func checkLogs(t *testing.T, logger Logger, assertOutput func(string)) {

	// Trace records must be emitted for a logger at the trace level.
	SetLevel(ALL, Standard)
	SetLevel(logger, Trace)
	logger.Log(Trace, "visible trace message")
	assertOutput(t.Name() + ": visible trace message\n")

	// Dropping the logger back to standard must suppress trace records again.
	SetLevel(logger, Standard)
	logger.Log(Trace, "suppressed trace message")
	assertOutput("")

	// Debug messages behave the same way: visible at debug, gone at standard.
	SetLevel(logger, Debug)
	logger.Log(Debug, "visible debug message")
	assertOutput(t.Name() + ": visible debug message\n")

	SetLevel(logger, Standard)
	logger.Log(Debug, "suppressed debug message")
	assertOutput("")

	SetLevel(ALL, Trace)
	SetLevel(logger, Standard)
	logger.Log(Trace, "logger overrides ALL")
	assertOutput("")

	// Dropping ALL back to standard must suppress the trace record again
	SetLevel(ALL, Standard)
	logger.Log(Trace, "suppressed via ALL standard message")
	assertOutput("")
}
