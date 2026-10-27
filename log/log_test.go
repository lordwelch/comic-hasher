package log

import (
	"testing"
)

func TestFlagGroupNameSelectsEveryMember(t *testing.T) {
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

func TestFlagAllLogger(t *testing.T) {
	var f Flag
	if err := f.Set("verbose,main:standard"); err != nil {
		t.Fatal(err)
	}
	if got := LogLevels[Logger("ALL")]; got != Verbose {
		t.Fatalf("expected all to set the logger to verbose, got %v", LogLevels)
	}
}
