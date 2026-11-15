package diode

import (
	"unsafe"
)

// GenericDataType is the data type the diodes operate on.
type GenericDataType unsafe.Pointer

// Alerter is used to report how many values were overwritten since the
// last write.
type Alerter interface {
	Alert(missed int)
}

// AlertFunc type is an adapter to allow the use of ordinary functions as
// Alert handlers.
type AlertFunc func(missed int)

// Alert calls f(missed)
func (f AlertFunc) Alert(missed int) {
	f(missed)
}

type bucket struct {
	data GenericDataType
	seq  uint64 // seq is the recorded write index at the time of writing
}
