package resource

import (
	"context"
	"io"
	"time"
)

// ConsoleKind is how a console session reaches an instance.
type ConsoleKind int

// The console kinds a backend may offer.
const (
	consoleKindNone ConsoleKind = iota
	// ConsoleVNC is the instance's graphical display.
	ConsoleVNC
	// ConsoleSerial is the instance's first serial port.
	ConsoleSerial
)

// String returns the wire name. An unknown kind returns "".
func (k ConsoleKind) String() string {
	switch k {
	case ConsoleVNC:
		return "vnc"
	case ConsoleSerial:
		return "serial"
	case consoleKindNone:
		return ""
	default:
		return ""
	}
}

// ConsoleSession is one console connection a backend opened to an instance.
// URL is the backend's internal websocket address; it is relayed, never
// handed to the caller. The session must be opened before Expires.
type ConsoleSession struct {
	Kind    ConsoleKind
	URL     string `json:"-"`
	Expires time.Time
	// Dial opens the backend-owned transport without exporting its credentials.
	Dial func(context.Context) (ConsoleStream, error) `json:"-"`
}

// ConsoleStream preserves text and binary messages across a console relay.
// One reader and one writer may run concurrently; Close interrupts both.
type ConsoleStream interface {
	NextReader() (int, io.Reader, error)
	NextWriter(int) (io.WriteCloser, error)
	Close() error
}
