//go:build dependency_pins

// Package pins keeps the production gosu imports visible to go mod tidy.
// The appliance compiles the verified upstream source using this module's locks.
package pins

import (
	_ "github.com/moby/sys/user"
	_ "golang.org/x/sys/unix"
)
