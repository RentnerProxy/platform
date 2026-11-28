package caddymodules

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestRootRegistersEveryShippedModule guards the xcaddy entry point: the custom
// build imports only this package, so it must register each module the Rust
// core configures and the platform queries.
func TestRootRegistersEveryShippedModule(t *testing.T) {
	for _, id := range []string{
		"http.handlers.rentnerproxy_response_cache",
		"http.handlers.rentnerproxy_upstream",
		"admin.api.rentnerproxy",
	} {
		if _, err := caddy.GetModule(id); err != nil {
			t.Errorf("module %s is not registered: %v", id, err)
		}
	}
}
