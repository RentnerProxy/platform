// Package caddymodules plugs RentnerProxy's own Caddy modules into the custom
// Caddy build. xcaddy imports only this module root, so it must import every
// module package the shipped binary registers.
package caddymodules

import (
	_ "github.com/RentnerProxy/platform/core/caddy-modules/responsecache"
	_ "github.com/RentnerProxy/platform/core/caddy-modules/upstreamobserver"
)
