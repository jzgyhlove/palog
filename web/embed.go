// Package web embeds the static front-end assets into the binary.
package web

import "embed"

//go:embed index.html app.js style.css
var FS embed.FS