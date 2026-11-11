package playground

import (
	_ "embed"
)

//go:embed web/index.html
var indexHTML []byte

//go:embed web/app.js
var appJS []byte

//go:embed web/app.css
var appCSS []byte
