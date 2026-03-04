package consoleapi

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui
var uiFiles embed.FS

// uiFileSystem returns an http.FileSystem rooted at the embedded ui/ directory.
// All non-API GET requests are served from here, with index.html as the
// fallback so that React-Router client-side routes work correctly.
func uiFileSystem() http.Handler {
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		// This should never happen; the ui/ directory is always embedded.
		panic("consoleapi: failed to create ui sub-filesystem: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}
