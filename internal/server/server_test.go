package server

import (
	"net/http"
	"testing"
)

func TestListenerBounds(t *testing.T) {
	srv := newHTTPServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("unbounded listener: header %s read %s write %s idle %s", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
