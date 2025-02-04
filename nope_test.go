package nope_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	nope "github.com/TFMV/nope"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestIsWhitelisted(t *testing.T) {
	wl := []string{"ls", "whoami"}
	require.True(t, nope.IsWhitelisted("ls", wl))
	require.False(t, nope.IsWhitelisted("rm -rf /", wl))
}

func TestHandleExecuteInvalidJSON(t *testing.T) {
	logger := zap.NewNop() // No-op logger for testing
	handler := nope.HandleExecute(logger, "", "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewBufferString("{invalid-json}"))
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleExecuteNotWhitelisted(t *testing.T) {
	logger := zap.NewNop()
	handler := nope.HandleExecute(logger, "", "")

	body, _ := json.Marshal(nope.SSHRequest{Host: "localhost", Command: "rm -rf /"})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewBuffer(body))
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestGetWhitelist(t *testing.T) {
	logger := zap.NewNop()

	// Should fallback to embedded if file missing
	wl, err := nope.GetWhitelist("/nonexistent/path.yaml", logger)
	require.NoError(t, err)
	require.NotEmpty(t, wl, "Expected fallback to embedded whitelist")

	// A real file test would require a fixture on disk or go-bindata mock
}
