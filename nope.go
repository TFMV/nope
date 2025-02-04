package nope

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// -----------------------------------------------------------------------------
// Embedded Assets (go-bindata Example)
// -----------------------------------------------------------------------------
//
// If you want to embed a default whitelist file or other static assets, you can
// do so using go-bindata or a similar tool. For demonstration, we embed a small
// default whitelist YAML file below.  (This is an example placeholder.)

//go:generate go-bindata -prefix "assets/" -o bindata.go -pkg main assets/
//
// In a real setup, create an `assets/` directory, put your `.yaml` file inside,
// then run `go generate` to produce bindata.go. For demonstration, we will just
// embed a small YAML string at compile time:

var (
	//go:embed assets/default_whitelist.yaml
	defaultWhitelistYAML []byte
)

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

// SSHRequest describes the payload for executing a whitelisted command remotely.
type SSHRequest struct {
	Host    string `json:"host"`
	Command string `json:"command"`
}

// Config holds runtime configuration loaded from CLI flags (docopt) or environment.
type Config struct {
	Port         string
	Whitelist    string
	SSHKeyPath   string
	ListenAddr   string
	LogLevel     string
	InsecureSkip bool
}

// -----------------------------------------------------------------------------
// Logging Setup
// -----------------------------------------------------------------------------

// NewLogger configures a zap.Logger using the specified log level.
func NewLogger(level string) (*zap.Logger, error) {
	// Convert the string level to a zapcore.Level
	var logLvl zapcore.Level
	if err := logLvl.UnmarshalText([]byte(level)); err != nil {
		logLvl = zapcore.InfoLevel // default if invalid
	}

	cfg := zap.Config{
		Encoding:         "json",
		Level:            zap.NewAtomicLevelAt(logLvl),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    zap.NewProductionEncoderConfig(),
	}
	return cfg.Build()
}

// -----------------------------------------------------------------------------
// Whitelist Handling
// -----------------------------------------------------------------------------

// GetWhitelist returns the set of whitelisted commands. If the configured path
// does not exist, we fall back to the embedded default.
func GetWhitelist(path string, log *zap.Logger) ([]string, error) {
	var data []byte
	var err error

	if path == "" {
		// Use embedded data
		log.Warn("Whitelist file path not provided; using default embedded whitelist")
		data = defaultWhitelistYAML
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			// As a fallback, try the embedded default
			log.Warn("Error reading whitelist file; falling back to default embedded list",
				zap.String("path", path), zap.Error(err))
			data = defaultWhitelistYAML
		}
	}

	var whitelist []string
	if err := yaml.Unmarshal(data, &whitelist); err != nil {
		return nil, fmt.Errorf("failed to unmarshal whitelist YAML: %w", err)
	}
	return whitelist, nil
}

// IsWhitelisted checks if the requested command is in the allow-list.
func IsWhitelisted(command string, whitelist []string) bool {
	for _, w := range whitelist {
		if w == command {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// SSH Execution
// -----------------------------------------------------------------------------

// sshCommand runs the specified command on a remote host using the provided key.
func sshCommand(ctx context.Context, host, command string, signer ssh.Signer) (stdout, stderr string, err error) {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		// In production, you must validate the server's host key. Use
		// ssh.FixedHostKey(...) or known_hosts checks instead.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Attempt connection
	conn, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		return "", "", fmt.Errorf("failed to SSH dial: %w", err)
	}
	defer conn.Close()

	// Open session
	session, err := conn.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Attach stdout/stderr buffers
	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	runErr := make(chan error, 1)

	// Because session.Run() is blocking, run it in a separate goroutine to allow
	// context cancellation if needed.
	go func() {
		runErr <- session.Run(command)
	}()

	select {
	case <-ctx.Done():
		// Attempt to close session if context is canceled
		_ = session.Signal(ssh.SIGKILL)
		return "", "", fmt.Errorf("context canceled before command completed: %w", ctx.Err())
	case err := <-runErr:
		return stdoutBuf.String(), stderrBuf.String(), err
	}
}

// -----------------------------------------------------------------------------
// HTTP Handler
// -----------------------------------------------------------------------------

// HandleExecute processes incoming JSON requests for remote SSH commands.
func HandleExecute(log *zap.Logger, whitelistPath, sshKeyPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sshReq SSHRequest
		if err := json.NewDecoder(r.Body).Decode(&sshReq); err != nil {
			log.Error("Failed to decode JSON request", zap.Error(err))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Load the whitelist each time for demonstration simplicity. In a real
		// system, you might cache it or watch for updates.
		whitelist, err := GetWhitelist(whitelistPath, log)
		if err != nil {
			log.Error("Error fetching command whitelist", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !IsWhitelisted(sshReq.Command, whitelist) {
			log.Warn("Attempted command not in whitelist",
				zap.String("host", sshReq.Host),
				zap.String("command", sshReq.Command))
			http.Error(w, "Command not allowed", http.StatusForbidden)
			return
		}

		keyBytes, err := os.ReadFile(sshKeyPath)
		if err != nil {
			log.Error("Error reading SSH key from file",
				zap.String("ssh_key_path", sshKeyPath), zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			log.Error("Error parsing SSH private key", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		stdout, stderr, execErr := sshCommand(ctx, sshReq.Host, sshReq.Command, signer)
		if execErr != nil {
			log.Error("SSH command execution failure",
				zap.Error(execErr),
				zap.String("host", sshReq.Host),
				zap.String("command", sshReq.Command),
				zap.String("stdout", stdout),
				zap.String("stderr", stderr),
			)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		response := map[string]string{
			"stdout": stdout,
			"stderr": stderr,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}
}

// -----------------------------------------------------------------------------
// Server Initialization
// -----------------------------------------------------------------------------

func StartServer(cfg *Config, log *zap.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/execute", HandleExecute(log, cfg.Whitelist, cfg.SSHKeyPath))

	srv := &http.Server{
		Addr:              cfg.ListenAddr + ":" + cfg.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if cfg.InsecureSkip {
		// Example: if you want to skip TLS verification for some reason,
		// set up a custom transport. Be cautious with this in production.
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		log.Warn("TLS certificate verification is disabled!")
	}

	log.Info("Server starting",
		zap.String("addr", srv.Addr),
		zap.String("log_level", cfg.LogLevel),
	)

	return srv.ListenAndServe()
}
