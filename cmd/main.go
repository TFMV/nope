package main

import (
	"fmt"
	"os"

	"github.com/TFMV/nope"
	"go.uber.org/zap"
)

func main() {
	// Initialize configuration with default values
	cfg := &nope.Config{
		Port:         "8080",
		Whitelist:    "default_whitelist.yaml",
		SSHKeyPath:   "id_rsa",
		ListenAddr:   "0.0.0.0",
		LogLevel:     "info",
		InsecureSkip: false,
	}

	// Create a new logger
	log, err := nope.NewLogger(cfg.LogLevel)
	if err != nil {
		// Use fmt.Fprintf to write to stderr since log is not initialized
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}

	// Start the server
	if err := nope.StartServer(cfg, log); err != nil {
		log.Error("Failed to start server", zap.Error(err))
		os.Exit(1)
	}

	log.Info("Server started", zap.String("port", cfg.Port))
}
