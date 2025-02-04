# Nope

Remotely run whitelisted commands over SSH.  
**Use at your own risk**: This is a demonstration of a minimal, production-style Go application for selectively executing commands remotely. Proper security reviews and hardening are essential before real-world deployment.

---

## Overview

**Nope** exposes an HTTP API (`/execute`) that accepts a JSON payload with:

1. The remote host (reachable via SSH).
2. The command to be executed on that host.

Before execution, it checks a YAML-based allow-list (“whitelist”) to ensure that only recognized commands are allowed. Any attempts to run unlisted commands will be blocked with an HTTP 403 response. Logging, security measures, and error handling follow recommended best practices.

---

## Features

- **Whitelisting**: A YAML file (e.g., `/etc/whitelist.yaml`) containing explicitly allowed commands.
- **SSH with Key Auth**: Executes commands as `root` via SSH, using a private key file (default: `/etc/ssh-key`).
- **Structured Logging**: Uses [zap](https://github.com/uber-go/zap) for fast, structured logs.
- **Configuration via CLI**: [docopt](https://github.com/docopt/docopt.go) for intuitive command-line parsing.
- **go-bindata Support**: Optional embedding of static files (whitelist defaults, etc.).
- **Testing**: Written with the standard `testing` package plus [testify](https://github.com/stretchr/testify) for assertions.

---

## Author

[TFMV](https://github.com/TFMV)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

