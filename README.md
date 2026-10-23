# bug-recon

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev/)
[![Security](https://img.shields.io/badge/Domain-AppSec%20%7C%20Bug%20Bounty-red?style=flat)](https://github.com/Amrit-04/bug-recon-project)
[![CLI](https://img.shields.io/badge/CLI-Reconnaissance-blue?style=flat)](https://github.com/Amrit-04/bug-recon-project)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)


A modular security reconnaissance tool for web application security testing. Built with Go, it provides subdomain enumeration, host probing, and security checks with scope enforcement and rate limiting.

## Features

- **Scope Enforcement**: YAML-based scope configuration with wildcard support and strict out-of-scope enforcement
- **Rate Limiting**: Global and per-host rate limiting to avoid detection and overloading targets
- **HTTP Client**: Custom HTTP client with scope enforcement, redirect checking, body size limiting, and dry-run mode
- **Worker Pool**: Bounded concurrency with graceful shutdown and context-based cancellation
- **Result Streaming**: JSONL output as results arrive, not buffered in memory
- **Progress Indicator**: TTY-aware progress reporting

## Architecture

The project is organized into phases:

- **Phase 1**: Foundation - Scope, Config, HTTP Client with Rate Limiting ✅
- **Phase 2**: Engine - Worker Pool, Pipeline, Result Streaming ✅
- **Phase 3**: Recon - Passive enum, DNS brute force, host probing (in progress)
- **Phase 4**: Checks - Headers, cookies, exposure, takeover, CORS, TLS
- **Phase 5**: Reporting - Markdown/HTML generation
- **Phase 6**: Integration tests, benchmarks, CI workflow

## Building

```bash
make build
```

## Running

```bash
./scoutr --help
```

## Testing

```bash
make test
```

## Development Progress

See [docs/PROGRESS.md](docs/PROGRESS.md) for detailed development progress and design decisions.
