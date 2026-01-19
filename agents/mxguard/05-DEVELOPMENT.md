# MxGuard - Development Guide

> **Version**: 1.0
> **Date**: 2026-01-19
> **Target**: Software Engineers, Contributors

---

## Table of Contents

1. [Development Setup](#1-development-setup)
2. [Project Structure](#2-project-structure)
3. [Building from Source](#3-building-from-source)
4. [Testing](#4-testing)
5. [Code Style](#5-code-style)
6. [Contributing](#6-contributing)
7. [Release Process](#7-release-process)

---

## 1. Development Setup

### 1.1 Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Go** | 1.21+ | Primary language |
| **Git** | 2.0+ | Version control |
| **Make** | 3.81+ | Build automation |
| **Docker** | 20.10+ | Testing (optional) |
| **golangci-lint** | 1.54+ | Linting |

### 1.2 Clone Repository

```bash
# Clone repository
git clone https://github.com/mxtac/mxguard.git
cd mxguard

# Install dependencies
go mod download
go mod verify
```

### 1.3 Install Development Tools

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install staticcheck
go install honnef.co/go/tools/cmd/staticcheck@latest

# Install gofumpt (stricter gofmt)
go install mvdan.cc/gofumpt@latest

# Install test coverage tools
go install github.com/axw/gocov/gocov@latest
go install github.com/AlekSi/gocov-xml@latest
```

### 1.4 IDE Setup

**VS Code**:
```json
// .vscode/settings.json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "package",
  "go.formatTool": "gofumpt",
  "go.testFlags": ["-v", "-race"],
  "go.coverOnSave": true
}
```

**GoLand**:
- Enable Go modules: Preferences → Go → Go Modules
- Set gofumpt: Preferences → Tools → File Watchers → Add gofumpt
- Enable golangci-lint: Preferences → Tools → Go Linter → golangci-lint

---

## 2. Project Structure

```
mxguard/
├── cmd/
│   └── mxguard/
│       └── main.go              # Entry point
│
├── internal/                    # Private application code
│   ├── agent/                   # Agent orchestrator
│   ├── collectors/              # Data collectors
│   ├── ocsf/                    # OCSF event builder
│   ├── buffer/                  # Event buffering
│   ├── output/                  # Output handlers
│   ├── filter/                  # Event filtering
│   └── utils/                   # Shared utilities
│
├── pkg/                         # Public API
│   └── api/
│       └── types.go             # Public types
│
├── configs/                     # Configuration files
├── scripts/                     # Build/test scripts
├── deployments/                 # Service definitions
├── docs/                        # Documentation
├── tests/                       # Test files
│
├── go.mod                       # Go module definition
├── go.sum                       # Dependency checksums
├── Makefile                     # Build automation
└── README.md                    # Project README
```

### 2.1 Package Design Principles

1. **internal/**: Private code, not importable by external projects
2. **pkg/**: Public API for other projects
3. **cmd/**: Application entry points
4. **Use interfaces**: For testability and modularity
5. **Dependency injection**: Pass dependencies explicitly

---

## 3. Building from Source

### 3.1 Quick Build

```bash
# Build for current platform
make build

# Output: bin/mxguard
```

### 3.2 Cross-Platform Build

```bash
# Build for all platforms
make build-all

# Output:
# bin/mxguard-linux-amd64
# bin/mxguard-linux-arm64
# bin/mxguard-windows-amd64.exe
# bin/mxguard-darwin-amd64
# bin/mxguard-darwin-arm64
```

### 3.3 Build with Version Information

```bash
# Build with git version
make build VERSION=$(git describe --tags --always --dirty)

# Build with custom flags
go build -ldflags="-X main.version=v1.0.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/mxguard cmd/mxguard/main.go
```

### 3.4 Build Options

```makefile
# Makefile targets
make build              # Build for current platform
make build-linux        # Build for Linux (amd64, arm64)
make build-windows      # Build for Windows (amd64)
make build-darwin       # Build for macOS (amd64, arm64)
make build-all          # Build for all platforms
make clean              # Remove build artifacts
make install            # Install to /usr/local/bin
```

---

## 4. Testing

### 4.1 Unit Tests

```bash
# Run all unit tests
make test

# Run with race detector
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific package
go test -v ./internal/collectors/file/

# Run specific test
go test -v -run TestFileMonitor ./internal/collectors/file/
```

### 4.2 Integration Tests

```bash
# Run integration tests (requires elevated privileges)
make test-integration

# Or manually:
sudo go test -v -tags=integration ./tests/integration/...
```

**Example integration test**:
```go
// tests/integration/file_test.go
// +build integration

package integration

import (
    "testing"
    "time"
    "github.com/mxtac/mxguard/internal/collectors/file"
)

func TestFileMonitor_RealFilesystem(t *testing.T) {
    // Create temp directory
    tmpDir := t.TempDir()

    // Start file monitor
    fm := file.NewMonitor([]string{tmpDir})
    go fm.Start()
    defer fm.Stop()

    // Create file
    testFile := filepath.Join(tmpDir, "test.txt")
    os.WriteFile(testFile, []byte("test"), 0644)

    // Wait for event
    select {
    case event := <-fm.Events():
        if event.File.Path != testFile {
            t.Errorf("Expected event for %s, got %s", testFile, event.File.Path)
        }
    case <-time.After(5 * time.Second):
        t.Fatal("Timeout waiting for file event")
    }
}
```

### 4.3 Benchmark Tests

```bash
# Run benchmarks
go test -bench=. ./...

# Run specific benchmark
go test -bench=BenchmarkEventBuilder -benchmem ./internal/ocsf/

# Profile CPU
go test -bench=. -cpuprofile=cpu.prof ./internal/buffer/
go tool pprof cpu.prof

# Profile memory
go test -bench=. -memprofile=mem.prof ./internal/buffer/
go tool pprof mem.prof
```

**Example benchmark**:
```go
// internal/ocsf/builder_test.go
func BenchmarkEventBuilder(b *testing.B) {
    builder := NewBuilder(Product{Name: "MxGuard"}, Device{})

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = builder.BuildFileActivity(
            "Create", 1,
            FileInfo{Path: "/tmp/test.txt"},
            ActorInfo{},
        )
    }
}
```

### 4.4 Test Coverage

```bash
# Generate coverage report
make coverage

# View in browser
go tool cover -html=coverage.out

# Coverage by package
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

**Target coverage**: 80%+ for critical paths

---

## 5. Code Style

### 5.1 Go Style Guidelines

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use [Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)
- Format with `gofumpt` (stricter than `gofmt`)

```bash
# Format code
make fmt

# Or manually:
gofumpt -w .
```

### 5.2 Linting

```bash
# Run linter
make lint

# Or manually:
golangci-lint run

# Fix auto-fixable issues
golangci-lint run --fix
```

**.golangci.yml**:
```yaml
linters:
  enable:
    - gofmt
    - gofumpt
    - goimports
    - govet
    - errcheck
    - staticcheck
    - unused
    - gosimple
    - ineffassign
    - misspell
    - unconvert
    - dupl
    - gocritic
    - gocyclo
    - revive

linters-settings:
  gocyclo:
    min-complexity: 15
  dupl:
    threshold: 100
```

### 5.3 Error Handling

```go
// ✓ GOOD: Wrap errors with context
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to do something: %w", err)
}

// ✗ BAD: Lose error context
if err := doSomething(); err != nil {
    return err
}

// ✓ GOOD: Check errors explicitly
result, err := doSomething()
if err != nil {
    return nil, err
}

// ✗ BAD: Ignore errors
result, _ := doSomething()
```

### 5.4 Logging

```go
// Use structured logging
log.Info("File created",
    "path", file.Path,
    "size", file.Size,
    "hash", file.Hash,
)

// Include context
log.Error("Failed to send event",
    "error", err,
    "url", output.URL,
    "attempt", attempt,
)
```

### 5.5 Naming Conventions

```go
// ✓ GOOD: Clear, descriptive names
type FileMonitor struct { ... }
func (fm *FileMonitor) Start() error { ... }

// ✗ BAD: Unclear abbreviations
type FMon struct { ... }
func (f *FMon) St() error { ... }

// ✓ GOOD: Consistent naming
type HTTPOutput struct { ... }   // Not HttpOutput
type URLParser struct { ... }    // Not UrlParser
type IDGenerator struct { ... }  // Not IdGenerator
```

---

## 6. Contributing

### 6.1 Contribution Workflow

```bash
# 1. Fork repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/mxguard.git
cd mxguard

# 3. Add upstream remote
git remote add upstream https://github.com/mxtac/mxguard.git

# 4. Create feature branch
git checkout -b feature/my-feature

# 5. Make changes
# ... edit files ...

# 6. Run tests
make test
make lint

# 7. Commit changes
git add .
git commit -m "feat: add my feature"

# 8. Push to your fork
git push origin feature/my-feature

# 9. Create Pull Request on GitHub
```

### 6.2 Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

**Examples**:
```
feat(collectors): add Windows registry monitoring

Implements registry monitoring for Windows using RegNotifyChangeKeyValue API.
Monitors HKLM and HKCU Run keys for persistence detection.

Closes #123

---

fix(buffer): prevent buffer overflow on high event rate

Add backpressure handling to drop oldest events when buffer is full.
Prevents memory exhaustion under high load.

Fixes #456
```

### 6.3 Pull Request Guidelines

1. **One feature per PR**: Keep PRs focused
2. **Write tests**: All new code must have tests
3. **Update docs**: Update relevant documentation
4. **Pass CI**: All checks must pass
5. **Code review**: Address reviewer feedback

**PR Template**:
```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- Change 1
- Change 2

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] CI passing
```

---

## 7. Release Process

### 7.1 Versioning

Follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes (v1.0.0 → v2.0.0)
- **MINOR**: New features (v1.0.0 → v1.1.0)
- **PATCH**: Bug fixes (v1.0.0 → v1.0.1)

### 7.2 Release Checklist

```bash
# 1. Update version
export NEW_VERSION="v1.1.0"

# 2. Update CHANGELOG.md
# ... add release notes ...

# 3. Commit changes
git add CHANGELOG.md
git commit -m "chore: release $NEW_VERSION"

# 4. Create tag
git tag -a $NEW_VERSION -m "Release $NEW_VERSION"

# 5. Push tag
git push origin main
git push origin $NEW_VERSION

# 6. CI will automatically:
#    - Build binaries for all platforms
#    - Create GitHub release
#    - Upload artifacts
#    - Update package repositories
```

### 7.3 GitHub Actions Workflow

**.github/workflows/release.yml**:
```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Build binaries
        run: make build-all

      - name: Create checksums
        run: |
          cd bin/
          sha256sum * > checksums.txt

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: bin/*
          generate_release_notes: true
```

---

## Development Tools

### Makefile Reference

```makefile
.PHONY: build test lint fmt clean

# Build
build:           # Build for current platform
build-all:       # Build for all platforms
build-linux:     # Build for Linux
build-windows:   # Build for Windows
build-darwin:    # Build for macOS

# Test
test:            # Run unit tests
test-integration:# Run integration tests
test-coverage:   # Generate coverage report
benchmark:       # Run benchmarks

# Code quality
lint:            # Run linters
fmt:             # Format code
vet:             # Run go vet
staticcheck:     # Run staticcheck

# Utilities
clean:           # Remove build artifacts
install:         # Install to system
deps:            # Download dependencies
```

### Useful Scripts

**scripts/test.sh**:
```bash
#!/bin/bash
set -e

echo "Running unit tests..."
go test -v -race -coverprofile=coverage.out ./...

echo "Running integration tests..."
sudo go test -v -tags=integration ./tests/integration/...

echo "Generating coverage report..."
go tool cover -html=coverage.out -o coverage.html

echo "Coverage report: coverage.html"
```

**scripts/build.sh**:
```bash
#!/bin/bash
set -e

VERSION=$(git describe --tags --always --dirty)
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS="-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}"

for GOOS in linux windows darwin; do
  for GOARCH in amd64 arm64; do
    if [ "$GOOS" = "windows" ] && [ "$GOARCH" = "arm64" ]; then
      continue  # Skip Windows ARM64
    fi

    OUTPUT="bin/mxguard-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
      OUTPUT="${OUTPUT}.exe"
    fi

    echo "Building ${OUTPUT}..."
    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="$LDFLAGS" -o "$OUTPUT" cmd/mxguard/main.go
  done
done

echo "Build complete!"
```

---

*Development guide for contributors*
*Next: See 06-API-REFERENCE.md for API documentation*
