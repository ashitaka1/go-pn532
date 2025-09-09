.PHONY: all build test test-unit test-integration lint lint-fix clean coverage coverage-unit coverage-integration check help reader tdd

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test

# TDD Guard detection and setup
TDDGUARD_AVAILABLE := $(shell command -v tdd-guard-go 2> /dev/null)
PROJECT_ROOT := $(PWD)

# Silent TDD wrapper that accepts all go test arguments
_tdd:
ifdef TDDGUARD_AVAILABLE
	@$(GOTEST) -json $(if $(ARGS),$(ARGS),./...) 2>&1 | tdd-guard-go -project-root $(PROJECT_ROOT)
else
	@$(GOTEST) $(if $(ARGS),$(ARGS),./...)
endif

# Default target
all: lint test build

# Build the project
build:
	@echo "Building packages..."
	$(GOBUILD) -v ./...

# Build reader binary
reader:
	@echo "Building reader..."
	$(GOBUILD) -o cmd/reader/reader ./cmd/reader

# Run all tests (unit + integration)
test: test-unit test-integration
	@echo "All tests completed!"

# Run unit tests only
test-unit:
	@echo "Running unit tests..."
	@$(MAKE) _tdd ARGS="-v -race -coverprofile=coverage-unit.txt -covermode=atomic"

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	@$(MAKE) _tdd ARGS="-v -race -tags=integration -coverprofile=coverage-integration.txt -covermode=atomic"

# Run unit tests with coverage report
coverage-unit: test-unit
	@echo "Generating unit test coverage report..."
	$(GOCMD) tool cover -html=coverage-unit.txt -o coverage-unit.html
	@echo "Unit test coverage report generated at coverage-unit.html"

# Run integration tests with coverage report
coverage-integration: test-integration
	@echo "Generating integration test coverage report..."
	$(GOCMD) tool cover -html=coverage-integration.txt -o coverage-integration.html
	@echo "Integration test coverage report generated at coverage-integration.html"

# Run both coverage reports
coverage: coverage-unit coverage-integration
	@echo "All coverage reports generated!"

# Run linters (includes formatting)
lint:
	@echo "Running linters..."
	$(GOCMD) mod tidy
	golangci-lint run ./...

# Run linters with auto-fix
lint-fix:
	@echo "Running linters with auto-fix..."
	$(GOCMD) mod tidy
	golangci-lint run --fix ./...

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@$(MAKE) _tdd ARGS="-bench=. -benchmem"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCMD) clean
	rm -f coverage*.txt coverage*.html
	rm -rf bin/ dist/ build/
	rm -f cmd/reader/reader

# Quick check before committing
check: lint test
	@echo "All checks passed!"

# Show help
help:
	@echo "go-pn532 Makefile"
	@echo "================="
	@echo ""
	@echo "Available targets:"
	@echo "  all                 - Lint, test, and build (default)"
	@echo "  build               - Build all packages"
	@echo "  reader              - Build reader binary to cmd/reader/"
	@echo "  test                - Run all tests (unit + integration)"
	@echo "  test-unit           - Run unit tests only"
	@echo "  test-integration    - Run integration tests only"
	@echo "  bench               - Run benchmarks"
	@echo "  coverage            - Generate all HTML coverage reports"
	@echo "  coverage-unit       - Generate unit test coverage report"
	@echo "  coverage-integration - Generate integration test coverage report"
	@echo "  lint                - Format code and run linters (golangci-lint)"
	@echo "  lint-fix            - Run linters with auto-fix (golangci-lint --fix)"
	@echo "  clean               - Remove build artifacts and coverage files"
	@echo "  check               - Run lint and test (pre-commit check)"
	@echo "  help                - Show this help message"
	@echo ""
	@echo "Custom arguments:"
	@echo "  Use ARGS to pass custom go test arguments"
	@echo ""
	@echo "Examples:"
	@echo "  make _tdd ARGS=\"./polling\"                    - Test polling package only"
	@echo "  make _tdd ARGS=\"-v -race ./cmd/reader\"        - Unit tests for reader with race detection"
	@echo "  make _tdd ARGS=\"-bench=. ./transport\"         - Benchmark transport package"
	@echo ""
	@echo "Note: Test commands automatically integrate with tdd-guard-go if available"
