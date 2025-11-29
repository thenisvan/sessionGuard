.PHONY: clean build package install help

# Maven command
MVN := mvn

# Project info
PROJECT_NAME := AuthAnalyzer
VERSION := 1.1.14
JAR_NAME := $(PROJECT_NAME)-$(VERSION)-jar-with-dependencies.jar
TARGET_DIR := target
JAR_PATH := $(TARGET_DIR)/$(JAR_NAME)

help:
	@echo "Available targets:"
	@echo "  clean     - Remove build artifacts"
	@echo "  compile   - Compile the project"
	@echo "  package   - Build JAR with dependencies"
	@echo "  build     - Clean and build (default)"
	@echo "  install   - Build and show JAR location"
	@echo "  test      - Run tests"

clean:
	@echo "Cleaning build artifacts..."
	$(MVN) clean

compile:
	@echo "Compiling project..."
	$(MVN) compile

package:
	@echo "Packaging JAR with dependencies..."
	$(MVN) package

build: clean package
	@echo "Build complete!"
	@echo "JAR location: $(JAR_PATH)"

install: build
	@echo ""
	@echo "=========================================="
	@echo "Extension built successfully!"
	@echo "=========================================="
	@echo "JAR file: $(JAR_PATH)"
	@echo ""
	@echo "To install in Burp Suite:"
	@echo "  1. Open Burp Suite"
	@echo "  2. Go to Extensions tab"
	@echo "  3. Click 'Add' button"
	@echo "  4. Select 'Java' extension type"
	@echo "  5. Browse and select: $(abspath $(JAR_PATH))"
	@echo "=========================================="

test:
	@echo "Running tests..."
	$(MVN) test

# Default target
.DEFAULT_GOAL := build


