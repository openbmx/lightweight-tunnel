.PHONY: all build clean install test help install-service

# Binary name
BINARY_NAME=lightweight-tunnel
OUTPUT_DIR=bin
SERVICE_NAME?=$(BINARY_NAME)
CONFIG_PATH?=
INSTALL_BIN_DIR=/usr/local/bin
SYSTEMD_UNIT=/etc/systemd/system/$(SERVICE_NAME).service
SERVICE_USER?=lightweight-tunnel
SERVICE_GROUP?=$(SERVICE_USER)

# Build variables
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/$(OUTPUT_DIR)
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w"

all: clean build

## build: Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(OUTPUT_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) ./cmd/$(BINARY_NAME)
	@echo "Build complete: $(GOBIN)/$(BINARY_NAME)"

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -rf $(OUTPUT_DIR)
	@echo "Clean complete"

## install: Install dependencies
install:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies installed"

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## install-service: Install systemd service (CONFIG_PATH=/path/to/config.json SERVICE_NAME=name)
install-service:
	@set -e; \
	if [ -z "$(CONFIG_PATH)" ]; then \
		echo "ERROR: CONFIG_PATH is required. Example: make install-service CONFIG_PATH=/etc/lightweight-tunnel/config.json"; \
		exit 1; \
	fi; \
	if [ "$(CONFIG_PATH)" = "${CONFIG_PATH#/}" ]; then \
		echo "ERROR: CONFIG_PATH must be an absolute path."; \
		exit 1; \
	fi; \
	if printf "%s" "$(CONFIG_PATH)" | grep -Eq '[[:space:]]'; then \
		echo "ERROR: CONFIG_PATH must not contain whitespace."; \
		exit 1; \
	fi; \
	if printf "%s" "$(CONFIG_PATH)" | grep -Eq "[;|&\\\`\\$$<>]"; then \
		echo "ERROR: CONFIG_PATH contains unsupported characters ( ; | & \` $ < > )."; \
		exit 1; \
	fi; \
	if [ -x "$(GOBIN)/$(BINARY_NAME)" ]; then \
		echo "Using existing binary at $(GOBIN)/$(BINARY_NAME)"; \
	elif command -v "$(GOCMD)" >/dev/null 2>&1; then \
		echo "Binary not found, building $(BINARY_NAME)..."; \
		$(MAKE) build; \
	else \
		echo "ERROR: $(GOBIN)/$(BINARY_NAME) not found and $(GOCMD) is not available. Please install Go or provide the prebuilt binary."; \
		exit 1; \
	fi; \
	sudo -n true >/dev/null 2>&1 || { \
		echo "Error: This target requires sudo privileges (user/group creation and systemd unit installation). Run with sudo or configure non-interactive sudo access."; \
		exit 1; \
	}; \
	if ! getent group $(SERVICE_GROUP) >/dev/null 2>&1; then \
		echo "Creating system group $(SERVICE_GROUP)..."; \
		sudo groupadd --system $(SERVICE_GROUP) || { \
			echo "Failed to create group $(SERVICE_GROUP). Please create it manually and retry."; \
			exit 1; \
		}; \
	fi; \
	if ! id -u $(SERVICE_USER) >/dev/null 2>&1; then \
		echo "Creating system user $(SERVICE_USER)..."; \
		sudo useradd \
			--system \
			--no-create-home \
			--home /nonexistent \
			--shell /usr/sbin/nologin \
			--no-user-group \
			--gid $(SERVICE_GROUP) \
			$(SERVICE_USER) || { \
			echo "Failed to create user $(SERVICE_USER). Please create it manually and retry."; \
			exit 1; \
		}; \
	fi; \
	echo "Installing binary to $(INSTALL_BIN_DIR)..."; \
	sudo install -m 755 $(GOBIN)/$(BINARY_NAME) $(INSTALL_BIN_DIR)/$(BINARY_NAME); \
	echo "Creating systemd unit $(SYSTEMD_UNIT)..."; \
	{ \
		echo "[Unit]"; \
		echo "Description=Lightweight Tunnel Service ($(SERVICE_NAME))"; \
		echo "After=network-online.target"; \
		echo "Wants=network-online.target"; \
		echo ""; \
		echo "[Service]"; \
		echo "Type=simple"; \
		echo "ExecStart=$(INSTALL_BIN_DIR)/$(BINARY_NAME) -c $(CONFIG_PATH)"; \
		echo "Restart=on-failure"; \
		echo "RestartSec=5s"; \
		echo "User=$(SERVICE_USER)"; \
		echo "Group=$(SERVICE_GROUP)"; \
		echo "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW"; \
		echo "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW"; \
		echo "NoNewPrivileges=yes"; \
		echo "# PrivateNetwork disabled because the tunnel requires host network access"; \
		echo "PrivateNetwork=no"; \
		echo "PrivateTmp=yes"; \
		echo "ProtectHome=yes"; \
		echo ""; \
		echo "[Install]"; \
		echo "WantedBy=multi-user.target"; \
	} | sudo tee $(SYSTEMD_UNIT) > /dev/null; \
	sudo systemctl daemon-reload; \
	sudo systemctl enable $(SERVICE_NAME); \
	echo "Service installed. Start it with: sudo systemctl start $(SERVICE_NAME)"

## run-server: Run as server (requires root)
run-server: build
	@echo "Running as server..."
	sudo $(GOBIN)/$(BINARY_NAME) -m server

## run-client: Run as client (requires root and SERVER_IP env var)
run-client: build
	@echo "Running as client..."
	@if [ -z "$(SERVER_IP)" ]; then \
		echo "ERROR: Please set SERVER_IP environment variable"; \
		exit 1; \
	fi
	sudo $(GOBIN)/$(BINARY_NAME) -m client -r $(SERVER_IP):9000 -t 10.0.0.2/24

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
