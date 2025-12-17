#!/bin/bash

# TLS Certificate Generation Script for Lightweight Tunnel
# This script generates self-signed certificates for testing purposes

set -e

echo "=== Lightweight Tunnel TLS Certificate Generator ==="
echo ""
echo "⚠️  WARNING: This script generates SELF-SIGNED certificates for TESTING ONLY"
echo "⚠️  For production use, obtain proper certificates from:"
echo "    - Let's Encrypt (free, automated)"
echo "    - Your organization's Certificate Authority"
echo "    - A commercial Certificate Authority"
echo ""

# Default values
CERT_DIR="${1:-./certs}"
SERVER_NAME="${2:-localhost}"
DAYS_VALID="${3:-365}"

echo "Configuration:"
echo "  Output directory: $CERT_DIR"
echo "  Server name: $SERVER_NAME"
echo "  Validity: $DAYS_VALID days"
echo ""

# Create certificate directory
mkdir -p "$CERT_DIR"

# Generate server certificate and key
echo "Generating server certificate..."
openssl req -x509 -newkey rsa:4096 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days "$DAYS_VALID" \
    -nodes \
    -subj "/CN=$SERVER_NAME"

# Set appropriate permissions
chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"

echo ""
echo "✅ Certificates generated successfully!"
echo ""
echo "Files created:"
echo "  Server certificate: $CERT_DIR/server.crt"
echo "  Server private key: $CERT_DIR/server.key"
echo ""
echo "Usage:"
echo "  Server: sudo ./lightweight-tunnel -m server -tls -tls-cert $CERT_DIR/server.crt -tls-key $CERT_DIR/server.key"
echo "  Client: sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -tls -tls-skip-verify"
echo ""
echo "⚠️  Note: Clients must use -tls-skip-verify with self-signed certificates"
echo "⚠️  This is INSECURE and should only be used for testing"
echo ""
