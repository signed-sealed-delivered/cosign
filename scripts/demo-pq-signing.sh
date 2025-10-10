#!/usr/bin/env bash

# Demo script for cosign signing and verification with ML-DSA and classical algorithms
# This script demonstrates:
# 1. Key generation using PQCrypto KMS plugin for ML-DSA-65/87
# 2. Signing local files (blobs) with both classical and post-quantum algorithms
# 3. Verifying signatures with all algorithms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
DEMO_DIR="${DEMO_DIR:-/tmp/cosign-pq-demo}"

echo_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

echo_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo_warning() {
    echo -e "${MAGENTA}[WARNING]${NC} $1"
}

echo_section() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    echo_section "Checking Prerequisites"

    # Check if cosign is built
    if [ ! -f "$COSIGN_DIR/cosign" ]; then
        echo_error "cosign binary not found. Please run 'make cosign-pq-circl' first"
        exit 1
    fi

    # Check for KMS plugin
    echo_info "Checking for PQCrypto KMS plugin..."
    if command -v sigstore-kms-pqcrypto &> /dev/null; then
        echo_success "PQCrypto KMS plugin found"
        which sigstore-kms-pqcrypto
    else
        echo_error "Plugin not found. Please run 'make build-circl' first"
        exit 1
    fi

    echo_success "All prerequisites met"
}

# Setup demo environment
setup_demo() {
    echo_section "Setting Up Demo Environment"

    mkdir -p "$DEMO_DIR"
    cd "$DEMO_DIR"

    echo_info "Demo directory: $DEMO_DIR"

    echo "This is a test file for signing with classical algorithms" > test-classical.txt
    echo "This is a test file for signing with post-quantum algorithms" > test-pq.txt

    echo_success "Demo environment ready"
}

# Generate ECDSA keys using cosign
generate_ecdsa_keys() {
    echo_section "Generating ECDSA Keys with Cosign"

    echo_info "Generating ECDSA key pair using cosign..."
    pwd
    COSIGN_PASSWORD="" $COSIGN_DIR/cosign generate-key-pair --output-key-prefix ecdsa

    if [ -f "ecdsa.key" ] && [ -f "ecdsa.pub" ]; then
        echo_success "ECDSA key pair generated"
        echo_info "Private key: ecdsa.key ($(wc -c < ecdsa.key) bytes)"
        echo_info "Public key: ecdsa.pub ($(wc -c < ecdsa.pub) bytes)"
    else
        echo_error "Failed to generate ECDSA key pair"
        return 1
    fi
}

# Generate ML-DSA-65 keys using PQCrypto KMS plugin
generate_mldsa65_keys() {
    echo_section "Generating ML-DSA-65 Keys with PQCrypto KMS Plugin"

    echo_info "Generating ML-DSA-65 key pair using KMS plugin..."
    $COSIGN_DIR/cosign generate-key-pair --kms "pqcrypto://demo/keys/mldsa65?algorithm=ML-DSA-65" --output-key-prefix mldsa65

    if [ -f "mldsa65.pub" ]; then
        echo_success "ML-DSA-65 key pair generated"
        echo_info "Public key: mldsa65.pub ($(wc -c < mldsa65.pub) bytes)"
        echo_info "Private key stored in KMS plugin storage"
    else
        echo_error "Failed to generate ML-DSA-65 key pair"
        return 1
    fi
}

# Generate ML-DSA-87 keys using PQCrypto KMS plugin
generate_mldsa87_keys() {
    echo_section "Generating ML-DSA-87 Keys with PQCrypto KMS Plugin"

    echo_info "Generating ML-DSA-87 key pair using KMS plugin..."
    $COSIGN_DIR/cosign generate-key-pair --kms "pqcrypto://demo/keys/mldsa87?algorithm=ML-DSA-87" --output-key-prefix mldsa87

    if [ -f "mldsa87.pub" ]; then
        echo_success "ML-DSA-87 key pair generated"
        echo_info "Public key: mldsa87.pub ($(wc -c < mldsa87.pub) bytes)"
        echo_info "Private key stored in KMS plugin storage"
    else
        echo_error "Failed to generate ML-DSA-87 key pair"
        return 1
    fi
}

# Sign and verify with ECDSA using cosign
demo_ecdsa_signing() {
    echo_section "Demo 1: ECDSA Signing with Cosign"

    echo_info "Signing test-classical.txt with ECDSA using cosign..."
    COSIGN_PASSWORD="" $COSIGN_DIR/cosign sign-blob --key ecdsa.key --use-signing-config=false --tlog-upload=false test-classical.txt > test-classical.txt.ecdsa.sig

    echo_info "Verifying ECDSA signature with cosign..."
    if $COSIGN_DIR/cosign verify-blob --key ecdsa.pub --signature test-classical.txt.ecdsa.sig --insecure-ignore-tlog test-classical.txt; then
        echo_success "ECDSA signature verified with cosign"
    else
        echo_error "ECDSA signature verification failed"
        return 1
    fi

    echo_info "Signature size: $(wc -c < test-classical.txt.ecdsa.sig) bytes"
}

# Sign and verify with ML-DSA-65 using KMS plugin
demo_mldsa65_signing() {
    echo_section "Demo 2: ML-DSA-65 Signing with KMS Plugin"

    echo_info "Signing test-pq.txt with ML-DSA-65 using KMS plugin..."
    $COSIGN_DIR/cosign sign-blob --key "pqcrypto://demo/keys/mldsa65" --use-signing-config=false --tlog-upload=false test-pq.txt > test-pq.txt.mldsa65.sig

    echo_info "Verifying ML-DSA-65 signature with cosign..."
    if $COSIGN_DIR/cosign verify-blob --key mldsa65.pub --signature test-pq.txt.mldsa65.sig --insecure-ignore-tlog test-pq.txt; then
        echo_success "ML-DSA-65 signature verified with cosign"
    else
        echo_error "ML-DSA-65 signature verification failed"
        return 1
    fi

    echo_info "Signature size: $(wc -c < test-pq.txt.mldsa65.sig) bytes"
}

# Sign and verify with ML-DSA-87 using KMS plugin
demo_mldsa87_signing() {
    echo_section "Demo 3: ML-DSA-87 Signing with KMS Plugin"

    echo_info "Signing test-pq.txt with ML-DSA-87 using KMS plugin..."
    $COSIGN_DIR/cosign sign-blob --key "pqcrypto://demo/keys/mldsa87" --use-signing-config=false --tlog-upload=false test-pq.txt > test-pq.txt.mldsa87.sig

    echo_info "Verifying ML-DSA-87 signature with cosign..."
    if $COSIGN_DIR/cosign verify-blob --key mldsa87.pub --signature test-pq.txt.mldsa87.sig --insecure-ignore-tlog test-pq.txt; then
        echo_success "ML-DSA-87 signature verified with cosign"
    else
        echo_error "ML-DSA-87 signature verification failed"
        return 1
    fi

    echo_info "Signature size: $(wc -c < test-pq.txt.mldsa87.sig) bytes"
}

# Compare algorithms
compare_algorithms() {
    echo_section "Algorithm Comparison Summary"

    echo_info "Key Sizes:"
    echo ""
    echo "ECDSA:"
    echo "  Private Key:  $(wc -c < ecdsa.key) bytes"
    echo "  Public Key:   $(wc -c < ecdsa.pub) bytes"
    echo ""
    echo "ML-DSA-65:"
    echo "  Private Key:  $(wc -c < ${HOME}/.circl-keys/demo/keys/mldsa65.pem) bytes"
    echo "  Public Key:   $(wc -c < mldsa65.pub) bytes"
    echo ""
    echo "ML-DSA-87:"
    echo "  Private Key:  $(wc -c < ${HOME}/.circl-keys/demo/keys/mldsa87.pem) bytes"
    echo "  Public Key:   $(wc -c < mldsa87.pub) bytes"
    echo ""

    echo_info "Signature Sizes:"
    echo ""
    if [ -f "test-classical.txt.ecdsa.sig" ]; then
        echo "ECDSA:          $(wc -c < test-classical.txt.ecdsa.sig) bytes"
    fi
    if [ -f "test-pq.txt.mldsa65.sig" ]; then
        echo "ML-DSA-65:      $(wc -c < test-pq.txt.mldsa65.sig) bytes"
    fi
    if [ -f "test-pq.txt.mldsa87.sig" ]; then
        echo "ML-DSA-87:      $(wc -c < test-pq.txt.mldsa87.sig) bytes"
    fi
}

# Cleanup
cleanup() {
    echo_section "Cleanup"
    echo_info "Demo files are located in: $DEMO_DIR"
    echo_info "To clean up, run: rm -rf $DEMO_DIR"
}

# Main execution
main() {
    echo_section "Cosign Post-Quantum Signing Demo"
    echo_info "This script demonstrates signing with classical and post-quantum algorithms"
    echo_info "Uses Cosign with PQCrypto KMS plugin for ML-DSA key generation and signing"

    # Navigate to cosign directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    COSIGN_DIR="$SCRIPT_DIR/.."

    check_prerequisites
    setup_demo

    # Generate all keys
    generate_ecdsa_keys
    generate_mldsa65_keys
    generate_mldsa87_keys

    # Run signing demos
    demo_ecdsa_signing
    demo_mldsa65_signing
    demo_mldsa87_signing

    # Show comparison
    compare_algorithms

    cleanup
}

# Run main function
main "$@"
