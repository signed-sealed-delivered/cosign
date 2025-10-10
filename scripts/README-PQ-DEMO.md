# Cosign Post-Quantum Signing Demo

This directory contains a demonstration script showing post-quantum cryptographic algorithms alongside classical algorithms using Cosign with the PQCrypto KMS plugin.

## Overview

The demo script (`demo-pq-signing.sh`) demonstrates:

1. **Key Generation** using:
   - Cosign for ECDSA
   - PQCrypto KMS plugin for ML-DSA-65
   - PQCrypto KMS plugin for ML-DSA-87

2. **Blob Signing** with cosign using all three algorithms

3. **Signature Verification** with cosign for all generated signatures

4. **Size Comparison** of keys and signatures across algorithms

## Prerequisites

### 1. Build Cosign with PQ Support

```bash
cd <cosign-directory>
make cosign-pq-circl
```

This builds cosign with CIRCL-based post-quantum cryptography support.

### 2. Build PQCrypto KMS Plugin

```bash
cd <sigstore-kms-pqcrypto-directory>
make build-circl
```

The plugin must be available in your PATH. The demo script will check for it.

## Running the Demo

### Usage

```bash
cd <cosign-directory>
./scripts/demo-pq-signing.sh
```

### Configuration

The only customization option is currently the temporary directory used for storing the generated artifacts, this can be customized using an environment variable:

```bash
# Use a different demo directory
DEMO_DIR="/tmp/my-pq-demo" ./scripts/demo-pq-signing.sh
```

## What the Demo Does

### Phase 1: Key Generation

1. **ECDSA Keys with Cosign**
   - Generates ECDSA key pair using `cosign generate-key-pair`
   - Stores keys as `ecdsa.key` and `ecdsa.pub`

2. **ML-DSA-65 Keys with PQCrypto KMS Plugin**
   - Generates ML-DSA-65 key pair via KMS plugin
   - Private key stored in plugin storage (`~/.circl-keys/demo/keys/mldsa65.pem`)
   - Public key exported as `mldsa65.pub`

3. **ML-DSA-87 Keys with PQCrypto KMS Plugin**
   - Generates ML-DSA-87 key pair via KMS plugin
   - Private key stored in plugin storage (`~/.circl-keys/demo/keys/mldsa87.pem`)
   - Public key exported as `mldsa87.pub`

### Phase 2: Signing Demos

1. **Demo 1: ECDSA Signing with Cosign**
   - Signs `test-classical.txt` with ECDSA using `cosign sign-blob`
   - Verifies signature with `cosign verify-blob`
   - Uses local key file (`ecdsa.key`)

2. **Demo 2: ML-DSA-65 Signing with KMS Plugin**
   - Signs `test-pq.txt` with ML-DSA-65 via KMS plugin
   - Verifies signature with `cosign verify-blob`
   - Uses KMS reference: `pqcrypto://demo/keys/mldsa65`

3. **Demo 3: ML-DSA-87 Signing with KMS Plugin**
   - Signs `test-pq.txt` with ML-DSA-87 via KMS plugin
   - Verifies signature with `cosign verify-blob`
   - Uses KMS reference: `pqcrypto://demo/keys/mldsa87`

### Phase 3: Algorithm Comparison

The script also provides a comparison of:
- Key sizes (private and public) for all algorithms
- Signature sizes for each algorithm

## Generated Artifacts

After running the demo, you'll find the following in `/tmp/cosign-pq-demo/`:

### Public and Private Keys
```
ecdsa.key, ecdsa.pub                   # ECDSA key pair (local)
mldsa65.pub                            # ML-DSA-65 public key
mldsa87.pub                            # ML-DSA-87 public key
```

### Test Files
```
test-classical.txt                     # Test file for ECDSA signing
test-pq.txt                            # Test file for PQ algorithm signing
```

### Signatures
```
test-classical.txt.ecdsa.sig          # ECDSA signature
test-pq.txt.mldsa65.sig               # ML-DSA-65 signature
test-pq.txt.mldsa87.sig               # ML-DSA-87 signature
```

### KMS Plugin Storage
```
~/.circl-keys/demo/keys/mldsa65.pem   # ML-DSA-65 private key
~/.circl-keys/demo/keys/mldsa87.pem   # ML-DSA-87 private key
```

## Cleanup

To remove demo artifacts:

```bash
rm -rf /tmp/cosign-pq-demo
rm -rf ~/.circl-keys/demo
```

## Manual Testing with Cosign

You can manually test the algorithms:

### Generate ECDSA Keys with Cosign

```bash
COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix my-ecdsa
```

### Generate ML-DSA-65 Keys with KMS Plugin

```bash
cosign generate-key-pair --kms "pqcrypto://demo/keys/my-mldsa65?algorithm=ML-DSA-65" --output-key-prefix my-mldsa65
```

### Generate ML-DSA-87 Keys with KMS Plugin

```bash
cosign generate-key-pair --kms "pqcrypto://demo/keys/my-mldsa87?algorithm=ML-DSA-87" --output-key-prefix my-mldsa87
```

### Sign and Verify with ECDSA

```bash
# Sign
COSIGN_PASSWORD="" cosign sign-blob --key my-ecdsa.key --tlog-upload=false myfile.txt > myfile.ecdsa.sig

# Verify
cosign verify-blob --key my-ecdsa.pub --signature myfile.ecdsa.sig --insecure-ignore-tlog myfile.txt
```

### Sign and Verify with ML-DSA-65

```bash
# Sign
cosign sign-blob --key "pqcrypto://demo/keys/my-mldsa65" --tlog-upload=false myfile.txt > myfile.mldsa65.sig

# Verify
cosign verify-blob --key my-mldsa65.pub --signature myfile.mldsa65.sig --insecure-ignore-tlog myfile.txt
```

### Sign and Verify with ML-DSA-87

```bash
# Sign
cosign sign-blob --key "pqcrypto://demo/keys/my-mldsa87" --tlog-upload=false myfile.txt > myfile.mldsa87.sig

# Verify
cosign verify-blob --key my-mldsa87.pub --signature myfile.mldsa87.sig --insecure-ignore-tlog myfile.txt
```

## KMS Reference Format

```
pqcrypto://<namespace>/<path>/<keyname>?algorithm=<algorithm>
```

Examples:
- `pqcrypto://demo/keys/mldsa65?algorithm=ML-DSA-65`
- `pqcrypto://demo/keys/mldsa87?algorithm=ML-DSA-87`