//go:build pq_circl || pq_openssl

//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"crypto"
	"encoding/pem"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/pqcrypto"
)

func init() {
	SetKeyPairHandler(&pqKeyPairHandler{
		previousHandler: GetKeyPairHandler(),
	})
}

func generatePQKeyPair(algorithm string, pf PassFunc) (*KeysBytes, error) {
	privKey, pubKey, err := pqcrypto.GenerateMLDSAKeyPair(algorithm)
	if err != nil {
		return nil, fmt.Errorf("generating %s key pair: %w", algorithm, err)
	}

	privDER, err := cryptoutils.MarshalPrivateKeyToDER(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key to DER: %w", err)
	}

	password := []byte{}
	if pf != nil {
		password, err = pf(true)
		if err != nil {
			return nil, err
		}
	}

	encBytes, err := encrypted.Encrypt(privDER, password)
	if err != nil {
		return nil, fmt.Errorf("encrypting private key: %w", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Bytes: encBytes,
		Type:  SigstorePrivateKeyPemType,
	})

	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}

	return &KeysBytes{
		PrivateBytes: privPEM,
		PublicBytes:  pubPEM,
		password:     password,
	}, nil
}

// pqKeyPairHandler implements KeyPairHandler with PQ support
type pqKeyPairHandler struct {
	previousHandler KeyPairHandler
}

// ImportKeyPair is the PQ-aware implementation that handles both classical and PQ keys
func (kph *pqKeyPairHandler) ImportKeyPair(key crypto.PrivateKey, ptype string) (*Keys, error) {
	if pqPriv, ok := key.(*pqcrypto.PQPrivateKey); ok {
		return importPQKeyPair(pqPriv, ptype)
	}

	return kph.previousHandler.ImportKeyPair(key, ptype)
}

// GenerateKeyPairForAlgorithm is the PQ-aware implementation that handles both classical and PQ algorithms
func (kph *pqKeyPairHandler) GenerateKeyPairForAlgorithm(algorithmName string) (*Keys, error) {
	if pqcrypto.IsAlgorithmSupported(algorithmName) {
		privKey, pubKey, err := pqcrypto.GenerateMLDSAKeyPair(algorithmName)
		if err != nil {
			return nil, fmt.Errorf("generating %s key pair: %w", algorithmName, err)
		}
		return &Keys{private: privKey, public: pubKey}, nil
	}

	return kph.previousHandler.GenerateKeyPairForAlgorithm(algorithmName)
}

// importPQKeyPair handles importing PQ private keys
func importPQKeyPair(pqPriv *pqcrypto.PQPrivateKey, ptype string) (*Keys, error) {
	pubKey := pqPriv.Public()
	if pubKey == nil {
		return nil, fmt.Errorf("unable to extract public key from PQ private key")
	}

	pqPub, ok := pubKey.(*pqcrypto.PQPublicKey)
	if !ok {
		return nil, fmt.Errorf("expected PQ public key, got %T", pubKey)
	}

	if err := validatePQPublicKey(pqPub); err != nil {
		return nil, keyTypeError(ptype, "validating", err)
	}

	return &Keys{pqPriv, pqPub}, nil
}

// validatePQPublicKey validates a PQ public key by checking its algorithm and key size
func validatePQPublicKey(pub *pqcrypto.PQPublicKey) error {
	switch pub.Algorithm {
	case pqcrypto.AlgorithmMLDSA65:
		if len(pub.KeyData) != 1952 {
			return fmt.Errorf("invalid ML-DSA-65 public key size: got %d, want 1952", len(pub.KeyData))
		}
	case pqcrypto.AlgorithmMLDSA87:
		if len(pub.KeyData) != 2592 {
			return fmt.Errorf("invalid ML-DSA-87 public key size: got %d, want 2592", len(pub.KeyData))
		}
	default:
		return fmt.Errorf("unsupported PQ algorithm: %s", pub.Algorithm)
	}
	return nil
}
