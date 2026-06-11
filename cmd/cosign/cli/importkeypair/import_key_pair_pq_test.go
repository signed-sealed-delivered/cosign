//go:build pq_circl || pq_openssl

//
// Copyright 2026 The Sigstore Authors.
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

package importkeypair

import (
	"context"
	"os"
	"testing"

	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/pqcrypto"
)

// TestImportOfPQKeys tests importing post-quantum ML-DSA keys
func TestImportOfPQKeys(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{
			name:      "ML-DSA-65",
			algorithm: "ML-DSA-65",
		},
		{
			name:      "ML-DSA-87",
			algorithm: "ML-DSA-87",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("COSIGN_PASSWORD", "test-pq-password")

			privateKeyFileName := "my-pq-private-key.pem"
			createTemporaryPQPrivateKey(privateKeyFileName, tt.algorithm, t)

			keyPairFileName := "my-pq-test"
			err := ImportKeyPairCmd(context.Background(), options.ImportKeyPairOptions{
				Key:              privateKeyFileName,
				OutputKeyPrefix:  keyPairFileName,
				SkipConfirmation: false,
			}, nil)
			if err != nil {
				t.Fatalf("ImportKeyPairCmd failed: %v", err)
			}

			// remove temporary PKCS#8 private key
			checkIfFileExistsThenDelete(privateKeyFileName, t)

			// Load the imported key and verify it works
			importedKeyPath := keyPairFileName + ".key"
			kb, err := os.ReadFile(importedKeyPath)
			if err != nil {
				t.Fatalf("failed to read imported key: %v", err)
			}

			// Try to load it with the password to verify it's properly encrypted
			password := []byte("test-pq-password")
			_, err = cosign.LoadPrivateKey(kb, password, nil)
			if err != nil {
				t.Fatalf("failed to load imported key: %v", err)
			}
			t.Logf("Successfully loaded and verified imported %s key", tt.algorithm)

			// Clean up keys
			checkIfFileExistsThenDelete(keyPairFileName+".key", t)
			checkIfFileExistsThenDelete(keyPairFileName+".pub", t)
		})
	}
}

func createTemporaryPQPrivateKey(privateKeyName, algorithm string, t *testing.T) {
	privKey, _, err := pqcrypto.GenerateMLDSAKeyPair(algorithm)
	if err != nil {
		t.Fatalf("failed to generate %s key pair: %v", algorithm, err)
	}

	keyPEM, err := cryptoutils.MarshalPrivateKeyToPEM(privKey)
	if err != nil {
		t.Fatalf("failed to marshal private key to DER: %v", err)
	}

	if err := os.WriteFile(privateKeyName, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write private key to file: %v", err)
	}
}
