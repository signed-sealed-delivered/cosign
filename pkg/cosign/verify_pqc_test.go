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
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/payload"
	"github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa"
	tsaMock "github.com/sigstore/cosign/v3/internal/pkg/cosign/tsa/mock"
	"github.com/sigstore/cosign/v3/pkg/oci/static"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/pqcrypto"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMLDSASignatureVerificationPQC tests ML-DSA signature verification
// Note: Rekor integration testing is deferred until Rekor has PQ support.
func TestMLDSASignatureVerificationPQC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	algorithms := []string{"ML-DSA-65", "ML-DSA-87"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			privKey, pubKey, err := pqcrypto.GenerateMLDSAKeyPair(alg)
			require.NoError(t, err, "Failed to generate %s key pair", alg)

			signer := &mldsaSigner{
				privateKey: privKey,
				publicKey:  pubKey,
			}

			blob, _, blobSignatureBase64 := generateBlobSignature(t, signer)

			ociSignature, err := static.NewSignature(blob, blobSignatureBase64)
			require.NoError(t, err, "error creating OCI signature")

			bundleVerified, err := VerifyImageSignature(ctx, ociSignature, v1.Hash{}, &CheckOpts{
				SigVerifier: signer,
				IgnoreTlog:  true,
			})

			assert.NoError(t, err, "ML-DSA signature verification should succeed")
			assert.False(t, bundleVerified, "bundle should not be verified without Rekor")
		})
	}
}

// TestMLDSASignatureWithTimestampPQC tests ML-DSA signatures with TSA timestamps
func TestMLDSASignatureWithTimestampPQC(t *testing.T) {
	algorithms := []string{"ML-DSA-65", "ML-DSA-87"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			client, err := tsaMock.NewTSAClient((tsaMock.TSAClientOptions{Time: time.Now()}))
			if err != nil {
				t.Fatal(err)
			}

			privKey, pubKey, err := pqcrypto.GenerateMLDSAKeyPair(alg)
			require.NoError(t, err)

			signer := &mldsaSigner{
				privateKey: privKey,
				publicKey:  pubKey,
			}

			payloadSigner := payload.NewSigner(signer)
			testSigner := tsa.NewSigner(payloadSigner, client)

			certChainPEM, err := cryptoutils.MarshalCertificatesToPEM(client.CertChain)
			if err != nil {
				t.Fatalf("unexpected error marshalling cert chain: %v", err)
			}

			leaves, intermediates, roots, err := tsa.SplitPEMCertificateChain(certChainPEM)
			if err != nil {
				t.Fatal("error splitting response into certificate chain")
			}

			payload := []byte{1, 2, 3, 4}
			sig, _, err := testSigner.Sign(context.Background(), bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("error signing the payload with the tsa client server: %v", err)
			}

			if bundleVerified, err := VerifyImageSignature(context.TODO(), sig, v1.Hash{}, &CheckOpts{
				SigVerifier:                 signer,
				TSACertificate:              leaves[0],
				TSAIntermediateCertificates: intermediates,
				TSARootCertificates:         roots,
				IgnoreTlog:                  true,
			}); err != nil || bundleVerified {
				t.Fatalf("unexpected error while verifying ML-DSA signature with timestamp, got %v", err)
			}
		})
	}
}

type mldsaSigner struct {
	privateKey *pqcrypto.PQPrivateKey
	publicKey  *pqcrypto.PQPublicKey
}

func (s *mldsaSigner) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.publicKey, nil
}

func (s *mldsaSigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	return s.privateKey.Sign(messageBytes)
}

func (s *mldsaSigner) VerifySignature(sig io.Reader, message io.Reader, opts ...signature.VerifyOption) error {
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return err
	}
	messageBytes, err := io.ReadAll(message)
	if err != nil {
		return err
	}
	if s.publicKey.Verify(messageBytes, sigBytes) {
		return nil
	}
	return errors.New("ML-DSA signature verification failed")
}
