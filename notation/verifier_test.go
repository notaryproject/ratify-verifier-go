/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package notation

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
)

const (
	testVerifierName = "notation-1"
	verfierType      = "notation"
	testRepo         = "test-registry/test-repo"
	testDigest1      = "sha256:cd0abf4135161b8aeb079b64b8215e433088d21463204771d070aadc52678aa0"
	testDigest2      = "sha256:e05b6fbf2432faf87115041d172aa1f587cff725b94c61d927f67c21e1e2d5b9"
	testSubject      = testRepo + "@" + testDigest1
)

var notationSignatureArtifact = ocispec.Descriptor{
	ArtifactType: "application/vnd.cncf.notary.signature",
	MediaType:    "application/vnd.oci.image.manifest.v1+json",
}

type mockTrustStore struct{}

func (m *mockTrustStore) GetCertificates(_ context.Context, _ truststore.Type, _ string) ([]*x509.Certificate, error) {
	return nil, nil
}

// mockStore is a mock implementation of ratify.Store.
type mockStore struct {
	manifest      *ocispec.Manifest
	manifestBytes []byte
	signatureBlob []byte
}

func (m *mockStore) Name() string {
	return "mock-store-name"
}

func (m *mockStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (m *mockStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.signatureBlob == nil {
		return nil, errors.New("signature blob not initialized")
	}
	return m.signatureBlob, nil
}

func (m *mockStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.manifest == nil && m.manifestBytes == nil {
		return nil, errors.New("image manifest not initialized")
	}
	if m.manifestBytes != nil {
		return m.manifestBytes, nil
	}
	return json.Marshal(m.manifest)
}

func (m *mockStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}

// mockVerifier is a mock implementation of notation.Verifier.
type mockVerifier struct {
	verifySucceeded bool
}

func (m *mockVerifier) Verify(_ context.Context, _ ocispec.Descriptor, _ []byte, _ notation.VerifierVerifyOptions) (*notation.VerificationOutcome, error) {
	if m.verifySucceeded {
		return &notation.VerificationOutcome{
			EnvelopeContent: &signature.EnvelopeContent{
				SignerInfo: signature.SignerInfo{
					CertificateChain: []*x509.Certificate{
						{
							Issuer:  pkix.Name{CommonName: "issuer"},
							Subject: pkix.Name{CommonName: "subject"},
						},
					},
				},
			},
		}, nil
	} else {
		return nil, errors.New("verification failed")
	}

}

func TestNewVerifier(t *testing.T) {
	opts := &VerifierOptions{
		Name: testVerifierName,
		TrustPolicyDoc: &trustpolicy.Document{
			Version: "1.0",
			TrustPolicies: []trustpolicy.TrustPolicy{
				{
					Name:           "default",
					RegistryScopes: []string{"*"},
					SignatureVerification: trustpolicy.SignatureVerification{
						VerificationLevel: "strict",
					},
					TrustStores:       []string{"ca:cert"},
					TrustedIdentities: []string{"*"},
				},
			},
		},
		TrustStore: &mockTrustStore{},
	}
	verifier, err := NewVerifier(opts)
	if err != nil || verifier == nil {
		t.Fatalf("failed to create a new verifier: %v", err)
	}
	if _, ok := interface{}(verifier).(ratify.Verifier); !ok {
		t.Fatalf("verifier does not implement ratify.Verifier")
	}

	if verifier.Name() != testVerifierName {
		t.Fatalf("unexpected verifier name: %s, expect: %s", verifier.Name(), testVerifierName)
	}
	if verifier.Type() != verfierType {
		t.Fatalf("unexpected verifier type: %s", verifier.Type())
	}

	if !verifier.Verifiable(notationSignatureArtifact) {
		t.Fatalf("unexpected artifact type: %s", notationSignatureArtifact.ArtifactType)
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name           string
		verifier       notation.Verifier
		opts           *ratify.VerifyOptions
		expectedResult *ratify.VerificationResult
		expectedError  bool
	}{
		{
			name:     "failed to fetch manifest",
			verifier: &mockVerifier{},
			opts: &ratify.VerifyOptions{
				Repository: testRepo,
				Store:      &mockStore{},
			},
			expectedError: true,
		},
		{
			name:     "no layers in the signature manifest",
			verifier: &mockVerifier{},
			opts: &ratify.VerifyOptions{
				Repository: testRepo,
				Store: &mockStore{
					manifest: &ocispec.Manifest{},
				},
			},
			expectedError: true,
		},
		{
			name:     "failed to unmarshal signature manifest",
			verifier: &mockVerifier{},
			opts: &ratify.VerifyOptions{
				Repository: testRepo,
				Store: &mockStore{
					manifestBytes: []byte("invalid"),
				},
			},
			expectedError: true,
		},
		{
			name:     "failed to fetch blob content",
			verifier: &mockVerifier{},
			opts: &ratify.VerifyOptions{
				Repository: testRepo,
				Store: &mockStore{
					manifest: &ocispec.Manifest{
						Layers: []ocispec.Descriptor{
							{
								Digest: testDigest2,
							},
						},
					},
				},
			},
			expectedError: true,
		},
		{
			name:     "failed to verify signature",
			verifier: &mockVerifier{},
			opts: &ratify.VerifyOptions{
				Repository: testRepo,
				Store: &mockStore{
					manifest: &ocispec.Manifest{
						Layers: []ocispec.Descriptor{
							{
								Digest: testDigest2,
							},
						},
					},
					signatureBlob: []byte{},
				},
			},
			expectedError:  false,
			expectedResult: &ratify.VerificationResult{},
		},
		{
			name: "verification succeeded",
			verifier: &mockVerifier{
				verifySucceeded: true,
			},
			opts: &ratify.VerifyOptions{
				Repository: testRepo,
				Store: &mockStore{
					manifest: &ocispec.Manifest{
						Layers: []ocispec.Descriptor{
							{
								Digest: testDigest2,
							},
						},
					},
					signatureBlob: []byte{},
				},
			},
			expectedError: false,
			expectedResult: &ratify.VerificationResult{
				Description: "Notation signature verification succeeded",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := &Verifier{
				name:     testVerifierName,
				verifier: tt.verifier,
			}

			result, err := verifier.Verify(context.Background(), tt.opts)
			if tt.expectedError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result.Description != tt.expectedResult.Description {
					t.Fatalf("expected description: %s, got: %s", tt.expectedResult.Description, result.Description)
				}
			}
		})
	}
}
