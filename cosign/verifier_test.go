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

package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Mock store for testing
type mockStore struct {
	manifests map[string][]byte
	blobs     map[string][]byte
}

func newMockStore() *mockStore {
	return &mockStore{
		manifests: make(map[string][]byte),
		blobs:     make(map[string][]byte),
	}
}

func (m *mockStore) FetchManifest(ctx context.Context, repository string, descriptor ocispec.Descriptor) ([]byte, error) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	if manifest, exists := m.manifests[key]; exists {
		return manifest, nil
	}
	return nil, fmt.Errorf("manifest not found: %s", key)
}

func (m *mockStore) FetchBlob(ctx context.Context, repository string, descriptor ocispec.Descriptor) ([]byte, error) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	if blob, exists := m.blobs[key]; exists {
		return blob, nil
	}
	return nil, fmt.Errorf("blob not found: %s", key)
}

func (m *mockStore) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, fmt.Errorf("resolve not implemented in mock")
}

func (m *mockStore) ListReferrers(ctx context.Context, ref string, artifactTypes []string, fn func(referrers []ocispec.Descriptor) error) error {
	return fn([]ocispec.Descriptor{})
}

func (m *mockStore) addManifest(repository string, descriptor ocispec.Descriptor, manifest []byte) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	m.manifests[key] = manifest
}

func (m *mockStore) addBlob(repository string, descriptor ocispec.Descriptor, blob []byte) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	m.blobs[key] = blob
}

// Test helper functions
func generateTestKey() (*ecdsa.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateTestCertificate(publicKey crypto.PublicKey) (string, error) {
	// Generate a private key for signing the certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return string(certPEM), nil
}

func createTestBundleAnnotation() (string, error) {
	bundleData := map[string]interface{}{
		"Payload": map[string]interface{}{
			"logIndex":       float64(12345),
			"logID":          "abcdef1234567890",
			"integratedTime": float64(1640995200),
			"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
		},
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("test-signature")),
	}

	bundleJSON, err := json.Marshal(bundleData)
	if err != nil {
		return "", err
	}

	return string(bundleJSON), nil
}

func createTestManifest(layers []ocispec.Descriptor) ([]byte, error) {
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ocispec.MediaTypeImageManifest,
		Layers:    layers,
	}

	return json.Marshal(manifest)
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name        string
		opts        *VerifierOptions
		expectError bool
	}{
		{
			name: "valid verifier with name",
			opts: &VerifierOptions{
				Name: "test-verifier",
			},
			expectError: false,
		},
		{
			name:        "missing name",
			opts:        &VerifierOptions{},
			expectError: true,
		},
		{
			name: "with public key config",
			opts: &VerifierOptions{
				Name: "test-verifier",
				PublicKeyConfigs: []*PublicKeyConfig{
					{
						PublicKey:          &ecdsa.PublicKey{},
						SignatureAlgorithm: crypto.SHA256,
					},
				},
			},
			expectError: false,
		},
		{
			name: "with nil public key config",
			opts: &VerifierOptions{
				Name: "test-verifier",
				PublicKeyConfigs: []*PublicKeyConfig{
					nil,
				},
			},
			expectError: true,
		},
		{
			name: "with identity policies",
			opts: &VerifierOptions{
				Name: "test-verifier",
				// Note: WithCertificateIdentity requires specific types, so we'll skip
				// complex identity policy testing for now
				IdentityPolicies: []verify.PolicyOption{},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if verifier == nil {
					t.Errorf("Expected verifier but got nil")
				}
				if verifier != nil && verifier.Name() != tt.opts.Name {
					t.Errorf("Expected name %s, got %s", tt.opts.Name, verifier.Name())
				}
			}
		})
	}
}

func TestVerifier_Name(t *testing.T) {
	verifier := &Verifier{name: "test-verifier"}
	if verifier.Name() != "test-verifier" {
		t.Errorf("Expected name 'test-verifier', got '%s'", verifier.Name())
	}
}

func TestVerifier_Type(t *testing.T) {
	verifier := &Verifier{}
	if verifier.Type() != verifierTypeCosign {
		t.Errorf("Expected type '%s', got '%s'", verifierTypeCosign, verifier.Type())
	}
}

func TestVerifier_Verifiable(t *testing.T) {
	verifier := &Verifier{}

	tests := []struct {
		name       string
		descriptor ocispec.Descriptor
		expected   bool
	}{
		{
			name: "valid cosign signature artifact",
			descriptor: ocispec.Descriptor{
				ArtifactType: mediaTypeCosignArtifactSignature,
				MediaType:    ocispec.MediaTypeImageManifest,
			},
			expected: true,
		},
		{
			name: "invalid artifact type",
			descriptor: ocispec.Descriptor{
				ArtifactType: "invalid-type",
				MediaType:    ocispec.MediaTypeImageManifest,
			},
			expected: false,
		},
		{
			name: "invalid media type",
			descriptor: ocispec.Descriptor{
				ArtifactType: mediaTypeCosignArtifactSignature,
				MediaType:    "invalid-media-type",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.Verifiable(tt.descriptor)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetVerificationMaterialX509CertificateChain(t *testing.T) {
	// Generate a test certificate
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certPEM, err := generateTestCertificate(publicKey)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
	}{
		{
			name: "valid certificate",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyCert: certPEM,
				},
			},
			expectError: false,
		},
		{
			name: "missing certificate annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{},
			},
			expectError: true,
		},
		{
			name: "invalid PEM",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyCert: "invalid-pem",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getVerificationMaterialX509CertificateChain(tt.layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
				if result != nil && result.X509CertificateChain == nil {
					t.Errorf("Expected certificate chain but got nil")
				}
			}
		})
	}
}

func TestGetVerificationMaterialTlogEntries(t *testing.T) {
	validBundle, err := createTestBundleAnnotation()
	if err != nil {
		t.Fatalf("Failed to create test bundle annotation: %v", err)
	}

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
	}{
		{
			name: "valid bundle annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: validBundle,
				},
			},
			expectError: false,
		},
		{
			name: "missing annotations",
			layer: ocispec.Descriptor{
				Annotations: nil,
			},
			expectError: true,
		},
		{
			name: "missing bundle annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{},
			},
			expectError: true,
		},
		{
			name: "empty bundle annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "",
				},
			},
			expectError: true,
		},
		{
			name: "invalid JSON",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "invalid-json",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getVerificationMaterialTlogEntries(tt.layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
				if len(result) == 0 {
					t.Errorf("Expected non-empty result")
				}
			}
		})
	}
}

func TestGetBundleMsgSignature(t *testing.T) {
	testSignature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
	}{
		{
			name: "valid SHA256 signature",
			layer: ocispec.Descriptor{
				Digest: digest.FromString("test-content"),
				Annotations: map[string]string{
					annotationKeySignature: testSignature,
				},
			},
			expectError: false,
		},
		{
			name: "missing signature annotation",
			layer: ocispec.Descriptor{
				Digest:      digest.FromString("test-content"),
				Annotations: map[string]string{},
			},
			expectError: false, // Empty string decodes successfully to empty bytes
		},
		{
			name: "invalid signature encoding",
			layer: ocispec.Descriptor{
				Digest: digest.FromString("test-content"),
				Annotations: map[string]string{
					annotationKeySignature: "invalid-base64!@#",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getBundleMsgSignature(tt.layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
			}
		})
	}
}

func TestGetSignatureDescriptors(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	// Create test manifest with simple signing layers
	layers := []ocispec.Descriptor{
		{
			MediaType: mediaTypeSimpleSigning,
			Digest:    digest.FromString("layer1"),
			Size:      100,
		},
		{
			MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
			Digest:    digest.FromString("layer2"),
			Size:      200,
		},
		{
			MediaType: mediaTypeSimpleSigning,
			Digest:    digest.FromString("layer3"),
			Size:      150,
		},
	}

	manifestBytes, err := createTestManifest(layers)
	if err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	artifactDesc := ocispec.Descriptor{
		Digest: digest.FromBytes(manifestBytes),
		Size:   int64(len(manifestBytes)),
	}

	store.addManifest(repo, artifactDesc, manifestBytes)

	descriptors, err := getSignatureDescriptors(ctx, store, repo, artifactDesc)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedCount := 2 // Only simple signing layers
	if len(descriptors) != expectedCount {
		t.Errorf("Expected %d descriptors, got %d", expectedCount, len(descriptors))
	}

	for _, desc := range descriptors {
		if desc.MediaType != mediaTypeSimpleSigning {
			t.Errorf("Expected media type %s, got %s", mediaTypeSimpleSigning, desc.MediaType)
		}
	}
}

func TestCreateTrustedPublicKeyMaterial(t *testing.T) {
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	config := &PublicKeyConfig{
		PublicKey:           publicKey,
		SignatureAlgorithm:  crypto.SHA256,
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(time.Hour),
	}

	material := createTrustedPublicKeyMaterial(config)
	if material == nil {
		t.Errorf("Expected trusted material but got nil")
	}
}

func TestLayerReport_MarshalJSON(t *testing.T) {
	tests := []struct {
		name   string
		report *layerReport
	}{
		{
			name: "successful report",
			report: &layerReport{
				Digest:    "sha256:abcdef",
				Succeeded: true,
				Error:     nil,
			},
		},
		{
			name: "failed report with error",
			report: &layerReport{
				Digest:    "sha256:abcdef",
				Succeeded: false,
				Error:     fmt.Errorf("verification failed"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.report.MarshalJSON()
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Failed to unmarshal result: %v", err)
			}

			if result["digest"] != tt.report.Digest {
				t.Errorf("Expected digest %s, got %v", tt.report.Digest, result["digest"])
			}

			if result["succeeded"] != tt.report.Succeeded {
				t.Errorf("Expected succeeded %v, got %v", tt.report.Succeeded, result["succeeded"])
			}

			if tt.report.Error != nil {
				if result["error"] != tt.report.Error.Error() {
					t.Errorf("Expected error %s, got %v", tt.report.Error.Error(), result["error"])
				}
			}
		})
	}
}

func TestPublicKeyConfigDefaults(t *testing.T) {
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	opts := &VerifierOptions{
		Name: "test-verifier",
		PublicKeyConfigs: []*PublicKeyConfig{
			{
				PublicKey: publicKey,
				// SignatureAlgorithm not set - should default to SHA256
			},
		},
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if verifier == nil {
		t.Errorf("Expected verifier but got nil")
	}
}

func TestVerifier_VerifyIntegration(t *testing.T) {
	// This is a basic integration test that tests the Verify method
	// with a mock store and basic setup
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	// Create a verifier with minimal setup
	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true, // Ignore tlog for this test
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Create test artifact descriptor
	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromString("test-artifact"),
		Size:         100,
	}

	// Create empty manifest (no layers)
	manifestBytes, err := createTestManifest([]ocispec.Descriptor{})
	if err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	store.addManifest(repo, artifactDesc, manifestBytes)

	verifyOpts := &ratify.VerifyOptions{
		Store:              store,
		Repository:         repo,
		ArtifactDescriptor: artifactDesc,
	}

	result, err := verifier.Verify(ctx, verifyOpts)
	if err != nil {
		t.Fatalf("Unexpected error during verification: %v", err)
	}

	if result == nil {
		t.Errorf("Expected verification result but got nil")
	}

	if result.Verifier != verifier {
		t.Errorf("Expected verifier to match")
	}

	// With no signature layers, we expect no valid signatures
	if result.Description != "Cosign signature verification failed: no valid signatures found" {
		t.Errorf("Unexpected description: %s", result.Description)
	}
}

func TestGetBundleVerificationMaterial(t *testing.T) {
	// Generate test certificate
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certPEM, err := generateTestCertificate(publicKey)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	bundleAnnotation, err := createTestBundleAnnotation()
	if err != nil {
		t.Fatalf("Failed to create test bundle annotation: %v", err)
	}

	layer := ocispec.Descriptor{
		Annotations: map[string]string{
			annotationKeyCert:   certPEM,
			annotationKeyBundle: bundleAnnotation,
		},
	}

	tests := []struct {
		name        string
		ignoreTlog  bool
		expectError bool
	}{
		{
			name:        "with tlog entries",
			ignoreTlog:  false,
			expectError: false,
		},
		{
			name:        "ignore tlog entries",
			ignoreTlog:  true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getBundleVerificationMaterial(layer, tt.ignoreTlog)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
				if result != nil {
					if result.Content == nil {
						t.Errorf("Expected content but got nil")
					}
					if tt.ignoreTlog && len(result.TlogEntries) > 0 {
						t.Errorf("Expected no tlog entries when ignored, got %d", len(result.TlogEntries))
					}
					if !tt.ignoreTlog && len(result.TlogEntries) == 0 {
						t.Errorf("Expected tlog entries when not ignored")
					}
				}
			}
		})
	}
}

// Additional test functions for comprehensive coverage

func TestVerifier_VerifyWithSignatureLayers(t *testing.T) {
	// This test verifies the Verify method with actual signature layers
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	// Create a verifier
	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true, // Ignore tlog for this test
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Generate test certificate
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certPEM, err := generateTestCertificate(publicKey)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	testSignature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	// Create signature layer with certificate and signature annotations
	sigLayer := ocispec.Descriptor{
		MediaType: mediaTypeSimpleSigning,
		Digest:    digest.FromString("signature-layer"),
		Size:      100,
		Annotations: map[string]string{
			annotationKeyCert:      certPEM,
			annotationKeySignature: testSignature,
		},
	}

	// Create manifest with signature layer
	manifestBytes, err := createTestManifest([]ocispec.Descriptor{sigLayer})
	if err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromBytes(manifestBytes),
		Size:         int64(len(manifestBytes)),
	}

	store.addManifest(repo, artifactDesc, manifestBytes)

	verifyOpts := &ratify.VerifyOptions{
		Store:              store,
		Repository:         repo,
		ArtifactDescriptor: artifactDesc,
	}

	result, err := verifier.Verify(ctx, verifyOpts)
	if err != nil {
		t.Fatalf("Unexpected error during verification: %v", err)
	}

	if result == nil {
		t.Errorf("Expected verification result but got nil")
	}

	// Check that we have verification details
	if result.Detail != nil {
		if detailMap, ok := result.Detail.(map[string][]*layerReport); ok {
			if details, exists := detailMap["verifiedSignatures"]; exists {
				if len(details) == 0 {
					t.Errorf("Expected at least one signature layer report")
				} else {
					// The signature will fail verification but we should still get a report
					if details[0].Digest != sigLayer.Digest.String() {
						t.Errorf("Expected digest %s, got %s", sigLayer.Digest.String(), details[0].Digest)
					}
				}
			} else {
				t.Errorf("Expected verification details but got none")
			}
		} else {
			t.Errorf("Expected verification details to be a map but got different type")
		}
	} else {
		t.Errorf("Expected verification details but got nil")
	}
}

func TestGetVerificationMaterialTlogEntries_MalformedBundle(t *testing.T) {
	// Test with various malformed bundle annotations
	tests := []struct {
		name   string
		bundle string
	}{
		{
			name:   "missing Payload",
			bundle: `{"NotPayload": {}}`,
		},
		{
			name:   "null Payload",
			bundle: `{"Payload": null}`,
		},
		{
			name:   "missing logIndex",
			bundle: `{"Payload": {"logID": "abc", "integratedTime": 123, "body": "dGVzdA=="}, "SignedEntryTimestamp": "dGVzdA=="}`,
		},
		{
			name:   "missing logID",
			bundle: `{"Payload": {"logIndex": 123, "integratedTime": 123, "body": "dGVzdA=="}, "SignedEntryTimestamp": "dGVzdA=="}`,
		},
		{
			name:   "invalid body base64",
			bundle: `{"Payload": {"logIndex": 123, "logID": "abc", "integratedTime": 123, "body": "invalid-base64!"}, "SignedEntryTimestamp": "dGVzdA=="}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layer := ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: tt.bundle,
				},
			}

			_, err := getVerificationMaterialTlogEntries(layer)
			if err == nil {
				t.Errorf("Expected error for malformed bundle but got none")
			}
		})
	}
}

func TestGetBundleMsgSignature_UnsupportedDigestAlgorithm(t *testing.T) {
	// Test with unsupported digest algorithm
	testSignature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	// Create a digest with an unsupported algorithm
	unsupportedDigest := digest.Digest("blake2b:abcdef1234567890")

	layer := ocispec.Descriptor{
		Digest: unsupportedDigest,
		Annotations: map[string]string{
			annotationKeySignature: testSignature,
		},
	}

	_, err := getBundleMsgSignature(layer)
	if err == nil {
		t.Errorf("Expected error for unsupported digest algorithm but got none")
	}

	expectedError := "unknown digest algorithm: blake2b"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestVerifier_VerifyBundleError(t *testing.T) {
	// Test verifyBundle method with invalid digest
	verifier := &Verifier{
		name:       "test-verifier",
		ignoreTLog: true,
	}

	// Create an invalid digest that should cause hex decoding to fail
	invalidDigest := digest.Digest("sha256:invalid-hex-string!")

	// This test would normally require a valid bundle, but since the digest
	// decoding will fail first, we can pass nil
	_, err := verifier.verifyBundle(nil, invalidDigest)
	if err == nil {
		t.Errorf("Expected error for invalid digest but got none")
	}
}

func TestVerifierOptions_Validation(t *testing.T) {
	// Test various edge cases in verifier options validation
	tests := []struct {
		name        string
		opts        *VerifierOptions
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil options",
			opts:        nil,
			expectError: true,
		},
		{
			name: "empty name",
			opts: &VerifierOptions{
				Name: "",
			},
			expectError: true,
			errorMsg:    "verifier name is required",
		},
		{
			name: "with multiple public key configs",
			opts: &VerifierOptions{
				Name: "test-verifier",
				PublicKeyConfigs: []*PublicKeyConfig{
					{
						PublicKey:          &ecdsa.PublicKey{},
						SignatureAlgorithm: crypto.SHA256,
					},
					{
						PublicKey:          &ecdsa.PublicKey{},
						SignatureAlgorithm: crypto.SHA512,
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.opts != nil {
				_, err = NewVerifier(tt.opts)
			} else {
				// Test nil options by calling with nil
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				_, err = NewVerifier(nil)
			}

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetSignatureDescriptors_ErrorCases(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	tests := []struct {
		name        string
		setupStore  func(*mockStore, ocispec.Descriptor)
		expectError bool
	}{
		{
			name: "manifest not found",
			setupStore: func(s *mockStore, desc ocispec.Descriptor) {
				// Don't add the manifest to the store
			},
			expectError: true,
		},
		{
			name: "invalid manifest JSON",
			setupStore: func(s *mockStore, desc ocispec.Descriptor) {
				s.addManifest(repo, desc, []byte("invalid-json"))
			},
			expectError: true,
		},
		{
			name: "wrong media type",
			setupStore: func(s *mockStore, desc ocispec.Descriptor) {
				manifest := ocispec.Manifest{
					Versioned: specs.Versioned{
						SchemaVersion: 2,
					},
					MediaType: "application/vnd.docker.distribution.manifest.v2+json",
					Layers:    []ocispec.Descriptor{},
				}
				manifestBytes, _ := json.Marshal(manifest)
				s.addManifest(repo, desc, manifestBytes)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactDesc := ocispec.Descriptor{
				Digest: digest.FromString("test-manifest"),
				Size:   100,
			}

			tt.setupStore(store, artifactDesc)

			_, err := getSignatureDescriptors(ctx, store, repo, artifactDesc)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestGetVerificationMaterialTlogEntries_ComprehensiveCoverage provides comprehensive
// test coverage for all code paths in getVerificationMaterialTlogEntries function
func TestGetVerificationMaterialTlogEntries_ComprehensiveCoverage(t *testing.T) {
	// Helper function to create bundle with specific payload
	createBundleWithPayload := func(payload map[string]interface{}, signedEntryTimestamp string) string {
		bundleData := map[string]interface{}{
			"Payload":              payload,
			"SignedEntryTimestamp": signedEntryTimestamp,
		}
		bundleJSON, _ := json.Marshal(bundleData)
		return string(bundleJSON)
	}

	// Helper function to create bundle with specific SignedEntryTimestamp
	createBundleWithSET := func(signedEntryTimestamp interface{}) string {
		payload := map[string]interface{}{
			"logIndex":       float64(12345),
			"logID":          "abcdef1234567890",
			"integratedTime": float64(1640995200),
			"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
		}
		bundleData := map[string]interface{}{
			"Payload":              payload,
			"SignedEntryTimestamp": signedEntryTimestamp,
		}
		bundleJSON, _ := json.Marshal(bundleData)
		return string(bundleJSON)
	}

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
		errorMsg    string
	}{
		// Test case: jsonData is nil after unmarshaling (edge case - this shouldn't happen in practice)
		{
			name: "nil json data after unmarshaling",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "null",
				},
			},
			expectError: true,
			errorMsg:    "bundle payload is missing",
		},
		// Test case: Payload exists but is null
		{
			name: "null payload",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: `{"Payload": null}`,
				},
			},
			expectError: true,
			errorMsg:    "bundle payload is missing",
		},
		// Test case: logIndex is not float64 (wrong type)
		{
			name: "logIndex wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       "not-a-number",
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: logID is not string (wrong type)
		{
			name: "logID wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          12345, // should be string
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: invalid hex in logID
		{
			name: "invalid hex in logID",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "invalid-hex-string!@#",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error decoding logID",
		},
		// Test case: missing integratedTime
		{
			name: "missing integratedTime",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex": float64(12345),
						"logID":    "abcdef1234567890",
						// missing integratedTime
						"body": base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "bundle payload integratedTime is missing",
		},
		// Test case: integratedTime is not float64 (wrong type)
		{
			name: "integratedTime wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": "not-a-number",
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: missing SignedEntryTimestamp
		{
			name: "missing SignedEntryTimestamp",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: `{
						"Payload": {
							"logIndex": 12345,
							"logID": "abcdef1234567890",
							"integratedTime": 1640995200,
							"body": "` + base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)) + `"
						}
					}`,
				},
			},
			expectError: true,
			errorMsg:    "signed entry timestamp is missing",
		},
		// Test case: SignedEntryTimestamp is not string (wrong type)
		{
			name: "SignedEntryTimestamp wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithSET(12345), // should be string
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: invalid base64 in SignedEntryTimestamp
		{
			name: "invalid base64 SignedEntryTimestamp",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithSET("invalid-base64!@#"),
				},
			},
			expectError: true,
			errorMsg:    "error decoding signedEntryTimestamp",
		},
		// Test case: missing body
		{
			name: "missing body",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						// missing body
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "bundle payload body is missing",
		},
		// Test case: body is not string (wrong type)
		{
			name: "body wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           12345, // should be string
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: invalid JSON in body after base64 decode
		{
			name: "invalid JSON in decoded body",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte("invalid-json{")),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling body",
		},
		// Test case: body contains null JSON (edge case)
		{
			name: "null JSON in decoded body",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte("null")),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body apiVersion is missing",
		},
		// Test case: missing apiVersion
		{
			name: "missing apiVersion",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"kind": "hashedrekord"}`)), // missing apiVersion
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body apiVersion is missing",
		},
		// Test case: apiVersion is null
		{
			name: "null apiVersion",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": null, "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body apiVersion is missing",
		},
		// Test case: apiVersion is not string (wrong type)
		{
			name: "apiVersion wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": 123, "kind": "hashedrekord"}`)), // should be string
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling body",
		},
		// Test case: missing kind
		{
			name: "missing kind",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1"}`)), // missing kind
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body kind is missing",
		},
		// Test case: kind is null
		{
			name: "null kind",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": null}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body kind is missing",
		},
		// Test case: kind is not string (wrong type)
		{
			name: "kind wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": 456}`)), // should be string
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling body",
		},
		// Test case: success with all valid fields
		{
			name: "valid complete bundle",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getVerificationMaterialTlogEntries(tt.layer)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("Expected result but got nil")
				return
			}

			if len(result) != 1 {
				t.Errorf("Expected exactly one transparency log entry, got %d", len(result))
				return
			}

			entry := result[0]
			if entry.LogIndex != 12345 {
				t.Errorf("Expected LogIndex 12345, got %d", entry.LogIndex)
			}
			if entry.LogId == nil || len(entry.LogId.KeyId) == 0 {
				t.Errorf("Expected LogId to be set")
			}
			if entry.KindVersion == nil {
				t.Errorf("Expected KindVersion to be set")
			} else {
				if entry.KindVersion.Kind != "hashedrekord" {
					t.Errorf("Expected Kind 'hashedrekord', got '%s'", entry.KindVersion.Kind)
				}
				if entry.KindVersion.Version != "0.0.1" {
					t.Errorf("Expected Version '0.0.1', got '%s'", entry.KindVersion.Version)
				}
			}
			if entry.IntegratedTime != 1640995200 {
				t.Errorf("Expected IntegratedTime 1640995200, got %d", entry.IntegratedTime)
			}
			if entry.InclusionPromise == nil || len(entry.InclusionPromise.SignedEntryTimestamp) == 0 {
				t.Errorf("Expected InclusionPromise with SignedEntryTimestamp to be set")
			}
			if len(entry.CanonicalizedBody) == 0 {
				t.Errorf("Expected CanonicalizedBody to be set")
			}
		})
	}
}
