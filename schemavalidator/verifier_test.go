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

package schemavalidator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testVerifierName = "schemavalidator-1"
	testRepo         = "test-registry/test-repo"
	testDigest       = "sha256:cd0abf4135161b8aeb079b64b8215e433088d21463204771d070aadc52678aa0"
	sarifMediaType   = "application/sarif+json"
)

// mockStore is a mock implementation of ratify.Store.
type mockStore struct {
	manifest    *ocispec.Manifest
	manifestErr error
	blob        []byte
	blobErr     error
}

func (m *mockStore) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}

func (m *mockStore) ListReferrers(_ context.Context, _ string, _ []string, _ func(referrers []ocispec.Descriptor) error) error {
	return nil
}

func (m *mockStore) FetchBlob(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.blobErr != nil {
		return nil, m.blobErr
	}
	return m.blob, nil
}

func (m *mockStore) FetchManifest(_ context.Context, _ string, _ ocispec.Descriptor) ([]byte, error) {
	if m.manifestErr != nil {
		return nil, m.manifestErr
	}
	return json.Marshal(m.manifest)
}

func manifestWithLayer(mediaType string) *ocispec.Manifest {
	return &ocispec.Manifest{
		Layers: []ocispec.Descriptor{
			{MediaType: mediaType, Digest: testDigest},
		},
	}
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name    string
		opts    *VerifierOptions
		wantErr bool
	}{
		{name: "nil options", opts: nil, wantErr: true},
		{name: "empty name", opts: &VerifierOptions{Schemas: map[string]string{"a": "b"}}, wantErr: true},
		{name: "no schemas", opts: &VerifierOptions{Name: testVerifierName}, wantErr: true},
		{name: "valid", opts: &VerifierOptions{Name: testVerifierName, Schemas: map[string]string{"a": "b"}}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewVerifier(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTypeAndName(t *testing.T) {
	v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName, Schemas: map[string]string{"a": "b"}})
	if v.Name() != testVerifierName {
		t.Fatalf("Name() = %s", v.Name())
	}
	if v.Type() != verifierTypeSchemaValidator {
		t.Fatalf("Type() = %s", v.Type())
	}
}

func TestVerifiable(t *testing.T) {
	v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName, Schemas: map[string]string{"a": "b"}, ArtifactTypes: []string{sarifMediaType}})
	if !v.Verifiable(ocispec.Descriptor{ArtifactType: sarifMediaType}) {
		t.Fatal("expected verifiable true for matching type")
	}
	if v.Verifiable(ocispec.Descriptor{ArtifactType: "other"}) {
		t.Fatal("expected verifiable false for non-matching type")
	}
}

func TestValidateOfflineSchema(t *testing.T) {
	schema, err := os.ReadFile("testdata/sarif-schema.json")
	if err != nil {
		t.Fatalf("failed to read schema: %v", err)
	}
	valid, err := os.ReadFile("testdata/trivy_scan_report.json")
	if err != nil {
		t.Fatalf("failed to read valid report: %v", err)
	}
	if err := validateAgainstOfflineSchema(schema, valid); err != nil {
		t.Fatalf("expected valid report to pass: %v", err)
	}

	mismatch, err := os.ReadFile("testdata/mismatch_schema.json")
	if err != nil {
		t.Fatalf("failed to read mismatch report: %v", err)
	}
	if err := validateAgainstOfflineSchema(schema, mismatch); err == nil {
		t.Fatal("expected mismatch report to fail validation")
	}
}

func TestVerify(t *testing.T) {
	schemaURL := "file://" + absPath(t, "testdata/sarif-schema.json")
	validReport := mustRead(t, "testdata/trivy_scan_report.json")
	mismatchReport := mustRead(t, "testdata/mismatch_schema.json")

	tests := []struct {
		name        string
		schemas     map[string]string
		store       *mockStore
		wantErr     bool
		wantFailure bool
	}{
		{
			name:    "valid report",
			schemas: map[string]string{sarifMediaType: schemaURL},
			store:   &mockStore{manifest: manifestWithLayer(sarifMediaType), blob: validReport},
		},
		{
			name:        "schema mismatch",
			schemas:     map[string]string{sarifMediaType: schemaURL},
			store:       &mockStore{manifest: manifestWithLayer(sarifMediaType), blob: mismatchReport},
			wantFailure: true,
		},
		{
			name:        "media type not configured",
			schemas:     map[string]string{sarifMediaType: schemaURL},
			store:       &mockStore{manifest: manifestWithLayer("application/other"), blob: validReport},
			wantFailure: true,
		},
		{
			name:        "no blobs",
			schemas:     map[string]string{sarifMediaType: schemaURL},
			store:       &mockStore{manifest: &ocispec.Manifest{}},
			wantFailure: true,
		},
		{
			name:    "manifest error",
			schemas: map[string]string{sarifMediaType: schemaURL},
			store:   &mockStore{manifestErr: errors.New("boom")},
			wantErr: true,
		},
		{
			name:    "blob error",
			schemas: map[string]string{sarifMediaType: schemaURL},
			store:   &mockStore{manifest: manifestWithLayer(sarifMediaType), blobErr: errors.New("boom")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := NewVerifier(&VerifierOptions{Name: testVerifierName, Schemas: tt.schemas})
			result, err := v.Verify(context.Background(), &ratify.VerifyOptions{
				Store:              tt.store,
				Repository:         testRepo,
				ArtifactDescriptor: ocispec.Descriptor{ArtifactType: sarifMediaType, Digest: testDigest},
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantFailure && result.Err == nil {
				t.Fatal("expected verification failure")
			}
			if !tt.wantFailure && result.Err != nil {
				t.Fatalf("unexpected verification failure: %v", result.Err)
			}
		})
	}
}

func absPath(t *testing.T, rel string) string {
	t.Helper()
	p, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return p + "/" + rel
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return b
}
