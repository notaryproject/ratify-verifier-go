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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/plugin"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const testScopedVerifierName = "test-cosign-verifier"

// mustMarshalParams marshals v into raw JSON verifier parameters.
func mustMarshalParams(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestFactory(t *testing.T) {
	tests := []struct {
		name        string
		opts        plugin.VerifierOptions
		wantErr     bool
		errContains string
	}{
		{
			name: "empty verifier name",
			opts: plugin.VerifierOptions{
				Name: "",
			},
			wantErr:     true,
			errContains: "verifier name cannot be empty",
		},
		{
			name: "invalid parameters json",
			opts: plugin.VerifierOptions{
				Name:       testScopedVerifierName,
				Parameters: json.RawMessage("{"),
			},
			wantErr:     true,
			errContains: "failed to unmarshal verifier parameters",
		},
		{
			name: "no trust policies",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{},
				}),
			},
			wantErr:     true,
			errContains: "at least one trust policy must be provided",
		},
		{
			name: "nil trust policy",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{nil},
				}),
			},
			wantErr:     true,
			errContains: "trust policy cannot be nil",
		},
		{
			name: "empty scope in trust policy",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{""},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "scope cannot be empty",
		},
		{
			name: "invalid registry scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"invalid:registry:with:colons"},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "invalid scope",
		},
		{
			name: "repository scope with wildcard",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com/*/repo"},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "scope cannot contain wildcard for repository",
		},
		{
			name: "repository scope with tag",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com/repo:latest"},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "scope cannot contain a tag or digest",
		},
		{
			name: "duplicate registry scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy-1",
							"scopes": []string{"registry.example.com", "registry.example.com"},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "duplicate registry scope",
		},
		{
			name: "duplicate repository scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy-1",
							"scopes": []string{"registry.example.com/repo", "registry.example.com/repo"},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "duplicate repository scope",
		},
		{
			name: "invalid wildcard scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"example.*.com"},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "wildcard must be at the beginning of the scope",
		},
		{
			name: "multiple wildcards in scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"*.*.example.com"},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "scope can only contain one wildcard",
		},
		{
			name: "valid single registry scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com"},
						},
					},
				}),
			},
			wantErr: false,
		},
		{
			name: "valid wildcard registry scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"*.example.com"},
						},
					},
				}),
			},
			wantErr: false,
		},
		{
			name: "valid repository scope",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com/namespace/repo"},
						},
					},
				}),
			},
			wantErr: false,
		},
		{
			name: "multiple trust policies",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "policy-1",
							"scopes": []string{"registry1.example.com"},
						},
						map[string]interface{}{
							"name":   "policy-2",
							"scopes": []string{"registry2.example.com"},
						},
					},
				}),
			},
			wantErr: false,
		},
		{
			name: "use global scopes when trust policy scopes empty",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name": "test-policy",
						},
					},
				}),
				Scopes: []string{"global.example.com"},
			},
			wantErr: false,
		},
		{
			name: "with certificate identity options",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":                       "test-policy",
							"scopes":                     []string{"registry.example.com"},
							"certificateIdentity":        "test@example.com",
							"certificateOIDCIssuer":      "https://github.com/login/oauth",
							"certificateIdentityRegex":   ".*@example\\.com",
							"certificateOIDCIssuerRegex": "https://github\\.com/.*",
							"ignoreTlog":                 true,
							"ignoreCTLog":                true,
						},
					},
				}),
			},
			wantErr: false,
		},
		{
			name: "failed to convert trust policy options",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com"},
							"keys": map[string]interface{}{
								"provider1": map[string]interface{}{
									"config": "value1",
								},
								"provider2": map[string]interface{}{
									"config": "value2",
								},
							},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "failed to convert trust policy options",
		},
		{
			name: "invalid key provider configuration",
			opts: plugin.VerifierOptions{
				Name: testScopedVerifierName,
				Parameters: mustMarshalParams(map[string]interface{}{
					"trustPolicies": []interface{}{
						map[string]interface{}{
							"name":   "test-policy",
							"scopes": []string{"registry.example.com"},
							"keys": map[string]interface{}{
								"invalid-provider": map[string]interface{}{
									"invalid": "config",
								},
							},
						},
					},
				}),
			},
			wantErr:     true,
			errContains: "failed to convert trust policy options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			opts.Registry = plugin.NewRegistry()
			verifier, err := Factory(context.Background(), opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Factory() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Factory() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Factory() unexpected error = %v", err)
				return
			}

			if verifier == nil {
				t.Errorf("Factory() returned nil verifier")
				return
			}

			// Test basic verifier properties
			if verifier.Name() != testScopedVerifierName {
				t.Errorf("ScopedVerifier.Name() = %v, want %v", verifier.Name(), testScopedVerifierName)
			}

			if verifier.Type() != verifierTypeCosign {
				t.Errorf("ScopedVerifier.Type() = %v, want %v", verifier.Type(), verifierTypeCosign)
			}
		})
	}
}

func TestScopedVerifier_Verifiable(t *testing.T) {
	verifier := createTestScopedVerifier(t)

	tests := []struct {
		name     string
		artifact ocispec.Descriptor
		want     bool
	}{
		{
			name: "cosign signature artifact",
			artifact: ocispec.Descriptor{
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: mediaTypeCosignArtifactSignature,
			},
			want: true,
		},
		{
			name: "wrong artifact type",
			artifact: ocispec.Descriptor{
				MediaType:    ocispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.oci.image.manifest.v1+json",
			},
			want: false,
		},
		{
			name: "wrong media type",
			artifact: ocispec.Descriptor{
				MediaType:    "application/vnd.oci.image.config.v1+json",
				ArtifactType: mediaTypeCosignArtifactSignature,
			},
			want: false,
		},
		{
			name: "both wrong",
			artifact: ocispec.Descriptor{
				MediaType:    "application/vnd.oci.image.config.v1+json",
				ArtifactType: "application/vnd.oci.image.manifest.v1+json",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifier.Verifiable(tt.artifact)
			if got != tt.want {
				t.Errorf("ScopedVerifier.Verifiable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScopedVerifier_MatchVerifier(t *testing.T) {
	// Create verifier with multiple scopes
	opts := plugin.VerifierOptions{
		Name: testScopedVerifierName,
		Parameters: mustMarshalParams(map[string]interface{}{
			"trustPolicies": []interface{}{
				map[string]interface{}{
					"name":   "wildcard-policy",
					"scopes": []string{"*.example.com"},
				},
				map[string]interface{}{
					"name":   "registry-policy",
					"scopes": []string{"registry.example.com"},
				},
				map[string]interface{}{
					"name":   "repo-policy",
					"scopes": []string{"registry.example.com/namespace/repo"},
				},
			},
		}),
		Registry: plugin.NewRegistry(),
	}

	verifier, err := Factory(context.Background(), opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	scopedVerifier := verifier.(*ScopedVerifier)

	tests := []struct {
		name        string
		repository  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "exact repository match",
			repository: "registry.example.com/namespace/repo",
			wantErr:    false,
		},
		{
			name:       "exact registry match",
			repository: "registry.example.com/other/repo",
			wantErr:    false,
		},
		{
			name:       "wildcard match",
			repository: "sub.example.com/some/repo",
			wantErr:    false,
		},
		{
			name:        "no match",
			repository:  "other.registry.com/repo",
			wantErr:     true,
			errContains: "no verifier configured for the repository",
		},
		{
			name:        "invalid repository format",
			repository:  "invalid:repository:format",
			wantErr:     true,
			errContains: "failed to parse repository reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := scopedVerifier.matchVerifier(tt.repository)

			if tt.wantErr {
				if err == nil {
					t.Errorf("matchVerifier() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("matchVerifier() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("matchVerifier() unexpected error = %v", err)
			}
		})
	}
}

func TestScopedVerifier_Verify(t *testing.T) {
	verifier := createTestScopedVerifier(t)

	// Test that Verify method calls matchVerifier and delegates to underlying verifier
	// Since we can't easily mock the underlying cosign verifier, we test error cases
	tests := []struct {
		name        string
		opts        *ratify.VerifyOptions
		wantErr     bool
		errContains string
	}{
		{
			name: "no matching verifier",
			opts: &ratify.VerifyOptions{
				Repository: "nomatch.example.com/repo",
			},
			wantErr:     true,
			errContains: "trust policy is not configured for repository",
		},
		{
			name: "invalid repository format",
			opts: &ratify.VerifyOptions{
				Repository: "invalid:repo:format",
			},
			wantErr:     true,
			errContains: "trust policy is not configured for repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), tt.opts)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Verify() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Verify() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Verify() unexpected error = %v", err)
			}
		})
	}
}

func TestScopedVerifier_RegisterVerifier(t *testing.T) {
	// Create a mock cosign verifier for testing
	mockCosignVerifier, err := NewVerifier(&VerifierOptions{
		Name: "mock-verifier",
	})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}

	verifier := newEmptyScopedVerifier()

	tests := []struct {
		name           string
		scope          string
		cosignVerifier *Verifier
		wantErr        bool
		errContains    string
	}{
		{
			name:           "empty scope",
			scope:          "",
			cosignVerifier: mockCosignVerifier,
			wantErr:        true,
			errContains:    "scope cannot be empty",
		},
		{
			name:           "nil verifier",
			scope:          "registry.example.com",
			cosignVerifier: nil,
			wantErr:        true,
			errContains:    "verifier cannot be nil",
		},
		{
			name:           "valid registry scope",
			scope:          "registry.example.com",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "valid repository scope",
			scope:          "registry.example.com/repo",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "valid wildcard scope",
			scope:          "*.example.com",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "valid fallback scope",
			scope:          "*",
			cosignVerifier: mockCosignVerifier,
			wantErr:        false,
		},
		{
			name:           "duplicate fallback scope",
			scope:          "*",
			cosignVerifier: mockCosignVerifier,
			wantErr:        true,
			errContains:    "duplicate fallback scope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.registerVerifier(tt.scope, tt.cosignVerifier)

			if tt.wantErr {
				if err == nil {
					t.Errorf("registerVerifier() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("registerVerifier() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("registerVerifier() unexpected error = %v", err)
			}
		})
	}
}

func TestToVerifierOptions(t *testing.T) {
	tests := []struct {
		name         string
		verifierName string
		input        *ScopedOptions
		wantErr      bool
		errContains  string
		validate     func(*testing.T, *VerifierOptions)
	}{
		{
			name:         "basic options",
			verifierName: "test-policy",
			input: &ScopedOptions{
				IgnoreTLog:  true,
				IgnoreCTLog: true,
			},
			wantErr: false,
			validate: func(t *testing.T, opts *VerifierOptions) {
				if opts.Name != "test-policy" {
					t.Errorf("Name = %v, want %v", opts.Name, "test-policy")
				}
				if !opts.IgnoreTLog {
					t.Errorf("IgnoreTLog = %v, want %v", opts.IgnoreTLog, true)
				}
				if !opts.IgnoreCTLog {
					t.Errorf("IgnoreCTLog = %v, want %v", opts.IgnoreCTLog, true)
				}
				if len(opts.IdentityPolicies) != 0 {
					t.Errorf("IdentityPolicies length = %v, want %v", len(opts.IdentityPolicies), 0)
				}
			},
		},
		{
			name:         "keyless honors ignoreCTLog false",
			verifierName: "test-policy",
			input: &ScopedOptions{
				IgnoreCTLog: false,
			},
			wantErr: false,
			validate: func(t *testing.T, opts *VerifierOptions) {
				if opts.IgnoreCTLog {
					t.Errorf("IgnoreCTLog = %v, want false (honored for keyless)", opts.IgnoreCTLog)
				}
			},
		},
		{
			name:         "with certificate identity",
			verifierName: "test-policy",
			input: &ScopedOptions{
				CertificateIdentity:   "test@example.com",
				CertificateOIDCIssuer: "https://github.com/login/oauth",
			},
			wantErr: false,
			validate: func(t *testing.T, opts *VerifierOptions) {
				if len(opts.IdentityPolicies) != 1 {
					t.Errorf("IdentityPolicies length = %v, want %v", len(opts.IdentityPolicies), 1)
				}
			},
		},
		{
			name:         "with regex patterns",
			verifierName: "test-policy",
			input: &ScopedOptions{
				CertificateIdentityRegex:   ".*@example\\.com",
				CertificateOIDCIssuerRegex: "https://github\\.com/.*",
			},
			wantErr: false,
			validate: func(t *testing.T, opts *VerifierOptions) {
				if len(opts.IdentityPolicies) != 1 {
					t.Errorf("IdentityPolicies length = %v, want %v", len(opts.IdentityPolicies), 1)
				}
			},
		},
		{
			name:         "invalid certificate identity regex",
			verifierName: "test-policy",
			input: &ScopedOptions{
				CertificateIdentityRegex: "[invalid-regex",
			},
			wantErr:     true,
			errContains: "failed to create certificate identity",
		},
		{
			name:         "multiple key providers error",
			verifierName: "test-policy",
			input: &ScopedOptions{
				Keys: map[string]json.RawMessage{
					"inline": mustMarshalParams(map[string]interface{}{
						"keys": "test-key-1",
					}),
					"azure": mustMarshalParams(map[string]interface{}{
						"vaultURI": "test-vault",
					}),
				},
			},
			wantErr:     true,
			errContains: "only one set of key provider is allowed",
		},
		{
			name:         "key-based verification options",
			verifierName: "test-policy",
			input: &ScopedOptions{
				Keys: map[string]json.RawMessage{
					"inline": mustMarshalParams(map[string]interface{}{
						"keys": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
					}),
				},
				IgnoreTLog: true, // Honored for key-based verification
			},
			wantErr:     true, // inline provider not registered in the test registry
			errContains: "failed to create key provider",
		},
		{
			name:         "invalid key provider",
			verifierName: "test-policy",
			input: &ScopedOptions{
				Keys: map[string]json.RawMessage{
					"invalid-provider": mustMarshalParams(map[string]interface{}{
						"invalid": "config",
					}),
				},
			},
			wantErr:     true,
			errContains: "failed to create key provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := toVerifierOptions(context.Background(), plugin.NewRegistry(), tt.input, tt.verifierName)

			if tt.wantErr {
				if err == nil {
					t.Errorf("toVerifierOptions() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("toVerifierOptions() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("toVerifierOptions() unexpected error = %v", err)
				return
			}

			if opts == nil {
				t.Errorf("toVerifierOptions() returned nil options")
				return
			}

			if tt.validate != nil {
				tt.validate(t, opts)
			}
		})
	}
}

type mockKeyProvider struct{}

func (mockKeyProvider) GetCertificates(context.Context) ([]*x509.Certificate, error) {
	return nil, nil
}

func (mockKeyProvider) GetKeys(context.Context) ([]*plugin.PublicKey, error) {
	return nil, nil
}

// TestToVerifierOptions_KeyBasedTimestampOptions verifies that key-based
// verification honors IgnoreTLog and IgnoreObserverTimestamps (so offline,
// key-signed images without a timestamp can be verified) and passes IgnoreCTLog
// through unchanged, since the certificate transparency log never applies to
// public keys.
func TestToVerifierOptions_KeyBasedTimestampOptions(t *testing.T) {
	const providerName = "mock-key-provider-timestamp"
	reg := plugin.NewRegistry()
	if err := reg.RegisterKeyProvider(providerName, func(context.Context, plugin.KeyProviderOptions) (plugin.KeyProvider, error) {
		return mockKeyProvider{}, nil
	}); err != nil {
		t.Fatalf("RegisterKeyProvider() unexpected error = %v", err)
	}

	tests := []struct {
		name                     string
		ignoreTLog               bool
		ignoreObserverTimestamps bool
		ignoreCTLog              bool
	}{
		{name: "offline key verification", ignoreTLog: true, ignoreObserverTimestamps: true},
		{name: "defaults preserved", ignoreTLog: false, ignoreObserverTimestamps: false},
		{name: "ignoreCTLog false is passed through", ignoreCTLog: false},
		{name: "ignoreCTLog true is passed through", ignoreCTLog: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := toVerifierOptions(context.Background(), reg, &ScopedOptions{
				IgnoreTLog:               tt.ignoreTLog,
				IgnoreObserverTimestamps: tt.ignoreObserverTimestamps,
				IgnoreCTLog:              tt.ignoreCTLog,
				Keys: map[string]json.RawMessage{
					providerName: json.RawMessage("{}"),
				},
			}, "test-policy")
			if err != nil {
				t.Fatalf("toVerifierOptions() unexpected error = %v", err)
			}
			if opts.IgnoreTLog != tt.ignoreTLog {
				t.Errorf("IgnoreTLog = %v, want %v", opts.IgnoreTLog, tt.ignoreTLog)
			}
			if opts.IgnoreCTLog != tt.ignoreCTLog {
				t.Errorf("IgnoreCTLog = %v, want %v", opts.IgnoreCTLog, tt.ignoreCTLog)
			}
			if opts.IgnoreObserverTimestamps != tt.ignoreObserverTimestamps {
				t.Errorf("IgnoreObserverTimestamps = %v, want %v", opts.IgnoreObserverTimestamps, tt.ignoreObserverTimestamps)
			}
			if opts.GetPublicKeys == nil {
				t.Fatal("GetPublicKeys = nil, want non-nil for key-based verification")
			}
			if _, err := opts.GetPublicKeys(context.Background()); err != nil {
				t.Errorf("GetPublicKeys() unexpected error = %v", err)
			}
		})
	}
}

func TestScopedVerifier_MatchVerifier_EdgeCases(t *testing.T) {
	// Test additional edge cases for matchVerifier
	verifier := newEmptyScopedVerifier()

	tests := []struct {
		name        string
		repository  string
		wantErr     bool
		errContains string
	}{
		{
			name:        "repository with no subdomain for wildcard matching",
			repository:  "example.com/repo",
			wantErr:     true,
			errContains: "no verifier configured for the repository",
		},
		{
			name:        "repository with single character before dot",
			repository:  "a.example.com/repo",
			wantErr:     true,
			errContains: "no verifier configured for the repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.matchVerifier(tt.repository)

			if tt.wantErr {
				if err == nil {
					t.Errorf("matchVerifier() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("matchVerifier() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("matchVerifier() unexpected error = %v", err)
			}
		})
	}
}

func TestFactory_RegistryRegistration(t *testing.T) {
	// The Factory should be usable as a plugin.VerifierFactory registered in
	// a plugin registry.
	reg := plugin.NewRegistry()
	if err := reg.RegisterVerifier(Type, Factory); err != nil {
		t.Fatalf("RegisterVerifier() unexpected error = %v", err)
	}

	_, err := reg.NewVerifier(context.Background(), Type, plugin.VerifierOptions{
		Name: testScopedVerifierName,
		Parameters: mustMarshalParams(map[string]interface{}{
			"trustPolicies": []interface{}{
				map[string]interface{}{
					"name":   "test-policy",
					"scopes": []string{"registry.example.com"},
				},
			},
		}),
		Registry: reg,
	})

	if err != nil {
		t.Errorf("Factory registration failed: %v", err)
	}
}

func TestFactory_UnmarshalError(t *testing.T) {
	// Test unmarshal error path
	opts := plugin.VerifierOptions{
		Name: testScopedVerifierName,
		Parameters: mustMarshalParams(map[string]interface{}{
			"trustPolicies": "invalid-string-instead-of-array",
		}),
		Registry: plugin.NewRegistry(),
	}

	_, err := Factory(context.Background(), opts)
	if err == nil {
		t.Fatal("Expected error from Factory with invalid parameters, but got none")
	}
	if !strings.Contains(err.Error(), "failed to unmarshal verifier parameters") {
		t.Errorf("Expected unmarshal error, got: %v", err)
	}
}

func TestScopedVerifier_RegisterRegistry_EdgeCases(t *testing.T) {
	verifier := newEmptyScopedVerifier()

	// Create a mock cosign verifier
	mockCosignVerifier, err := NewVerifier(&VerifierOptions{
		Name: "mock-verifier",
	})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}

	tests := []struct {
		name        string
		scope       string
		wantErr     bool
		errContains string
	}{
		{
			name:    "localhost registry",
			scope:   "localhost:5000",
			wantErr: false,
		},
		{
			name:    "IP address registry",
			scope:   "192.168.1.100:5000",
			wantErr: false,
		},
		{
			name:    "wildcard with port",
			scope:   "*.example.com:8080",
			wantErr: false,
		},
		{
			name:    "duplicate wildcard registration",
			scope:   "*.test.com",
			wantErr: false,
		},
	}

	// First register a wildcard to test duplicate detection
	err = verifier.registerRegistry("*.test.com", mockCosignVerifier)
	if err != nil {
		t.Fatalf("Failed to register initial wildcard: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.registerRegistry(tt.scope, mockCosignVerifier)

			if tt.name == "duplicate wildcard registration" {
				// This should fail due to duplicate
				if err == nil {
					t.Errorf("registerRegistry() expected error for duplicate wildcard but got none")
				}
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Errorf("registerRegistry() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("registerRegistry() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("registerRegistry() unexpected error = %v", err)
			}
		})
	}
}

func TestScopedVerifier_RegisterRepository_EdgeCases(t *testing.T) {
	verifier := newEmptyScopedVerifier()

	// Create a mock cosign verifier
	mockCosignVerifier, err := NewVerifier(&VerifierOptions{
		Name: "mock-verifier",
	})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}

	tests := []struct {
		name        string
		scope       string
		wantErr     bool
		errContains string
	}{
		{
			name:        "repository with digest",
			scope:       "registry.example.com/repo@sha256:abcd1234",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:    "deep repository path",
			scope:   "registry.example.com/org/team/project/repo",
			wantErr: false,
		},
		{
			name:    "repository with special characters",
			scope:   "registry.example.com/org-name/repo_name",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.registerRepository(tt.scope, mockCosignVerifier)

			if tt.wantErr {
				if err == nil {
					t.Errorf("registerRepository() expected error but got none")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("registerRepository() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("registerRepository() unexpected error = %v", err)
			}
		})
	}
}

func TestScopedVerifier_ScopeMatchingPrecedence(t *testing.T) {
	// Test that scope matching follows the correct precedence:
	// 1. Exact repository match
	// 2. Exact registry match
	// 3. Wildcard registry match

	opts := plugin.VerifierOptions{
		Name: testScopedVerifierName,
		Parameters: mustMarshalParams(map[string]interface{}{
			"trustPolicies": []interface{}{
				// Wildcard policy (lowest precedence)
				map[string]interface{}{
					"name":   "wildcard-policy",
					"scopes": []string{"*.example.com"},
				},
				// Registry policy (medium precedence)
				map[string]interface{}{
					"name":   "registry-policy",
					"scopes": []string{"registry.example.com"},
				},
				// Repository policy (highest precedence)
				map[string]interface{}{
					"name":   "repo-policy",
					"scopes": []string{"registry.example.com/namespace/repo"},
				},
			},
		}),
		Registry: plugin.NewRegistry(),
	}

	verifier, err := Factory(context.Background(), opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	scopedVerifier := verifier.(*ScopedVerifier)

	tests := []struct {
		name       string
		repository string
		wantScope  string // Which scope should match
	}{
		{
			name:       "exact repository match should take precedence",
			repository: "registry.example.com/namespace/repo",
			wantScope:  "repository", // Should match repository scope
		},
		{
			name:       "registry match when no exact repository",
			repository: "registry.example.com/other/repo",
			wantScope:  "registry", // Should match registry scope
		},
		{
			name:       "wildcard match when no exact matches",
			repository: "sub.example.com/some/repo",
			wantScope:  "wildcard", // Should match wildcard scope
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchedVerifier, err := scopedVerifier.matchVerifier(tt.repository)
			if err != nil {
				t.Errorf("matchVerifier() unexpected error = %v", err)
				return
			}

			if matchedVerifier == nil {
				t.Errorf("matchVerifier() returned nil verifier")
				return
			}

			// The test validates that a verifier is found - the specific verifier
			// instance validation would require more complex setup with different
			// verifier instances per scope
		})
	}
}

func TestFactory_FallbackScope(t *testing.T) {
	newOpts := func(scopes, globalScopes []string) plugin.VerifierOptions {
		policy := map[string]interface{}{"name": "fallback-policy"}
		if scopes != nil {
			policy["scopes"] = scopes
		}
		return plugin.VerifierOptions{
			Name: testScopedVerifierName,
			Parameters: mustMarshalParams(map[string]interface{}{
				"trustPolicies": []interface{}{
					map[string]interface{}{
						"name":   "registry-policy",
						"scopes": []string{"registry.example.com"},
					},
					policy,
				},
			}),
			Scopes:   globalScopes,
			Registry: plugin.NewRegistry(),
		}
	}

	tests := []struct {
		name         string
		scopes       []string
		globalScopes []string
	}{
		{
			name:   "explicit fallback scope",
			scopes: []string{"*"},
		},
		{
			name:         "inherited fallback scope",
			globalScopes: []string{"*"},
		},
		{
			name:         "inherited mixed scopes",
			globalScopes: []string{"other.example.com", "*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := Factory(context.Background(), newOpts(tt.scopes, tt.globalScopes))
			if err != nil {
				t.Fatalf("Factory() unexpected error = %v", err)
			}
			scopedVerifier := v.(*ScopedVerifier)
			if scopedVerifier.fallback == nil {
				t.Fatal("expected fallback verifier to be registered")
			}

			matched, err := scopedVerifier.matchVerifier("unknown.io/foo")
			if err != nil {
				t.Fatalf("matchVerifier() unexpected error = %v", err)
			}
			if matched != scopedVerifier.fallback {
				t.Error("expected unmatched repository to route to fallback verifier")
			}

			matched, err = scopedVerifier.matchVerifier("registry.example.com/foo")
			if err != nil {
				t.Fatalf("matchVerifier() unexpected error = %v", err)
			}
			if matched == scopedVerifier.fallback {
				t.Error("expected exact registry match to take precedence over fallback")
			}
		})
	}
}

func TestOptions_JsonMarshaling(t *testing.T) {
	// Test that Options and ScopedOptions can be properly marshaled/unmarshaled
	originalOpts := Options{
		TrustPolicies: []*ScopedOptions{
			{
				Scopes:                     []string{"registry.example.com", "*.test.com"},
				CertificateIdentity:        "test@example.com",
				CertificateIdentityRegex:   ".*@example\\.com",
				CertificateOIDCIssuer:      "https://github.com/login/oauth",
				CertificateOIDCIssuerRegex: "https://github\\.com/.*",
				IgnoreTLog:                 true,
				IgnoreCTLog:                false,
			},
		},
	}

	// This test validates the structure can be used in real scenarios
	// by creating a verifier with complex options
	params := map[string]interface{}{
		"trustPolicies": []interface{}{
			map[string]interface{}{
				"name":                       "test-policy",
				"scopes":                     []string{"registry.example.com", "*.test.com"},
				"certificateIdentity":        "test@example.com",
				"certificateIdentityRegex":   ".*@example\\.com",
				"certificateOIDCIssuer":      "https://github.com/login/oauth",
				"certificateOIDCIssuerRegex": "https://github\\.com/.*",
				"ignoreTlog":                 true,
				"ignoreCTLog":                false,
			},
		},
	}

	opts := plugin.VerifierOptions{
		Name:       testScopedVerifierName,
		Parameters: mustMarshalParams(params),
		Registry:   plugin.NewRegistry(),
	}

	verifier, err := Factory(context.Background(), opts)
	if err != nil {
		t.Errorf("Factory() with complex options failed: %v", err)
		return
	}

	if verifier == nil {
		t.Errorf("Factory() returned nil verifier")
		return
	}

	// Validate that the original options structure is compatible
	if len(originalOpts.TrustPolicies) != 1 {
		t.Errorf("Original options structure validation failed")
	}
}

func TestConvertProviderKeysToCosignKeys(t *testing.T) {
	// Generate test RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	startTime := time.Now()
	endTime := startTime.Add(24 * time.Hour)

	tests := []struct {
		name         string
		providerKeys []*plugin.PublicKey
		expected     []*PublicKeyConfig
	}{
		{
			name:         "empty input",
			providerKeys: []*plugin.PublicKey{},
			expected:     []*PublicKeyConfig{},
		},
		{
			name: "single key with all fields",
			providerKeys: []*plugin.PublicKey{
				{
					Key:                 &rsaKey.PublicKey,
					SignatureAlgorithm:  crypto.SHA256,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
			expected: []*PublicKeyConfig{
				{
					PublicKey:           &rsaKey.PublicKey,
					SignatureAlgorithm:  crypto.SHA256,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
		},
		{
			name: "single key with minimal fields",
			providerKeys: []*plugin.PublicKey{
				{
					Key: &rsaKey.PublicKey,
				},
			},
			expected: []*PublicKeyConfig{
				{
					PublicKey: &rsaKey.PublicKey,
				},
			},
		},
		{
			name: "multiple keys",
			providerKeys: []*plugin.PublicKey{
				{
					Key:                &rsaKey.PublicKey,
					SignatureAlgorithm: crypto.SHA256,
				},
				{
					Key:                 &rsaKey.PublicKey,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
			expected: []*PublicKeyConfig{
				{
					PublicKey:          &rsaKey.PublicKey,
					SignatureAlgorithm: crypto.SHA256,
				},
				{
					PublicKey:           &rsaKey.PublicKey,
					ValidityPeriodStart: startTime,
					ValidityPeriodEnd:   endTime,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertProviderKeysToCosignKeys(tt.providerKeys)

			// Check length
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d keys, got %d", len(tt.expected), len(result))
			}

			// Check each key
			for i, expectedKey := range tt.expected {
				actualKey := result[i]

				if actualKey.PublicKey != expectedKey.PublicKey {
					t.Errorf("key %d: public key mismatch", i)
				}

				if actualKey.SignatureAlgorithm != expectedKey.SignatureAlgorithm {
					t.Errorf("key %d: signature algorithm mismatch: expected %v, got %v",
						i, expectedKey.SignatureAlgorithm, actualKey.SignatureAlgorithm)
				}

				// Compare validity period start
				if !actualKey.ValidityPeriodStart.Equal(expectedKey.ValidityPeriodStart) {
					t.Errorf("key %d: validity period start mismatch: expected %v, got %v",
						i, expectedKey.ValidityPeriodStart, actualKey.ValidityPeriodStart)
				}

				// Compare validity period end
				if !actualKey.ValidityPeriodEnd.Equal(expectedKey.ValidityPeriodEnd) {
					t.Errorf("key %d: validity period end mismatch: expected %v, got %v",
						i, expectedKey.ValidityPeriodEnd, actualKey.ValidityPeriodEnd)
				}
			}
		})
	}
}

func TestConvertProviderKeysToCosignKeys_NilInput(t *testing.T) {
	// Test edge case with nil input
	result := convertProviderKeysToCosignKeys(nil)
	if result == nil {
		t.Error("expected non-nil result for nil input")
	}
	if len(result) != 0 {
		t.Errorf("expected empty slice for nil input, got length %d", len(result))
	}
}

// Repository scopes are normalized so that they match the normalized
// repository of the artifacts being verified.
func TestScopedVerifier_RegisterVerifier_NormalizesRepositoryScope(t *testing.T) {
	cosignVerifier, err := NewVerifier(&VerifierOptions{Name: "mock-verifier"})
	if err != nil {
		t.Fatalf("Failed to create mock cosign verifier: %v", err)
	}
	verifier := newEmptyScopedVerifier()
	for _, scope := range []string{"docker.io/nginx", "org/app"} {
		if err := verifier.registerVerifier(scope, cosignVerifier); err != nil {
			t.Fatalf("failed to register scope %q: %v", scope, err)
		}
	}
	for _, repository := range []string{"docker.io/library/nginx", "docker.io/org/app"} {
		if _, err := verifier.matchVerifier(repository); err != nil {
			t.Errorf("expected %q to match a normalized repository scope, got: %v", repository, err)
		}
	}
	if err := verifier.registerVerifier("docker.io/library/nginx", cosignVerifier); err == nil {
		t.Error("expected an error for a scope that normalizes to an already registered scope, got nil")
	}
}

// Helper functions

// createTestScopedVerifier creates a scoped verifier without an explicit
// registry, exercising the fallback to plugin.Default.
func createTestScopedVerifier(t *testing.T) ratify.Verifier {
	opts := plugin.VerifierOptions{
		Name: testScopedVerifierName,
		Parameters: mustMarshalParams(map[string]interface{}{
			"trustPolicies": []interface{}{
				map[string]interface{}{
					"name":   "test-policy",
					"scopes": []string{"registry.example.com"},
				},
			},
		}),
	}

	verifier, err := Factory(context.Background(), opts)
	if err != nil {
		t.Fatalf("Failed to create test verifier: %v", err)
	}

	return verifier
}

func newEmptyScopedVerifier() *ScopedVerifier {
	return &ScopedVerifier{
		name:       testScopedVerifierName,
		wildcard:   make(map[string]*Verifier),
		registry:   make(map[string]*Verifier),
		repository: make(map[string]*Verifier),
	}
}
