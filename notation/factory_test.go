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
	"reflect"
	"testing"

	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify-go"
	ratifyplugin "github.com/notaryproject/ratify-go/plugin"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const mockKeyProviderType = "mock-key-provider"

type mockKeyProvider struct {
	ReturnErr bool `json:"returnErr"`
	LeafCert  bool `json:"leafCert"`
}

func (m *mockKeyProvider) GetCertificates(_ context.Context) ([]*x509.Certificate, error) {
	if m.ReturnErr {
		return nil, errors.New("mock error")
	}
	return []*x509.Certificate{{Subject: pkix.Name{CommonName: "test-cert"}, IsCA: !m.LeafCert}}, nil
}

func (m *mockKeyProvider) GetKeys(_ context.Context) ([]*ratifyplugin.PublicKey, error) {
	return nil, nil
}

func newTestRegistry(t *testing.T) *ratifyplugin.Registry {
	t.Helper()
	r := ratifyplugin.NewRegistry()
	if err := r.RegisterVerifier(Type, Factory); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterKeyProvider(mockKeyProviderType, func(_ context.Context, opts ratifyplugin.KeyProviderOptions) (ratifyplugin.KeyProvider, error) {
		p := &mockKeyProvider{}
		if err := ratifyplugin.DecodeParameters(opts.Parameters, p); err != nil {
			return nil, err
		}
		return p, nil
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFactory(t *testing.T) {
	tests := []struct {
		name      string
		params    string
		expectErr bool
	}{
		{name: "malformed params", params: `{`, expectErr: true},
		{name: "missing trust store options", params: `{}`, expectErr: true},
		{name: "invalid trust store type", params: `{"certificates":[{"type":"invalid"}]}`, expectErr: true},
		{name: "non-string trust store type", params: `{"certificates":[{"type":1}]}`, expectErr: true},
		{name: "duplicate trust store type", params: `{"certificates":[{"type":"ca"},{"type":"ca"}]}`, expectErr: true},
		{name: "unregistered key provider", params: `{"certificates":[{"unknown":{}}]}`, expectErr: true},
		{name: "key provider fails", params: `{"certificates":[{"mock-key-provider":{"returnErr":true}}]}`, expectErr: true},
		{name: "invalid certificate", params: `{"certificates":[{"mock-key-provider":{"leafCert":true}}]}`, expectErr: true},
		{name: "valid options", params: `{"certificates":[{"type":"ca","mock-key-provider":{}},{"type":"tsa","mock-key-provider":{}}]}`},
		{name: "valid options with signing authority", params: `{"scopes":["docker.io/nginx"],"trustedIdentities":["x509.subject: C=US, ST=WA, O=Test, CN=test"],"certificates":[{"type":"signingAuthority","mock-key-provider":{}}]}`},
	}

	r := newTestRegistry(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := r.NewVerifier(context.Background(), Type, ratifyplugin.VerifierOptions{
				Name:       testVerifierName,
				Parameters: json.RawMessage(tt.params),
			})
			if (err != nil) != tt.expectErr {
				t.Fatalf("NewVerifier() error = %v, expectErr %v", err, tt.expectErr)
			}
			if err == nil && (v.Name() != testVerifierName || v.Type() != Type) {
				t.Fatalf("unexpected verifier: %s/%s", v.Name(), v.Type())
			}
		})
	}
}

func TestFactory_DefaultRegistry(t *testing.T) {
	// A nil registry falls back to the default registry, where the mock key
	// provider is not registered.
	_, err := Factory(context.Background(), ratifyplugin.VerifierOptions{
		Name:       testVerifierName,
		Parameters: json.RawMessage(`{"certificates":[{"mock-key-provider":{}}]}`),
	})
	if !errors.Is(err, ratifyplugin.ErrNotRegistered) {
		t.Fatalf("expected ErrNotRegistered, got %v", err)
	}
}

func TestNewVerifierOptions(t *testing.T) {
	r := newTestRegistry(t)
	opts, err := newVerifierOptions(context.Background(), ratifyplugin.VerifierOptions{
		Name:     testVerifierName,
		Registry: r,
		// executor scopes must not leak into the Notation trust policy
		Scopes: []string{"*.example.com"},
		Parameters: json.RawMessage(`{
			"scopes": ["docker.io/nginx", "docker.io/library/nginx", "example.com/app"],
			"certificates": [{"mock-key-provider": {}}],
			"pluginDirectory": "/.ratify/plugins",
			"pluginConfig": {"aws-region": "us-west-2"}
		}`),
	})
	if err != nil {
		t.Fatalf("newVerifierOptions() error = %v", err)
	}

	policy := opts.TrustPolicyDoc.TrustPolicies[0]
	if want := []string{"docker.io/library/nginx", "example.com/app"}; !reflect.DeepEqual(policy.RegistryScopes, want) {
		t.Errorf("RegistryScopes = %v, want %v", policy.RegistryScopes, want)
	}
	if want := []string{"*"}; !reflect.DeepEqual(policy.TrustedIdentities, want) {
		t.Errorf("TrustedIdentities = %v, want %v", policy.TrustedIdentities, want)
	}
	if want := []string{"ca:ratify"}; !reflect.DeepEqual(policy.TrustStores, want) {
		t.Errorf("TrustStores = %v, want %v", policy.TrustStores, want)
	}
	if _, ok := opts.PluginManager.(*plugin.CLIManager); !ok {
		t.Errorf("PluginManager = %T, want *plugin.CLIManager", opts.PluginManager)
	}
	if want := map[string]string{"aws-region": "us-west-2"}; !reflect.DeepEqual(opts.PluginConfig, want) {
		t.Errorf("PluginConfig = %v, want %v", opts.PluginConfig, want)
	}
	certs, err := opts.TrustStore.GetCertificates(context.Background(), truststore.TypeCA, trustStoreName)
	if err != nil || len(certs) != 1 {
		t.Errorf("GetCertificates() = %v, %v", certs, err)
	}
}

func TestNewVerifierOptions_NoPluginDirectory(t *testing.T) {
	opts, err := newVerifierOptions(context.Background(), ratifyplugin.VerifierOptions{
		Name:       testVerifierName,
		Registry:   newTestRegistry(t),
		Parameters: json.RawMessage(`{"certificates":[{"mock-key-provider":{}}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.PluginManager != nil {
		t.Errorf("PluginManager = %v, want nil", opts.PluginManager)
	}
	if want := []string{"*"}; !reflect.DeepEqual(opts.TrustPolicyDoc.TrustPolicies[0].RegistryScopes, want) {
		t.Errorf("RegistryScopes = %v, want %v", opts.TrustPolicyDoc.TrustPolicies[0].RegistryScopes, want)
	}
}

func TestTrustStore(t *testing.T) {
	s := newTrustStore()
	ctx := context.Background()
	if certs, err := s.GetCertificates(ctx, truststore.TypeCA, trustStoreName); err != nil || certs != nil {
		t.Fatalf("empty store: %v, %v", certs, err)
	}
	s.addKeyProvider(truststore.TypeCA, trustStoreName, &mockKeyProvider{})
	s.addKeyProvider(truststore.TypeCA, trustStoreName, &mockKeyProvider{})
	if certs, err := s.GetCertificates(ctx, truststore.TypeCA, trustStoreName); err != nil || len(certs) != 2 {
		t.Fatalf("GetCertificates() = %v, %v", certs, err)
	}
	s.addKeyProvider(truststore.TypeTSA, trustStoreName, &mockKeyProvider{ReturnErr: true})
	if _, err := s.GetCertificates(ctx, truststore.TypeTSA, trustStoreName); err == nil {
		t.Fatal("expected error from key provider")
	}
}

func TestVerifyPassesPluginConfig(t *testing.T) {
	mock := &mockVerifier{verifySucceeded: true}
	pluginConfig := map[string]string{"aws-region": "us-east-1"}
	v := &Verifier{name: testVerifierName, verifier: mock, pluginConfig: pluginConfig}

	manifest := &ocispec.Manifest{Layers: []ocispec.Descriptor{{MediaType: "application/jose+json"}}}
	_, err := v.Verify(context.Background(), &ratify.VerifyOptions{
		Repository: testRepo,
		Store:      &mockStore{manifest: manifest, signatureBlob: []byte("sig")},
	})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !reflect.DeepEqual(mock.lastVerifyOpts.PluginConfig, pluginConfig) {
		t.Fatalf("PluginConfig = %v, want %v", mock.lastVerifyOpts.PluginConfig, pluginConfig)
	}
}
