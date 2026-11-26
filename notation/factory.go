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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify-go"
	"github.com/notaryproject/ratify-go/imageref"
	ratifyplugin "github.com/notaryproject/ratify-go/plugin"
)

const (
	// Type is the plugin type of the Notation verifier.
	Type = notationVerifierType

	trustStoreName = "ratify"
	typeKey        = "type"
)

// TrustStoreOptions configures one trust store of the Notation verifier. The
// value of the "type" key must be one of "ca", "tsa" or "signingAuthority" and
// defaults to "ca". Every other key is the type of a registered key provider,
// and its value is the configuration of that key provider. For example:
//
//	{"type": "ca", "inline": {"type": "ca", "value": "-----BEGIN CERTIFICATE-----..."}}
type TrustStoreOptions map[string]json.RawMessage

// Options is the configuration of the Notation verifier plugin. It is the
// schema of the "parameters" field of a verifier of type "notation".
type Options struct {
	// Scopes is a list of repository scopes covered by the trust policy.
	// Optional. Defaults to "*".
	Scopes []string `json:"scopes,omitempty"`

	// TrustedIdentities is a list of trusted identities. Optional. Defaults to
	// "*".
	TrustedIdentities []string `json:"trustedIdentities,omitempty"`

	// Certificates configures the trust stores. Required.
	Certificates []TrustStoreOptions `json:"certificates"`

	// PluginDirectory is the directory that contains Notation verification
	// plugins, such as the AWS Signer plugin. It uses the same layout as the
	// Notation CLI: <PluginDirectory>/<plugin-name>/notation-<plugin-name>.
	// Signatures that require a verification plugin fail if it is not set.
	// Optional.
	PluginDirectory string `json:"pluginDirectory,omitempty"`

	// PluginConfig is passed to the Notation verification plugins on every
	// verification. Optional.
	PluginConfig map[string]string `json:"pluginConfig,omitempty"`
}

// Factory creates a Notation verifier from plugin options. It implements
// [ratifyplugin.VerifierFactory]. Key providers referenced by the trust
// stores are resolved from opts.Registry.
func Factory(ctx context.Context, opts ratifyplugin.VerifierOptions) (ratify.Verifier, error) {
	verifierOpts, err := newVerifierOptions(ctx, opts)
	if err != nil {
		return nil, err
	}
	return NewVerifier(verifierOpts)
}

func newVerifierOptions(ctx context.Context, opts ratifyplugin.VerifierOptions) (*VerifierOptions, error) {
	var params Options
	if err := ratifyplugin.DecodeParameters(opts.Parameters, &params); err != nil {
		return nil, fmt.Errorf("failed to decode notation verifier parameters: %w", err)
	}
	registry := opts.Registry
	if registry == nil {
		registry = ratifyplugin.Default
	}

	trustStore, types, err := newTrustStoreFromOptions(ctx, registry, params.Certificates)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize trust store: %w", err)
	}

	// The executor scopes are not inherited because Notation trust policies
	// only accept repository scopes or "*", while executor scopes may also be
	// registries or wildcard registries.
	verifierOpts := &VerifierOptions{
		Name:           opts.Name,
		TrustPolicyDoc: newTrustPolicyDocument(params.Scopes, params.TrustedIdentities, types),
		TrustStore:     trustStore,
		PluginConfig:   params.PluginConfig,
	}
	if params.PluginDirectory != "" {
		verifierOpts.PluginManager = plugin.NewCLIManager(dir.NewSysFS(params.PluginDirectory))
	}
	return verifierOpts, nil
}

func newTrustStoreFromOptions(ctx context.Context, registry *ratifyplugin.Registry, opts []TrustStoreOptions) (*trustStore, []truststore.Type, error) {
	if len(opts) == 0 {
		return nil, nil, fmt.Errorf("no trust store options provided")
	}

	store := newTrustStore()
	types := make(map[truststore.Type]struct{})
	for _, opt := range opts {
		storeType := truststore.TypeCA
		if raw, ok := opt[typeKey]; ok {
			var err error
			if storeType, err = parseTrustStoreType(raw); err != nil {
				return nil, nil, err
			}
		}
		if _, exists := types[storeType]; exists {
			return nil, nil, fmt.Errorf("duplicate trust store type %s detected. Please check your configuration to ensure each trust store type is unique", storeType)
		}
		types[storeType] = struct{}{}

		// iterate in a stable order so that errors are deterministic
		providerTypes := make([]string, 0, len(opt))
		for key := range opt {
			if key != typeKey {
				providerTypes = append(providerTypes, key)
			}
		}
		sort.Strings(providerTypes)
		for _, providerType := range providerTypes {
			provider, err := registry.NewKeyProvider(ctx, providerType, ratifyplugin.KeyProviderOptions{
				Parameters: opt[providerType],
			})
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get key provider %s: %w", providerType, err)
			}
			if err := validateTrustStoreCertificates(ctx, provider); err != nil {
				return nil, nil, fmt.Errorf("failed to validate key provider %s certificates: %w", providerType, err)
			}
			store.addKeyProvider(storeType, trustStoreName, provider)
		}
	}

	names := make([]truststore.Type, 0, len(types))
	for storeType := range types {
		names = append(names, storeType)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return store, names, nil
}

func validateTrustStoreCertificates(ctx context.Context, provider ratifyplugin.KeyProvider) error {
	certs, err := provider.GetCertificates(ctx)
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		return nil
	}
	return truststore.ValidateCertificates(certs)
}

func parseTrustStoreType(raw json.RawMessage) (truststore.Type, error) {
	var t string
	if err := json.Unmarshal(raw, &t); err != nil {
		return "", fmt.Errorf("trust store type must be a string")
	}
	storeType := truststore.Type(t)
	if storeType != truststore.TypeCA && storeType != truststore.TypeTSA && storeType != truststore.TypeSigningAuthority {
		return "", fmt.Errorf("invalid trust store type %s", storeType)
	}
	return storeType, nil
}

func newTrustPolicyDocument(scopes, trustedIdentities []string, storeTypes []truststore.Type) *trustpolicy.Document {
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	// Normalize repository scopes so that they match the normalized
	// references of the artifacts being verified, e.g. "docker.io/nginx"
	// becomes "docker.io/library/nginx".
	scopes = imageref.NormalizeScopes(scopes)
	if len(trustedIdentities) == 0 {
		trustedIdentities = []string{"*"}
	}
	trustStoreNames := make([]string, len(storeTypes))
	for i, storeType := range storeTypes {
		trustStoreNames[i] = fmt.Sprintf("%s:%s", storeType, trustStoreName)
	}
	return &trustpolicy.Document{
		Version: "1.0",
		TrustPolicies: []trustpolicy.TrustPolicy{
			{
				Name:           "default",
				RegistryScopes: scopes,
				SignatureVerification: trustpolicy.SignatureVerification{
					VerificationLevel: "strict",
				},
				TrustStores:       trustStoreNames,
				TrustedIdentities: trustedIdentities,
			},
		},
	}
}
