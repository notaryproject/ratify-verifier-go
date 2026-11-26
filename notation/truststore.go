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
	"fmt"

	"github.com/notaryproject/notation-go/verifier/truststore"
	ratifyplugin "github.com/notaryproject/ratify-go/plugin"
)

// trustStore implements [truststore.X509TrustStore] on top of key providers.
type trustStore struct {
	stores map[truststore.Type]map[string][]ratifyplugin.KeyProvider
}

func newTrustStore() *trustStore {
	return &trustStore{
		stores: make(map[truststore.Type]map[string][]ratifyplugin.KeyProvider),
	}
}

// GetCertificates implements [truststore.X509TrustStore] interface.
func (s *trustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	keyProviders, ok := s.stores[storeType][namedStore]
	if !ok {
		return nil, nil
	}
	var allCerts []*x509.Certificate
	for _, keyProvider := range keyProviders {
		certs, err := keyProvider.GetCertificates(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificates from key provider for trust store %s:%s: %w", storeType, namedStore, err)
		}
		allCerts = append(allCerts, certs...)
	}
	return allCerts, nil
}

// addKeyProvider adds a key provider to the trust store.
func (s *trustStore) addKeyProvider(storeType truststore.Type, namedStore string, keyProvider ratifyplugin.KeyProvider) {
	if s.stores[storeType] == nil {
		s.stores[storeType] = make(map[string][]ratifyplugin.KeyProvider)
	}
	s.stores[storeType][namedStore] = append(s.stores[storeType][namedStore], keyProvider)
}
