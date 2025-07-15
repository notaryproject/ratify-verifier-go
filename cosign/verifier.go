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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	verifierTypeCosign        = "cosign"
	signatureArtifactCosign   = "application/vnd.dev.cosign.artifact.sig.v1+json"
	sigstoreBundleMediaType01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	annotationKeyBundle       = "dev.sigstore.cosign/bundle"
	AnnotationKeyCert         = "dev.sigstore.cosign/certificate"
	annotationKeySignature    = "dev.cosignproject.cosign/signature"
	mediaTypeSimpleSigning    = "application/vnd.dev.cosign.simplesigning.v1+json"
)

// PublicKeyConfig contains the configuration for key-based verification.
type PublicKeyConfig struct {
	// PublicKey for key-based verification.
	PublicKey crypto.PublicKey

	// SignatureAlgorithm defines the algorithm used for signature verification.
	// Optional. If not provided, defaults to SHA256.
	SignatureAlgorithm crypto.Hash

	// ValidityPeriodStart defines the start time for the public key validity
	// period. Optional. If not provided, the key is considered valid from the
	// beginning of time.
	ValidityPeriodStart time.Time

	// ValidityPeriodEnd defines the end time for the public key validity period.
	// Optional. If not provided, the key is considered valid until the end of
	// time.
	ValidityPeriodEnd time.Time
}

// VerifierOptions contains the options for creating a new Cosign verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// TrustedRoot defines the trusted root for verification. For keyless verification,
	// this will contain Fulcio certificates and Rekor public keys. Optional.
	// If not provided, the default Sigstore trusted root will be used.
	TrustedRoot *root.TrustedRoot

	// PublicKeyConfig contains the public key and its validity period for key-based verification.
	// If provided, key-based verification will be performed. Optional.
	PublicKeyConfigs []*PublicKeyConfig

	// IdentityPolicies contains policies for keyless verification.
	// These policies specify which OIDC identities are trusted. Optional.
	IdentityPolicies []verify.PolicyOption

	// IgnoreTlog when set to true, skips Artifact transparency log verification.
	// Only applies to keyless verification. Optional, defaults to false.
	IgnoreTlog bool

	// IgnoreCTLog when set to true, skips certificate transparency log verification.
	// Only applies to keyless verification. Optional, defaults to false.
	IgnoreCTLog bool

	// TUFOptions provides custom TUF client options for fetching trusted root.
	// Optional.
	TUFOptions *tuf.Options
}

// Verifier is a ratify.Verifier implementation that verifies Cosign signatures.
type Verifier struct {
	name             string
	identityPolicies []verify.PolicyOption
	ignoreTlog       bool
	verifier         *verify.Verifier
}

// NewVerifier creates a new Cosign verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name is required")
	}

	trustedMaterial := make(root.TrustedMaterialCollection, 0)

	// Key-based verification: create trusted material with the public keys
	for _, config := range opts.PublicKeyConfigs {
		if config == nil {
			return nil, fmt.Errorf("public key config cannot be nil")
		}
		if config.SignatureAlgorithm == 0 {
			// Default to SHA256 if no algorithm is specified
			config.SignatureAlgorithm = crypto.SHA256
		}
		trustedMaterial = append(trustedMaterial, createTrustedPublicKeyMaterial(config))
	}

	// Keyless verification: use provided trusted root or fetch from TUF
	if opts.TrustedRoot != nil {
		trustedMaterial = append(trustedMaterial, opts.TrustedRoot)
	} else {
		// Fetch default Sigstore trusted root
		if opts.TUFOptions == nil {
			opts.TUFOptions = tuf.DefaultOptions()
		}
		tufClient, err := tuf.New(opts.TUFOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUF client: %w", err)
		}

		trustedRoot, err := root.GetTrustedRoot(tufClient)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch trusted root: %w", err)
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}

	// Create verifier options for signature verification
	var verifierOpts []verify.VerifierOption

	// Configure transparency log verification
	if !opts.IgnoreTlog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	// Configure timestamp verification
	verifierOpts = append(verifierOpts, verify.WithObserverTimestamps(1))

	// Configure certificate transparency log verification
	if !opts.IgnoreCTLog {
		verifierOpts = append(verifierOpts, verify.WithSignedCertificateTimestamps(1))
	}

	// Create the underlying cosign verifier
	v, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return &Verifier{
		name:             opts.Name,
		identityPolicies: opts.IdentityPolicies,
		ignoreTlog:       opts.IgnoreTlog,
		verifier:         v,
	}, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `cosign`.
func (v *Verifier) Type() string {
	return verifierTypeCosign
}

// Verifiable returns true if the artifact is a Cosign signature.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == signatureArtifactCosign &&
		artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify verifies the artifact containing Cosign signatures.
// The verification passes if at least one valid signature is found.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	sigManifestBytes, err := opts.Store.FetchManifest(ctx, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature manifest: %w", err)
	}

	var sigManifest ocispec.Manifest
	if err := json.Unmarshal(sigManifestBytes, &sigManifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature manifest: %w", err)
	}

	// Get signature descriptors of simple signing layers
	layers, err := getSignatureDescriptors(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature descriptors: %w", err)
	}

	validSigFound := false
	var reports []*layerReport

	for _, layer := range layers {
		report := &layerReport{
			Digest: layer.Digest.String(),
		}
		if res, err := v.verifySignatureLayer(layer); err != nil {
			report.Error = err
			report.Succeeded = false
		} else {
			validSigFound = true
			report.Succeeded = true
			report.VerificationResult = res
		}
		reports = append(reports, report)
	}

	result := &ratify.VerificationResult{
		Verifier: v,
		Detail: map[string][]*layerReport{
			"verifiedSignatures": reports,
		},
	}
	if validSigFound {
		result.Description = "Cosign signature verification succeeded"
	} else {
		result.Description = "Cosign signature verification failed: no valid signatures found"
	}
	return result, nil
}

// verifySignatureLayer verifies a single simple signing layer.
func (v *Verifier) verifySignatureLayer(manifestLayer ocispec.Descriptor) (*verify.VerificationResult, error) {
	// Build the verification material for the bundle
	verificationMaterial, err := getBundleVerificationMaterial(manifestLayer, v.ignoreTlog)
	if err != nil {
		return nil, fmt.Errorf("error getting verification material: %v", err)
	}

	// Build the message signature for the bundle
	msgSignature, err := getBundleMsgSignature(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting message signature: %v", err)
	}

	// Construct and verify the bundle
	pb := protobundle.Bundle{
		MediaType:            sigstoreBundleMediaType01,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}
	bun, err := bundle.NewBundle(&pb)
	if err != nil {
		return nil, fmt.Errorf("error creating bundle: %v", err)
	}

	return v.verifyBundle(bun, manifestLayer.Digest)
}

// verifyBundle verifies the bundle using the configured verifier.
func (v *Verifier) verifyBundle(bundleObj *bundle.Bundle, layer digest.Digest) (*verify.VerificationResult, error) {
	digestBytes, err := hex.DecodeString(layer.Encoded())
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest hex: %w", err)
	}

	// Create artifact policy
	artifactPolicy := verify.WithArtifactDigest(string(layer.Algorithm()), digestBytes)
	return v.verifier.Verify(bundleObj, verify.NewPolicy(artifactPolicy, v.identityPolicies...))
}

// getBundleVerificationMaterial returns the bundle verification material from
// the simple signing layer
func getBundleVerificationMaterial(manifestLayer ocispec.Descriptor, ignoreTlog bool) (*protobundle.VerificationMaterial, error) {
	// 1. Get the signing certificate chain
	signingCert, err := getVerificationMaterialX509CertificateChain(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting signing certificate: %w", err)
	}

	// 2. Get the transparency log entries
	var tlogEntries []*protorekor.TransparencyLogEntry
	if !ignoreTlog {
		tlogEntries, err = getVerificationMaterialTlogEntries(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting tlog entries: %w", err)
		}
	}

	// 3. Construct the verification material
	return &protobundle.VerificationMaterial{
		Content:                   signingCert,
		TlogEntries:               tlogEntries,
		TimestampVerificationData: nil, // TODO: support RFC3161Timestamp.
	}, nil
}

// getVerificationMaterialX509CertificateChain returns the verification material
// X509 certificate chain from the simple signing layer
func getVerificationMaterialX509CertificateChain(manifestLayer ocispec.Descriptor) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	// 1. Get the PEM certificate from the simple signing layer
	pemCert := manifestLayer.Annotations[AnnotationKeyCert]
	// 2. Construct the DER encoded version of the PEM certificate
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}, nil
}

// getVerificationMaterialTlogEntries returns the verification material transparency log entries from the simple signing layer
func getVerificationMaterialTlogEntries(manifestLayer ocispec.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	// 1. Get the bundle annotation
	if manifestLayer.Annotations == nil {
		return nil, fmt.Errorf("manifest layer annotations are nil")
	}
	bun, exists := manifestLayer.Annotations[annotationKeyBundle]
	if !exists {
		return nil, fmt.Errorf("bundle annotation not found")
	}
	if bun == "" {
		return nil, fmt.Errorf("bundle annotation is empty")
	}

	var jsonData map[string]any
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	if jsonData == nil {
		return nil, fmt.Errorf("unmarshaled json data is nil")
	}

	// 2. Get the log index, log ID, integrated time, signed entry timestamp and body
	payload, ok := jsonData["Payload"].(map[string]any)
	if !ok || payload == nil {
		return nil, fmt.Errorf("error getting Payload")
	}

	logIndex, ok := payload["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	li, ok := payload["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := payload["integratedTime"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting integratedTime")
	}
	set, ok := jsonData["SignedEntryTimestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting SignedEntryTimestamp")
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(set)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}
	// 3. Unmarshal the body and extract the rekor KindVersion details
	body, ok := payload["body"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	if jsonData == nil {
		return nil, fmt.Errorf("unmarshaled body json data is nil")
	}
	apiVersionRaw, ok := jsonData["apiVersion"]
	if !ok || apiVersionRaw == nil {
		return nil, fmt.Errorf("error getting apiVersion")
	}
	apiVersion, ok := apiVersionRaw.(string)
	if !ok {
		return nil, fmt.Errorf("apiVersion is not a string")
	}
	kindRaw, ok := jsonData["kind"]
	if !ok || kindRaw == nil {
		return nil, fmt.Errorf("error getting kind")
	}
	kind, ok := kindRaw.(string)
	if !ok {
		return nil, fmt.Errorf("kind is not a string")
	}
	// 4. Construct the transparency log entry list
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(logIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}

// getBundleMsgSignature returns the bundle message signature from the simple signing layer
func getBundleMsgSignature(simpleSigningLayer ocispec.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// 1. Get the message digest algorithm
	var msgHashAlg protocommon.HashAlgorithm
	switch alg := simpleSigningLayer.Digest.Algorithm(); alg {
	case "sha256":
		msgHashAlg = protocommon.HashAlgorithm_SHA2_256
	default:
		return nil, fmt.Errorf("unknown digest algorithm: %s", alg)
	}
	// 2. Get the message digest
	digest, err := hex.DecodeString(simpleSigningLayer.Digest.Encoded())
	if err != nil {
		return nil, fmt.Errorf("error decoding digest: %w", err)
	}
	// 3. Get the signature
	s := simpleSigningLayer.Annotations[annotationKeySignature]
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("error decoding manSig: %w", err)
	}
	// Construct the bundle message signature
	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: msgHashAlg,
				Digest:    digest,
			},
			Signature: sig,
		},
	}, nil
}

// getSignatureDescriptors extracts the signature descriptors from the signature
// manifest.
func getSignatureDescriptors(ctx context.Context, store ratify.Store, repo string, artifactDesc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	manifestBytes, err := store.FetchManifest(ctx, repo, artifactDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}
	if manifest.MediaType != ocispec.MediaTypeImageManifest {
		return nil, fmt.Errorf("expected media type %s, got %s", ocispec.MediaTypeImageManifest, manifest.MediaType)
	}

	var descriptors []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		if layer.MediaType == mediaTypeSimpleSigning {
			descriptors = append(descriptors, layer)
		}
	}

	return descriptors, nil
}

// createTrustedPublicKeyMaterial creates a trusted material from a public key
// with validity period.
func createTrustedPublicKeyMaterial(config *PublicKeyConfig) root.TrustedMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadVerifier(config.PublicKey, config.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}
		return root.NewExpiringKey(verifier, config.ValidityPeriodStart, config.ValidityPeriodEnd), nil
	})
}

// layerReport is a report generated for a single simple signing
// layer.
type layerReport struct {
	// Digest is the digest of the simple signing layer.
	Digest string `json:"digest"`

	// Succeeded indicates whether the signature verification succeeded.
	Succeeded bool `json:"succeeded"`

	// Error contains the error if the verification failed.
	Error error

	// VerificationResult contains the verification result if the verification
	// succeeded.
	VerificationResult *verify.VerificationResult `json:"verificationResult,omitempty"`
}

// MarshalJSON deals with the Error field to ensure it is serialized correctly.
func (b *layerReport) MarshalJSON() ([]byte, error) {
	type Alias layerReport
	var errorStr string
	if b.Error != nil {
		errorStr = b.Error.Error()
	}
	return json.Marshal(struct {
		Alias
		Error string `json:"error,omitempty"`
	}{
		Alias: Alias(*b),
		Error: errorStr,
	})
}
