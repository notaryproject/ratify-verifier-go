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
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
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
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// ArtifactTypeCosignSignature is the artifact type of legacy cosign
	// signatures, which carry a simple signing layer plus signature
	// annotations.
	ArtifactTypeCosignSignature = "application/vnd.dev.cosign.artifact.sig.v1+json"

	// ArtifactTypeSigstoreBundle is the artifact type of the OCI referrers
	// produced by cosign v3 (new bundle format). The single layer of such a
	// referrer is a protobuf-JSON encoded Sigstore bundle. Both cosign
	// signatures and attestations use this artifact type; they are told apart
	// by the in-toto predicate type.
	ArtifactTypeSigstoreBundle = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// AnnotationKeyBundlePredicateType is the manifest annotation set by cosign
	// v3 on Sigstore bundle referrers to advertise the in-toto predicate type
	// of the bundled statement. The annotation is not signed and is only used
	// as a pre-filter.
	AnnotationKeyBundlePredicateType = "dev.sigstore.bundle.predicateType"

	// PredicateTypeCosignSign is the in-toto predicate type used by
	// `cosign sign` when producing Sigstore bundle signatures.
	PredicateTypeCosignSign = "https://sigstore.dev/cosign/sign/v1"
)

const (
	verifierTypeCosign = "cosign"

	mediaTypeCosignArtifactSignature = ArtifactTypeCosignSignature
	mediaTypeSigstoreBundle01        = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	mediaTypeSimpleSigning           = "application/vnd.dev.cosign.simplesigning.v1+json"

	// mediaTypeSigstoreBundlePrefix is the media type prefix of Sigstore bundle
	// layers, e.g. application/vnd.dev.sigstore.bundle.v0.3+json.
	mediaTypeSigstoreBundlePrefix = "application/vnd.dev.sigstore.bundle"
	payloadTypeInToto             = "application/vnd.in-toto+json"

	// minBundleVersion is the minimum Sigstore bundle version accepted for
	// cosign v3 bundle signatures.
	minBundleVersion = "v0.3"

	// maxBundleSize is the maximum size of a Sigstore bundle layer. Cosign
	// bundles are typically a few kilobytes.
	maxBundleSize = 4 * 1024 * 1024

	annotationKeyBundle    = "dev.sigstore.cosign/bundle"
	annotationKeyCert      = "dev.sigstore.cosign/certificate"
	annotationKeySignature = "dev.cosignproject.cosign/signature"
)

// PublicKeyConfig contains the configuration for key-based verification.
type PublicKeyConfig struct {
	// PublicKey for key-based verification.
	PublicKey crypto.PublicKey

	// SignatureAlgorithm defines the algorithm used for signature verification.
	// Optional. If not provided, defaults to SHA256 for legacy cosign
	// signatures.
	//
	// For Sigstore bundle signatures (cosign v3), the default hash for the key
	// type is always accepted (ECDSA P-256: SHA256, P-384: SHA384, P-521:
	// SHA512, RSA: SHA256, Ed25519), matching how cosign signs with a key. If
	// SignatureAlgorithm is set to a different hash, it is accepted as well.
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

	// GetPublicKeys retrieves the public keys for key-based verification.
	GetPublicKeys func(ctx context.Context) ([]*PublicKeyConfig, error)

	// IdentityPolicies contains policies for keyless verification.
	// These policies specify which OIDC identities are trusted. Optional.
	IdentityPolicies []verify.PolicyOption

	// IgnoreTLog when set to true, skips Artifact transparency log verification.
	// Only applies to keyless verification. Optional, defaults to false.
	IgnoreTLog bool

	// IgnoreCTLog when set to true, skips certificate transparency log verification.
	// Only applies to keyless verification. Optional, defaults to false.
	IgnoreCTLog bool

	// IgnoreObserverTimestamps when set to true, skips observer timestamp
	// verification (RFC3161 or log SignedEntryTimestamp), allowing key-based
	// verification without a timestamp. Only applies to key-based verification.
	// Optional, defaults to false.
	IgnoreObserverTimestamps bool

	// TUFOptions provides custom TUF client options for fetching trusted root.
	// Optional.
	TUFOptions *tuf.Options
}

// Verifier is a ratify.Verifier implementation that verifies Cosign signatures.
type Verifier struct {
	name             string
	identityPolicies []verify.PolicyOption
	ignoreTLog       bool
	getPublicKeys    func(context.Context) ([]*PublicKeyConfig, error)
	getVerifier      func() (*verify.Verifier, error)

	// getBundleVerifiers returns the verifiers used for Sigstore bundle
	// signatures. For key-based verification there is one verifier per
	// configured public key. If nil, getVerifier is used.
	getBundleVerifiers func() ([]*verify.Verifier, error)
}

// NewVerifier creates a new Cosign verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts == nil {
		return nil, fmt.Errorf("verifier options are required")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name is required")
	}

	var getVerifier func() (*verify.Verifier, error)
	var getBundleVerifiers func() ([]*verify.Verifier, error)
	if opts.GetPublicKeys != nil {
		getVerifier = func() (*verify.Verifier, error) {
			return createVerifier(opts)
		}
		getBundleVerifiers = func() ([]*verify.Verifier, error) {
			return createBundleKeyVerifiers(opts)
		}
	} else {
		v, err := createVerifier(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
		}
		getVerifier = func() (*verify.Verifier, error) {
			return v, nil
		}
		getBundleVerifiers = func() ([]*verify.Verifier, error) {
			return []*verify.Verifier{v}, nil
		}
	}

	return &Verifier{
		getVerifier:        getVerifier,
		getBundleVerifiers: getBundleVerifiers,
		name:               opts.Name,
		identityPolicies:   opts.IdentityPolicies,
		ignoreTLog:         opts.IgnoreTLog,
		getPublicKeys:      opts.GetPublicKeys,
	}, nil
}

func createVerifier(opts *VerifierOptions) (*verify.Verifier, error) {
	var trustedMaterial root.TrustedMaterialCollection

	// Create trusted material from public keys if provided.
	trustedPublicKeyMaterial, err := createTrustedMaterialFromPublicKeys(context.Background(), opts.GetPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to create trusted material from public keys: %w", err)
	}
	trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial...)

	// Keyless verification: use provided trusted root or fetch from TUF
	trustedRoot, err := getTrustedRoot(opts)
	if err != nil {
		return nil, err
	}
	trustedMaterial = append(trustedMaterial, trustedRoot)

	// Create the underlying cosign verifier
	return verify.NewVerifier(trustedMaterial, getVerifierOptions(opts)...)
}

// createBundleKeyVerifiers creates one verifier per configured public key for
// key-based verification of Sigstore bundle signatures. A dedicated verifier
// per key is required because the public key material does not use key hints,
// so a single collection would only ever try the first key.
func createBundleKeyVerifiers(opts *VerifierOptions) ([]*verify.Verifier, error) {
	publicKeys, err := opts.GetPublicKeys(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}
	if len(publicKeys) == 0 {
		return nil, errors.New("no public keys configured")
	}
	for _, config := range publicKeys {
		if config == nil {
			return nil, fmt.Errorf("public key config cannot be nil")
		}
	}

	trustedRoot, err := getTrustedRoot(opts)
	if err != nil {
		return nil, err
	}
	verifierOpts := getVerifierOptions(opts)

	verifiers := make([]*verify.Verifier, 0, len(publicKeys))
	for _, config := range publicKeys {
		trustedMaterial := root.TrustedMaterialCollection{
			createBundlePublicKeyMaterial(config),
			trustedRoot,
		}
		v, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
		}
		verifiers = append(verifiers, v)
	}
	return verifiers, nil
}

// getTrustedRoot returns the configured trusted root, or fetches the default
// Sigstore trusted root via TUF if none is configured.
func getTrustedRoot(opts *VerifierOptions) (root.TrustedMaterial, error) {
	if opts.TrustedRoot != nil {
		return opts.TrustedRoot, nil
	}

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
	return trustedRoot, nil
}

// getVerifierOptions returns the sigstore-go verifier options derived from the
// verifier options.
func getVerifierOptions(opts *VerifierOptions) []verify.VerifierOption {
	// Create verifier options for signature verification
	var verifierOpts []verify.VerifierOption

	// Configure transparency log verification
	if !opts.IgnoreTLog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	// Configure timestamp verification
	if opts.IgnoreObserverTimestamps && opts.GetPublicKeys != nil {
		verifierOpts = append(verifierOpts, verify.WithNoObserverTimestamps())
	} else {
		verifierOpts = append(verifierOpts, verify.WithObserverTimestamps(1))
	}

	// Configure certificate transparency log verification. Key-based
	// verification carries no Fulcio certificate and therefore no signed
	// certificate timestamps, so the certificate transparency log never applies
	// there and IgnoreCTLog is a no-op for it.
	if !opts.IgnoreCTLog && opts.GetPublicKeys == nil {
		verifierOpts = append(verifierOpts, verify.WithSignedCertificateTimestamps(1))
	}

	return verifierOpts
}

func createTrustedMaterialFromPublicKeys(ctx context.Context, getPublicKeys func(context.Context) ([]*PublicKeyConfig, error)) ([]root.TrustedMaterial, error) {
	var trustedMaterial []root.TrustedMaterial
	if getPublicKeys == nil {
		return trustedMaterial, nil
	}

	publicKeys, err := getPublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}

	for _, config := range publicKeys {
		if config == nil {
			return nil, fmt.Errorf("public key config cannot be nil")
		}
		// Copy the config so that the caller-owned config is not mutated.
		legacyConfig := *config
		if legacyConfig.SignatureAlgorithm == 0 {
			// Default to SHA256 if no algorithm is specified
			legacyConfig.SignatureAlgorithm = crypto.SHA256
		}
		trustedMaterial = append(trustedMaterial, createTrustedPublicKeyMaterial(&legacyConfig))
	}
	return trustedMaterial, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `cosign`.
func (v *Verifier) Type() string {
	return verifierTypeCosign
}

// Verifiable returns true if the artifact is a Cosign signature, either a
// legacy cosign signature or a cosign v3 Sigstore bundle signature.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return IsVerifiable(artifact)
}

// IsVerifiable returns true if the artifact is a Cosign signature that can be
// verified by a Cosign [Verifier]:
//   - a legacy cosign signature with artifact type
//     [ArtifactTypeCosignSignature], or
//   - a cosign v3 Sigstore bundle with artifact type
//     [ArtifactTypeSigstoreBundle], unless its
//     [AnnotationKeyBundlePredicateType] annotation advertises a predicate type
//     other than [PredicateTypeCosignSign]. Such bundles are attestations (e.g.
//     SLSA provenance or SBOMs) rather than signatures and are skipped so that
//     no verification report is produced for them. Bundles without the
//     annotation are treated as verifiable; the signed predicate type is always
//     checked during verification.
//
// In both cases, the artifact must be an OCI image manifest.
func IsVerifiable(artifact ocispec.Descriptor) bool {
	if artifact.MediaType != ocispec.MediaTypeImageManifest {
		return false
	}
	switch artifact.ArtifactType {
	case ArtifactTypeCosignSignature:
		return true
	case ArtifactTypeSigstoreBundle:
		if predicateType, ok := artifact.Annotations[AnnotationKeyBundlePredicateType]; ok {
			return predicateType == PredicateTypeCosignSign
		}
		return true
	default:
		return false
	}
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

	if opts.ArtifactDescriptor.ArtifactType == ArtifactTypeSigstoreBundle || sigManifest.ArtifactType == ArtifactTypeSigstoreBundle {
		return v.verifyBundleSignatures(ctx, opts, &sigManifest)
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

	return newVerificationResult(v, reports, validSigFound), nil
}

// newVerificationResult builds the verification result from the per-layer
// reports.
func newVerificationResult(v *Verifier, reports []*layerReport, validSigFound bool) *ratify.VerificationResult {
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
		result.Err = errors.New("no valid signatures found, see result for details")
	}
	return result
}

// verifyBundleSignatures verifies a cosign v3 signature stored as a Sigstore
// bundle in the layer of an OCI referrer manifest.
func (v *Verifier) verifyBundleSignatures(ctx context.Context, opts *ratify.VerifyOptions, sigManifest *ocispec.Manifest) (*ratify.VerificationResult, error) {
	if sigManifest.MediaType != ocispec.MediaTypeImageManifest {
		return nil, fmt.Errorf("expected media type %s, got %s", ocispec.MediaTypeImageManifest, sigManifest.MediaType)
	}

	var layers []ocispec.Descriptor
	for _, layer := range sigManifest.Layers {
		if strings.HasPrefix(layer.MediaType, mediaTypeSigstoreBundlePrefix) {
			layers = append(layers, layer)
		}
	}
	if len(layers) == 0 {
		return nil, errors.New("no Sigstore bundle layer found in signature manifest")
	}

	validSigFound := false
	var reports []*layerReport
	for _, layer := range layers {
		report := &layerReport{
			Digest: layer.Digest.String(),
		}
		if res, err := v.verifyBundleLayer(ctx, opts, layer); err != nil {
			report.Error = err
			report.Succeeded = false
		} else {
			validSigFound = true
			report.Succeeded = true
			report.VerificationResult = res
		}
		reports = append(reports, report)
	}

	return newVerificationResult(v, reports, validSigFound), nil
}

// verifyBundleLayer fetches, parses and verifies a single Sigstore bundle
// layer against the subject.
func (v *Verifier) verifyBundleLayer(ctx context.Context, opts *ratify.VerifyOptions, layer ocispec.Descriptor) (*verify.VerificationResult, error) {
	if layer.Size > maxBundleSize {
		return nil, fmt.Errorf("bundle size %d exceeds the limit of %d bytes", layer.Size, maxBundleSize)
	}
	bundleBytes, err := opts.Store.FetchBlob(ctx, opts.Repository, layer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle: %w", err)
	}
	if len(bundleBytes) > maxBundleSize {
		return nil, fmt.Errorf("bundle size %d exceeds the limit of %d bytes", len(bundleBytes), maxBundleSize)
	}

	bun, err := parseBundle(bundleBytes)
	if err != nil {
		return nil, err
	}
	return v.verifySigstoreBundle(bun, opts.SubjectDescriptor.Digest)
}

// parseBundle parses a protobuf-JSON encoded Sigstore bundle and checks that it
// is a cosign v3 style bundle, i.e. a bundle of version v0.3 or later carrying
// a DSSE envelope with an in-toto statement.
func parseBundle(bundleBytes []byte) (*bundle.Bundle, error) {
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &pb); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}
	bun, err := bundle.NewBundle(&pb)
	if err != nil {
		return nil, fmt.Errorf("invalid bundle: %w", err)
	}
	if !bun.MinVersion(minBundleVersion) {
		return nil, fmt.Errorf("unsupported bundle media type %q: bundle version must be %s or later", pb.GetMediaType(), minBundleVersion)
	}
	envelope := pb.GetDsseEnvelope()
	if envelope == nil {
		return nil, errors.New("bundle content is not a DSSE envelope")
	}
	if envelope.GetPayloadType() != payloadTypeInToto {
		return nil, fmt.Errorf("unsupported DSSE payload type %q: expected %q", envelope.GetPayloadType(), payloadTypeInToto)
	}
	return bun, nil
}

// verifySigstoreBundle verifies a cosign v3 Sigstore bundle against the subject
// digest and ensures that the signed statement is a cosign signature.
func (v *Verifier) verifySigstoreBundle(bun *bundle.Bundle, subject digest.Digest) (*verify.VerificationResult, error) {
	artifactPolicy, err := getArtifactDigestPolicy(subject)
	if err != nil {
		return nil, err
	}

	if v.getPublicKeys != nil && bun.GetVerificationMaterial().GetPublicKey() == nil {
		return nil, errors.New("key-based verification requires a bundle signed with a public key")
	}

	verifiers, err := v.bundleVerifiers()
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier: %w", err)
	}

	policy := verify.NewPolicy(artifactPolicy, v.identityPolicies...)
	var errs []error
	for _, verifier := range verifiers {
		res, err := verifier.Verify(bun, policy)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := checkCosignSignStatement(res); err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, errors.Join(errs...)
}

// bundleVerifiers returns the verifiers used for Sigstore bundles.
func (v *Verifier) bundleVerifiers() ([]*verify.Verifier, error) {
	if v.getBundleVerifiers != nil {
		return v.getBundleVerifiers()
	}
	verifier, err := v.getVerifier()
	if err != nil {
		return nil, err
	}
	return []*verify.Verifier{verifier}, nil
}

// getArtifactDigestPolicy returns the artifact policy binding the in-toto
// statement subject to the subject digest.
func getArtifactDigestPolicy(subject digest.Digest) (verify.ArtifactPolicyOption, error) {
	if err := subject.Validate(); err != nil {
		return nil, fmt.Errorf("invalid subject digest %q: %w", subject, err)
	}
	alg := subject.Algorithm()
	switch alg {
	case digest.SHA256, digest.SHA512:
	default:
		return nil, fmt.Errorf("unsupported subject digest algorithm: %s", alg)
	}
	digestBytes, err := hex.DecodeString(subject.Encoded())
	if err != nil {
		return nil, fmt.Errorf("failed to decode subject digest: %w", err)
	}
	return verify.WithArtifactDigest(string(alg), digestBytes), nil
}

// checkCosignSignStatement ensures that the verified in-toto statement is a
// cosign signature. The predicate type annotation on the referrer manifest is
// not signed, so an attestation could otherwise be presented as a signature.
func checkCosignSignStatement(res *verify.VerificationResult) error {
	if res == nil || res.Statement == nil {
		return errors.New("bundle does not contain an in-toto statement")
	}
	if predicateType := res.Statement.GetPredicateType(); predicateType != PredicateTypeCosignSign {
		return fmt.Errorf("bundle is not a cosign signature: predicateType %q", predicateType)
	}
	return nil
}

// verifySignatureLayer verifies a single simple signing layer.
func (v *Verifier) verifySignatureLayer(manifestLayer ocispec.Descriptor) (*verify.VerificationResult, error) {
	// Build the verification material for the bundle
	verificationMaterial, err := getBundleVerificationMaterial(manifestLayer, v.ignoreTLog, v.getPublicKeys)
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
		MediaType:            mediaTypeSigstoreBundle01,
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
	verifier, err := v.getVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier: %w", err)
	}
	return verifier.Verify(bundleObj, verify.NewPolicy(artifactPolicy, v.identityPolicies...))
}

// getBundleVerificationMaterial returns the bundle verification material from
// the simple signing layer
func getBundleVerificationMaterial(manifestLayer ocispec.Descriptor, ignoreTlog bool, getPublicKeys func(ctx context.Context) ([]*PublicKeyConfig, error)) (*protobundle.VerificationMaterial, error) {
	// 1. Get the transparency log entries
	var tlogEntries []*protorekor.TransparencyLogEntry
	var err error
	if !ignoreTlog {
		tlogEntries, err = getVerificationMaterialTlogEntries(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting tlog entries: %w", err)
		}
	}

	// 2. Construct the verification material based on the type of verification
	verificationMaterial := &protobundle.VerificationMaterial{
		TlogEntries:               tlogEntries,
		TimestampVerificationData: nil, // TODO: support RFC3161Timestamp.
	}
	// If getPublicKeys is nil, this indicates keyless verification.
	// If getPublicKeys is non-nil, this indicates key-based verification.
	if getPublicKeys != nil {
		// If we have public keys, construct an empty public key material
		verificationMaterial.Content = &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{
				Hint: "",
			},
		}
	} else {
		// Otherwise, get the signing certificate chain from the manifest
		signingCert, err := getVerificationMaterialX509CertificateChain(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting signing certificate: %w", err)
		}
		verificationMaterial.Content = signingCert
	}

	return verificationMaterial, nil
}

// getVerificationMaterialX509CertificateChain returns the verification material
// X509 certificate chain from the simple signing layer
func getVerificationMaterialX509CertificateChain(manifestLayer ocispec.Descriptor) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	// 1. Get the PEM certificate from the simple signing layer
	pemCert := manifestLayer.Annotations[annotationKeyCert]
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

// bundleAnnotation represents the structure of the bundle annotation
type bundleAnnotation struct {
	Payload              *bundlePayload `json:"Payload"`
	SignedEntryTimestamp *string        `json:"SignedEntryTimestamp"`
}

// bundlePayload represents the payload structure within the bundle
type bundlePayload struct {
	LogIndex       *float64 `json:"logIndex"`
	LogID          *string  `json:"logID"`
	IntegratedTime *float64 `json:"integratedTime"`
	Body           *string  `json:"body"`
}

// payloadBody represents the structure of the decoded body
type payloadBody struct {
	APIVersion *string `json:"apiVersion"`
	Kind       *string `json:"kind"`
}

func (b *bundleAnnotation) validate() error {
	if b.Payload == nil {
		return fmt.Errorf("bundle payload is missing")
	}
	if b.Payload.LogIndex == nil {
		return fmt.Errorf("bundle payload logIndex is missing")
	}
	if b.Payload.LogID == nil {
		return fmt.Errorf("bundle payload logID is missing")
	}
	if b.Payload.IntegratedTime == nil {
		return fmt.Errorf("bundle payload integratedTime is missing")
	}
	if b.Payload.Body == nil {
		return fmt.Errorf("bundle payload body is missing")
	}
	if b.SignedEntryTimestamp == nil {
		return fmt.Errorf("signed entry timestamp is missing")
	}
	return nil
}

func (b *payloadBody) validate() error {
	if b.APIVersion == nil {
		return fmt.Errorf("body apiVersion is missing")
	}
	if b.Kind == nil {
		return fmt.Errorf("body kind is missing")
	}
	return nil
}

// getVerificationMaterialTlogEntries returns the verification material
// transparency log entries from the simple signing layer
func getVerificationMaterialTlogEntries(manifestLayer ocispec.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	// 1. Get the bundle annotation from the manifest layer.
	annotation, exists := manifestLayer.Annotations[annotationKeyBundle]
	if !exists {
		return nil, fmt.Errorf("bundle annotation not found")
	}

	// 2. Unmarshal the bundle annotation into a bundleAnnotation.
	var bundle bundleAnnotation
	if err := json.Unmarshal([]byte(annotation), &bundle); err != nil {
		return nil, fmt.Errorf("error unmarshaling bundle annotation: %w", err)
	}
	if err := bundle.validate(); err != nil {
		return nil, fmt.Errorf("bundle validation failed: %w", err)
	}
	logID, err := hex.DecodeString(*bundle.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(*bundle.SignedEntryTimestamp)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}

	// 3. Decode the body from the bundle payload.
	bodyDecoded, err := base64.StdEncoding.DecodeString(*bundle.Payload.Body)
	if err != nil {
		return nil, err
	}
	var body payloadBody
	if err := json.Unmarshal(bodyDecoded, &body); err != nil {
		return nil, fmt.Errorf("error unmarshaling body: %w", err)
	}
	if err := body.validate(); err != nil {
		return nil, fmt.Errorf("body validation failed: %w", err)
	}

	// 4. Construct the transparency log entry.
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(*bundle.Payload.LogIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    *body.Kind,
				Version: *body.APIVersion,
			},
			IntegratedTime: int64(*bundle.Payload.IntegratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			CanonicalizedBody: bodyDecoded,
		},
	}, nil
}

// getBundleMsgSignature returns the bundle message signature from the simple
// signing layer
func getBundleMsgSignature(simpleSigningLayer ocispec.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// 1. Get the message digest algorithm
	var msgHashAlg protocommon.HashAlgorithm
	switch alg := simpleSigningLayer.Digest.Algorithm(); alg {
	case digest.SHA256:
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

// createBundlePublicKeyMaterial creates a trusted material from a public key
// for verifying Sigstore bundle signatures. Unlike legacy cosign signatures,
// which always sign a SHA256 digest, DSSE signatures are computed with the
// default hash of the signing key, so the key-specific default hash is used.
func createBundlePublicKeyMaterial(config *PublicKeyConfig) root.TrustedMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := loadBundleKeyVerifier(config.PublicKey, config.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}
		return root.NewExpiringKey(verifier, config.ValidityPeriodStart, config.ValidityPeriodEnd), nil
	})
}

// loadBundleKeyVerifier loads a signature verifier for the public key using
// the default hash for the key type (ECDSA P-256: SHA256, P-384: SHA384,
// P-521: SHA512, RSA: SHA256). If hashFunc is set and differs from the
// default, signatures using hashFunc are accepted as well.
func loadBundleKeyVerifier(publicKey crypto.PublicKey, hashFunc crypto.Hash) (signature.Verifier, error) {
	var verifiers []signature.Verifier
	var errs []error

	defaultVerifier, err := signature.LoadDefaultVerifier(publicKey)
	if err != nil {
		errs = append(errs, err)
	} else {
		verifiers = append(verifiers, defaultVerifier)
	}

	if hashFunc != 0 {
		useConfigured := defaultVerifier == nil
		if !useConfigured {
			details, err := signature.GetDefaultAlgorithmDetails(publicKey)
			useConfigured = err != nil || details.GetHashType() != hashFunc
		}
		if useConfigured {
			configuredVerifier, err := signature.LoadVerifier(publicKey, hashFunc)
			if err != nil {
				errs = append(errs, err)
			} else {
				verifiers = append(verifiers, configuredVerifier)
			}
		}
	}

	switch len(verifiers) {
	case 0:
		return nil, fmt.Errorf("failed to load verifier for public key: %w", errors.Join(errs...))
	case 1:
		return verifiers[0], nil
	default:
		return &multiHashVerifier{verifiers: verifiers}, nil
	}
}

// multiHashVerifier verifies signatures created by the same public key with
// one of several hash functions.
type multiHashVerifier struct {
	verifiers []signature.Verifier
}

// PublicKey returns the public key of the verifier.
func (m *multiHashVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return m.verifiers[0].PublicKey(opts...)
}

// VerifySignature succeeds if any of the underlying verifiers verifies the
// signature.
func (m *multiHashVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}
	var messageBytes []byte
	if message != nil {
		messageBytes, err = io.ReadAll(message)
		if err != nil {
			return fmt.Errorf("failed to read message: %w", err)
		}
	}

	var errs []error
	for _, verifier := range m.verifiers {
		var messageReader io.Reader
		if message != nil {
			messageReader = bytes.NewReader(messageBytes)
		}
		err := verifier.VerifySignature(bytes.NewReader(sigBytes), messageReader, opts...)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
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
