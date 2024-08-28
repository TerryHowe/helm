/*
Copyright The Helm Authors.

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

package registry // import "helm.sh/helm/v3/pkg/registry"

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	v2 "oras.land/oras-go/v2"
	v2content "oras.land/oras-go/v2/content"
	v2memory "oras.land/oras-go/v2/content/memory"
	v2registry "oras.land/oras-go/v2/registry"
	v2remote "oras.land/oras-go/v2/registry/remote"
	v2auth "oras.land/oras-go/v2/registry/remote/auth"
	v2credentials "oras.land/oras-go/v2/registry/remote/credentials"

	"helm.sh/helm/v3/internal/version"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/helmpath"
)

// See https://github.com/helm/helm/issues/10166
const (
	registryUnderscoreMessage = `
OCI artifact references (e.g. tags) do not support the plus sign (+). To support
storing semantic versions, Helm adopts the convention of changing plus (+) to
an underscore (_) in chart version tags when pushing to a registry and back to
a plus (+) when pulling from a registry.`
	dockerConfigDirEnv = "DOCKER_CONFIG"
)

type (
	// Client works with OCI-compliant registries
	Client struct {
		debug            bool
		out              io.Writer
		credentialsFile  string
		Insecure         bool
		plainHTTP        bool
		enableCache      bool
		httpClient       *http.Client
		credentialsStore v2credentials.Store
		credentialFunc   v2auth.CredentialFunc
	}
	// ClientOption allows specifying various settings configurable by the user for overriding the defaults
	// used when creating a new default client
	ClientOption func(*Client)
)

// NewClient returns a new registry client with config
func NewClient(options ...ClientOption) (*Client, error) {
	client := &Client{
		out:             io.Discard,
		credentialsFile: helmpath.ConfigPath(CredentialsFileBasename),
	}

	// Override default settings with options
	for _, option := range options {
		option(client)
	}
	// TODO this doesn't need to return error ATM
	return client, nil
}

// ClientOptDebug returns a function that sets the debug setting on client options set
func ClientOptDebug(debug bool) ClientOption {
	return func(client *Client) {
		client.debug = debug
	}
}

// ClientOptEnableCache returns a function that sets the enableCache setting on a client options set
func ClientOptEnableCache(enableCache bool) ClientOption {
	return func(client *Client) {
		client.enableCache = enableCache
	}
}

// ClientOptWriter returns a function that sets the writer setting on client options set
func ClientOptWriter(out io.Writer) ClientOption {
	return func(client *Client) {
		client.out = out
	}
}

// ClientOptCredentialsFile returns a function that sets the credentialsFile setting on a client options set
func ClientOptCredentialsFile(credentialsFile string) ClientOption {
	return func(client *Client) {
		client.credentialsFile = credentialsFile
	}
}

// ClientOptHTTPClient returns a function that sets the httpClient setting on a client options set
func ClientOptHTTPClient(httpClient *http.Client) ClientOption {
	return func(client *Client) {
		client.httpClient = httpClient
	}
}

func ClientOptPlainHTTP() ClientOption {
	return func(c *Client) {
		c.plainHTTP = true
	}
}

func LoadCertPool(path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if ok := pool.AppendCertsFromPEM(pemBytes); !ok {
		return nil, errors.New("Failed to load certificate in file: " + path)
	}
	return pool, nil
}

func (c *Client) createCredentials(host string, options *loginOperation) error {
	dir := filepath.Dir(c.credentialsFile)
	err := os.Setenv(dockerConfigDirEnv, dir)
	if err != nil {
		return err
	}

	storeOpts := v2credentials.StoreOptions{
		AllowPlaintextPut: true,
	}
	credStore, err := v2credentials.NewStoreFromDocker(storeOpts)
	if err != nil {
		return err
	}
	c.credentialsStore = credStore

	if options.username != "" || options.password != "" {
		cred := v2auth.Credential{}
		if options.username == "" {
			cred.AccessToken = options.password
			// properly support access token and refresher token
		} else {
			cred.Username = options.username
			cred.Password = options.password
		}
		c.credentialFunc = v2auth.StaticCredential(host, cred)
		return nil
	}
	c.credentialFunc = v2credentials.Credential(credStore)
	return nil
}

func (c *Client) createHTTPClient(options *loginOperation) (err error) {
	if c.httpClient != nil {
		return nil
	}
	defaultCopy := *http.DefaultClient
	c.httpClient = &defaultCopy
	if options.caFile != "" || options.certFile != "" || options.keyFile != "" || options.insecure {

		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.Insecure,
		}
		if options.caFile != "" {
			fmt.Printf("CA FILE %s", options.caFile)
			tlsConfig.RootCAs, err = LoadCertPool(options.caFile)
			if err != nil {
				return err
			}
		}
		if options.certFile != "" {
			fmt.Printf("ert FILE %s", options.certFile)
			fmt.Printf("key FILE %s", options.keyFile)
			cert, err := tls.LoadX509KeyPair(options.certFile, options.keyFile)
			if err != nil {
				return err
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		c.httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}
	return nil
}

func (c *Client) createAuthClient() *v2auth.Client {
	authClient := v2auth.Client{
		Client:     c.httpClient,
		Credential: c.credentialFunc,
	}
	if c.enableCache {
		authClient.Cache = v2auth.DefaultCache
	}
	authClient.SetUserAgent(version.GetUserAgent())
	return &authClient
}

type (
	// LoginOption allows specifying various settings on login
	LoginOption func(*loginOperation)

	loginOperation struct {
		username string
		password string
		insecure bool
		certFile string
		keyFile  string
		caFile   string
	}
)

// LoginOptBasicAuth returns a function that sets the username/password settings on login
func LoginOptBasicAuth(username string, password string) LoginOption {
	return func(operation *loginOperation) {
		operation.username = username
		operation.password = password
	}
}

// LoginOptInsecure returns a function that sets the insecure setting on login
func LoginOptInsecure(insecure bool) LoginOption {
	return func(operation *loginOperation) {
		operation.insecure = insecure
	}
}

// LoginOptTLSClientConfig returns a function that sets the TLS settings on login.
func LoginOptTLSClientConfig(certFile, keyFile, caFile string) LoginOption {
	return func(operation *loginOperation) {
		operation.certFile = certFile
		operation.keyFile = keyFile
		operation.caFile = caFile
	}
}

func warningHandler(warning v2remote.Warning) {
	fmt.Printf("WARN(%d): Agent(%s): %s", warning.Code, warning.Agent, warning.Text)
}

// Login logs into a registry
func (c *Client) Login(host string, options ...LoginOption) error {
	operation := &loginOperation{}
	for _, option := range options {
		option(operation)
	}

	err := c.createCredentials(host, operation)
	if err != nil {
		return err
	}

	err = c.createHTTPClient(operation)
	if err != nil {
		return err
	}

	remoteRegistry, err := v2remote.NewRegistry(host)
	if err != nil {
		return err
	}
	remoteRegistry.PlainHTTP = c.plainHTTP
	remoteRegistry.PlainHTTP = true // TODO remove
	remoteRegistry.HandleWarning = warningHandler
	remoteRegistry.Client = c.createAuthClient()
	cred, err := c.credentialFunc(ctx(c.out, c.debug), host)
	if err != nil {
		return err
	}

	if err := v2credentials.Login(ctx(c.out, c.debug), c.credentialsStore, remoteRegistry, cred); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(c.out, "Login Succeeded")
	return nil
}

// Logout logs out of a registry
func (c *Client) Logout(host string) error {
	operation := &loginOperation{}
	err := c.createCredentials(host, operation)
	if err != nil {
		return err
	}

	err = v2credentials.Logout(ctx(c.out, c.debug), c.credentialsStore, host)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.out, "Removing login credentialFunc for %s\n", host)
	return nil
}

type (
	// PullOption allows specifying various settings on pull
	PullOption func(*pullOperation)

	// PullResult is the result returned upon successful pull.
	PullResult struct {
		Manifest *DescriptorPullSummary         `json:"manifest"`
		Config   *DescriptorPullSummary         `json:"config"`
		Chart    *DescriptorPullSummaryWithMeta `json:"chart"`
		Prov     *DescriptorPullSummary         `json:"prov"`
		Ref      string                         `json:"ref"`
	}

	DescriptorPullSummary struct {
		Data   []byte `json:"-"`
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}

	DescriptorPullSummaryWithMeta struct {
		DescriptorPullSummary
		Meta *chart.Metadata `json:"meta"`
	}

	pullOperation struct {
		withChart         bool
		withProv          bool
		ignoreMissingProv bool
	}
)

func (c *Client) readStoreBytes(memoryStore *v2memory.Store, desc ocispec.Descriptor) ([]byte, error) {
	byteReader, err := memoryStore.Fetch(ctx(c.out, c.debug), desc)
	if err != nil {
		return nil, errors.Errorf("Unable to retrieve blob with digest %s", desc.Digest)
	}
	defer func() { _ = byteReader.Close() }()

	buf := bytes.Buffer{}
	_, err = buf.ReadFrom(byteReader)
	if err != nil {
		return nil, errors.Errorf("Unable to read blob with digest %s", desc.Digest)
	}
	return buf.Bytes(), nil
}

// Pull downloads a chart from a registry
func (c *Client) Pull(ref string, options ...PullOption) (*PullResult, error) {
	parsedRef, err := NewReference(ref)
	if err != nil {
		return nil, err
	}

	operation := &pullOperation{
		withChart: true, // By default, always download the chart layer
	}
	for _, option := range options {
		option(operation)
	}
	if !operation.withChart && !operation.withProv {
		return nil, errors.New(
			"must specify at least one layer to pull (chart/prov)")
	}
	memoryStore := v2memory.New()

	//allowedMediaTypes := []string{
	//	ConfigMediaType,
	//}
	//minNumDescriptors := 1 // 1 for the config
	//if operation.withChart {
	//	minNumDescriptors++
	//	allowedMediaTypes = append(allowedMediaTypes, ChartLayerMediaType, LegacyChartLayerMediaType)
	//}
	//if operation.withProv {
	//	if !operation.ignoreMissingProv {
	//		minNumDescriptors++
	//	}
	//	allowedMediaTypes = append(allowedMediaTypes, ProvLayerMediaType)
	//}

	var descriptors, layers []ocispec.Descriptor

	src, err := v2remote.NewRepository(parsedRef.OrasReference.String())
	if err != nil {
		return nil, err
	}
	src.Client = c.httpClient
	src.PlainHTTP = c.plainHTTP
	manifest, err := src.Resolve(ctx(c.out, c.debug), parsedRef.Tag)
	if err != nil {
		return nil, err
	}

	copyOptions := v2.DefaultExtendedCopyOptions
	copyOptions.FindPredecessors = func(ctx context.Context, src v2content.ReadOnlyGraphStorage, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return v2registry.Referrers(ctx, src, desc, "")
	}
	manifest, err = v2.ExtendedCopy(ctx(c.out, c.debug), src, parsedRef.OrasReference.String(), memoryStore, "", copyOptions)
	if err != nil {
		return nil, err
	}

	descriptors = append(descriptors, manifest)
	descriptors = append(descriptors, layers...)

	//numDescriptors := len(descriptors)
	//if numDescriptors < minNumDescriptors {
	//	return nil, fmt.Errorf("manifest does not contain minimum number of descriptors (%d), descriptors found: %d",
	//		minNumDescriptors, numDescriptors)
	//}
	var configDescriptor *ocispec.Descriptor
	var chartDescriptor *ocispec.Descriptor
	var provDescriptor *ocispec.Descriptor
	for _, descriptor := range descriptors {
		d := descriptor
		switch d.MediaType {
		case ConfigMediaType:
			configDescriptor = &d
		case ChartLayerMediaType:
			chartDescriptor = &d
		case ProvLayerMediaType:
			provDescriptor = &d
		case LegacyChartLayerMediaType:
			chartDescriptor = &d
			_, _ = fmt.Fprintf(c.out, "Warning: chart media type %s is deprecated\n", LegacyChartLayerMediaType)
		}
	}
	if configDescriptor == nil {
		return nil, fmt.Errorf("could not load config with mediatype %s", ConfigMediaType)
	}
	if operation.withChart && chartDescriptor == nil {
		return nil, fmt.Errorf("manifest does not contain a layer with mediatype %s", ChartLayerMediaType)
	}
	if operation.withProv && provDescriptor == nil && !operation.ignoreMissingProv {
		return nil, fmt.Errorf("manifest does not contain a layer with mediatype %s", ProvLayerMediaType)
	}
	result := &PullResult{
		Manifest: &DescriptorPullSummary{
			Digest: manifest.Digest.String(),
			Size:   manifest.Size,
		},
		Config: &DescriptorPullSummary{
			Digest: configDescriptor.Digest.String(),
			Size:   configDescriptor.Size,
		},
		Chart: &DescriptorPullSummaryWithMeta{},
		Prov:  &DescriptorPullSummary{},
		Ref:   parsedRef.OrasReference.String(),
	}

	if result.Manifest.Data, err = c.readStoreBytes(memoryStore, manifest); err != nil {
		return nil, err
	}
	if result.Config.Data, err = c.readStoreBytes(memoryStore, *configDescriptor); err != nil {
		return nil, err
	}
	var meta *chart.Metadata
	if err := json.Unmarshal(result.Config.Data, &meta); err != nil {
		return nil, err
	}
	result.Chart.Meta = meta

	if chartDescriptor != nil {
		if result.Chart.Data, err = c.readStoreBytes(memoryStore, *chartDescriptor); err != nil {
			return nil, err
		}
		result.Chart.Digest = chartDescriptor.Digest.String()
		result.Chart.Size = chartDescriptor.Size
	}
	if provDescriptor != nil {
		if result.Prov.Data, err = c.readStoreBytes(memoryStore, *provDescriptor); err != nil {
			return nil, err
		}
		result.Prov.Digest = provDescriptor.Digest.String()
		result.Prov.Size = provDescriptor.Size
	}

	_, _ = fmt.Fprintf(c.out, "Pulled: %s\n", result.Ref)
	_, _ = fmt.Fprintf(c.out, "Digest: %s\n", result.Manifest.Digest)

	if strings.Contains(result.Ref, "_") {
		_, _ = fmt.Fprintf(c.out, "%s contains an underscore.\n", result.Ref)
		_, _ = fmt.Fprint(c.out, registryUnderscoreMessage+"\n")
	}

	return result, nil
}

// PullOptWithChart returns a function that sets the withChart setting on pull
func PullOptWithChart(withChart bool) PullOption {
	return func(operation *pullOperation) {
		operation.withChart = withChart
	}
}

// PullOptWithProv returns a function that sets the withProv setting on pull
func PullOptWithProv(withProv bool) PullOption {
	return func(operation *pullOperation) {
		operation.withProv = withProv
	}
}

// PullOptIgnoreMissingProv returns a function that sets the ignoreMissingProv setting on pull
func PullOptIgnoreMissingProv(ignoreMissingProv bool) PullOption {
	return func(operation *pullOperation) {
		operation.ignoreMissingProv = ignoreMissingProv
	}
}

type (
	// PushOption allows specifying various settings on push
	PushOption func(*pushOperation)

	// PushResult is the result returned upon successful push.
	PushResult struct {
		Manifest *descriptorPushSummary         `json:"manifest"`
		Config   *descriptorPushSummary         `json:"config"`
		Chart    *descriptorPushSummaryWithMeta `json:"chart"`
		Prov     *descriptorPushSummary         `json:"prov"`
		Ref      string                         `json:"ref"`
	}

	descriptorPushSummary struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}

	descriptorPushSummaryWithMeta struct {
		descriptorPushSummary
		Meta *chart.Metadata `json:"meta"`
	}

	pushOperation struct {
		provData     []byte
		strictMode   bool
		creationTime string
	}
)

// Push uploads a chart to a registry.
func (c *Client) Push(data []byte, ref string, options ...PushOption) (*PushResult, error) {
	parsedRef, err := NewReference(ref)
	if err != nil {
		return nil, err
	}

	operation := &pushOperation{
		strictMode: true, // By default, enable strict mode
	}
	for _, option := range options {
		option(operation)
	}
	meta, err := extractChartMeta(data)
	if err != nil {
		return nil, err
	}
	if operation.strictMode {
		if !strings.HasSuffix(ref, fmt.Sprintf("/%s:%s", meta.Name, meta.Version)) {
			return nil, errors.New(
				"strict mode enabled, ref basename and tag must match the chart name and version")
		}
	}
	memoryStore := v2memory.New()
	chartDescriptor, err := v2.PushBytes(ctx(c.out, c.debug), memoryStore, ChartLayerMediaType, data)
	if err != nil {
		return nil, err
	}

	configData, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	configDescriptor, err := v2.PushBytes(ctx(c.out, c.debug), memoryStore, ConfigMediaType, configData)
	if err != nil {
		return nil, err
	}

	descriptors := []ocispec.Descriptor{chartDescriptor, configDescriptor}
	var provDescriptor ocispec.Descriptor
	if operation.provData != nil {
		provDescriptor, err := v2.PushBytes(ctx(c.out, c.debug), memoryStore, ProvLayerMediaType, operation.provData)
		if err != nil {
			return nil, err
		}

		descriptors = append(descriptors, provDescriptor)
	}

	ociAnnotations := generateOCIAnnotations(meta, operation.creationTime)
	packManifestOptions := v2.PackManifestOptions{
		ManifestAnnotations: ociAnnotations,
		ConfigDescriptor:    &configDescriptor,
		Layers:              descriptors,
	}
	manifest, err := v2.PackManifest(ctx(c.out, c.debug), memoryStore, v2.PackManifestVersion1_0, ocispec.MediaTypeImageManifest, packManifestOptions)
	if err != nil {
		return nil, err
	}

	dst, err := v2remote.NewRepository(parsedRef.OrasReference.String())
	if err != nil {
		return nil, err
	}
	dst.Client = c.httpClient
	dst.PlainHTTP = c.plainHTTP
	//desc, err := dst.Resolve(ctx(c.out, c.debug), parsedRef.Tag)
	//if err != nil {
	//	return nil, err
	//}

	// Copy
	copyOptions := v2.DefaultExtendedCopyOptions
	_, err = v2.ExtendedCopy(ctx(c.out, c.debug), memoryStore, "", dst, parsedRef.OrasReference.String(), copyOptions)
	if err != nil {
		return nil, err
	}

	chartSummary := &descriptorPushSummaryWithMeta{
		Meta: meta,
	}
	chartSummary.Digest = chartDescriptor.Digest.String()
	chartSummary.Size = chartDescriptor.Size
	result := &PushResult{
		Manifest: &descriptorPushSummary{
			Digest: manifest.Digest.String(),
			Size:   manifest.Size,
		},
		Config: &descriptorPushSummary{
			Digest: configDescriptor.Digest.String(),
			Size:   configDescriptor.Size,
		},
		Chart: chartSummary,
		Prov:  &descriptorPushSummary{}, // prevent nil references
		Ref:   parsedRef.OrasReference.String(),
	}
	if operation.provData != nil {
		result.Prov = &descriptorPushSummary{
			Digest: provDescriptor.Digest.String(),
			Size:   provDescriptor.Size,
		}
	}
	_, _ = fmt.Fprintf(c.out, "Pushed: %s\n", result.Ref)
	_, _ = fmt.Fprintf(c.out, "Digest: %s\n", result.Manifest.Digest)
	if strings.Contains(parsedRef.OrasReference.Reference, "_") {
		_, _ = fmt.Fprintf(c.out, "%s contains an underscore.\n", result.Ref)
		_, _ = fmt.Fprint(c.out, registryUnderscoreMessage+"\n")
	}

	return result, err
}

// PushOptProvData returns a function that sets the prov bytes setting on push
func PushOptProvData(provData []byte) PushOption {
	return func(operation *pushOperation) {
		operation.provData = provData
	}
}

// PushOptStrictMode returns a function that sets the strictMode setting on push
func PushOptStrictMode(strictMode bool) PushOption {
	return func(operation *pushOperation) {
		operation.strictMode = strictMode
	}
}

// PushOptCreationTime returns a function that sets the creation time
func PushOptCreationTime(creationTime string) PushOption {
	return func(operation *pushOperation) {
		operation.creationTime = creationTime
	}
}

// Tags provides a sorted list all semver compliant tags for a given repository
func (c *Client) Tags(ref string) ([]string, error) {
	src, err := v2remote.NewRepository(ref)
	if err != nil {
		return nil, err
	}
	src.Client = c.httpClient
	src.PlainHTTP = c.plainHTTP

	var tagVersions []*semver.Version
	err = src.Tags(ctx(c.out, c.debug), "", func(tags []string) error {
		for _, tag := range tags {
			// Change underscore (_) back to plus (+) for Helm
			// See https://github.com/helm/helm/issues/10166
			tagVersion, err := semver.StrictNewVersion(strings.ReplaceAll(tag, "_", "+"))
			if err == nil {
				tagVersions = append(tagVersions, tagVersion)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort the collection
	sort.Sort(sort.Reverse(semver.Collection(tagVersions)))

	tags := make([]string, len(tagVersions))
	for iTv, tv := range tagVersions {
		tags[iTv] = tv.String()
	}

	return tags, nil
}

// Resolve a reference to a descriptor.
func (c *Client) Resolve(ref Reference) (*ocispec.Descriptor, error) {
	path := ref.Registry + "/" + ref.Repository
	src, err := v2remote.NewRepository(path)
	if err != nil {
		return nil, err
	}

	desc, err := src.Resolve(ctx(c.out, c.debug), ref.Tag)
	if err != nil {
		return nil, err
	}

	return &desc, err
}
