// Package csi implements the Secrets Store CSI Driver provider side of
// goca's secret manager: a gRPC server, run as `goca run csi-provider`
// inside a small DaemonSet pod on every node, that the upstream
// secrets-store-csi-driver talks to over a Unix domain socket.
//
// Provider holds no database or vault key material of its own. Every Mount
// call forwards the requesting pod's own bound ServiceAccount token to the
// central goca server's POST /api/v1/vault/fetch endpoint over HTTPS, and
// that server - already the trust boundary for CA private keys and every
// other secret in this application - is the only place that authenticates
// the token, authorizes it against a secret's bindings, and holds the vault
// key needed to decrypt anything. This keeps the same "one place holds the
// keys" property the rest of goca already has: compromising a node's
// provider pod yields no credentials beyond what that pod's own workloads
// could already request for themselves.
package csi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	v1alpha1 "github.com/mevijays/goca/internal/csi/v1alpha1"
)

// certFileSemantics maps the fixed file names internal/vault.Materialize
// always uses for a certificate secret onto the semantic keys a
// SecretProviderClass's "items" map may use to rename them - see the
// package example in k8s-demo/csi.
var certFileSemantics = map[string]string{
	"tls.crt": "cert",
	"tls.key": "key",
	"ca.crt":  "ca",
}

// Provider implements v1alpha1.CSIDriverProviderServer.
type Provider struct {
	v1alpha1.UnimplementedCSIDriverProviderServer

	// Audience selects which entry of the token map the driver injects
	// into MountRequest to forward - it must match the CSIDriver's
	// spec.tokenRequests[].audience (see k8s-demo/csi/csidriver.yaml).
	Audience string
	// AuthMethod names the CSI trust domain (a k8s_auth_methods row on the
	// goca server) this provider runs in - typically the cluster's name. It
	// is sent as the X-Goca-Auth-Method header so the server verifies the
	// pod's token under exactly this domain's Verifier and scopes secret
	// bindings to it. Empty means "default".
	AuthMethod string
	// DefaultGocaAddress is used when a SecretProviderClass's parameters
	// omit gocaAddress.
	DefaultGocaAddress string
	// HTTPClient talks to the goca server. Configure its Transport for TLS
	// trust (a custom CA for a self-signed deployment) and timeouts.
	HTTPClient *http.Client
	// RuntimeVersion is reported in VersionResponse - goca's own build
	// version.
	RuntimeVersion string
	Log            *slog.Logger
}

func (p *Provider) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// Version implements the CSIDriverProvider.Version RPC.
func (p *Provider) Version(context.Context, *v1alpha1.VersionRequest) (*v1alpha1.VersionResponse, error) {
	return &v1alpha1.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "goca",
		RuntimeVersion: p.RuntimeVersion,
	}, nil
}

// objectSpec is one entry of a SecretProviderClass's "objects" YAML list.
type objectSpec struct {
	SecretName string            `yaml:"secretName"`
	FileName   string            `yaml:"fileName,omitempty"` // kv/file secrets: the mounted file's name
	Items      map[string]string `yaml:"items,omitempty"`    // certificate secrets: semantic name (cert|key|ca) -> mounted file name
}

// tokenInfo is one entry of the csi.storage.k8s.io/serviceAccount.tokens map
// the driver injects when the CSIDriver has tokenRequests configured.
type tokenInfo struct {
	Token               string `json:"token"`
	ExpirationTimestamp string `json:"expirationTimestamp"`
}

// Mount implements the CSIDriverProvider.Mount RPC: resolves every object a
// SecretProviderClass lists and returns their content as mount files.
// Resolution fails closed - if any requested object cannot be fetched
// (not found, not authorized, a transient error), the whole call fails
// rather than mounting a partial, silently-incomplete volume.
func (p *Provider) Mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {
	var attrs map[string]string
	if err := json.Unmarshal([]byte(req.GetAttributes()), &attrs); err != nil {
		return nil, fmt.Errorf("csi: parse mount attributes: %w", err)
	}

	podNamespace := attrs["csi.storage.k8s.io/pod.namespace"]
	podName := attrs["csi.storage.k8s.io/pod.name"]
	podSA := attrs["csi.storage.k8s.io/serviceAccount.name"]

	var objects []objectSpec
	if err := yaml.Unmarshal([]byte(attrs["objects"]), &objects); err != nil {
		return nil, fmt.Errorf("csi: parse SecretProviderClass objects: %w", err)
	}
	if len(objects) == 0 {
		return nil, errors.New("csi: SecretProviderClass has no objects listed")
	}

	token, err := p.podToken(attrs)
	if err != nil {
		return nil, fmt.Errorf("csi: %w (pod %s/%s, ServiceAccount %s)", err, podNamespace, podName, podSA)
	}

	gocaAddress := strings.TrimSpace(attrs["gocaAddress"])
	if gocaAddress == "" {
		gocaAddress = p.DefaultGocaAddress
	}
	if gocaAddress == "" {
		return nil, errors.New("csi: no gocaAddress in the SecretProviderClass parameters and no default configured")
	}

	names := make([]string, len(objects))
	for i, o := range objects {
		if strings.TrimSpace(o.SecretName) == "" {
			return nil, fmt.Errorf("csi: objects[%d] has no secretName", i)
		}
		names[i] = o.SecretName
	}

	results, err := p.fetch(ctx, gocaAddress, token, names)
	if err != nil {
		return nil, fmt.Errorf("csi: fetch secrets from %s: %w", gocaAddress, err)
	}
	byName := make(map[string]fetchResult, len(results))
	for _, r := range results {
		byName[r.SecretName] = r
	}

	resp := &v1alpha1.MountResponse{}
	for _, o := range objects {
		r, ok := byName[o.SecretName]
		if !ok {
			return nil, fmt.Errorf("csi: server returned no result for secret %q", o.SecretName)
		}
		if r.Error != "" {
			return nil, fmt.Errorf("csi: secret %q: %s", o.SecretName, r.Error)
		}
		if len(r.Files) > 1 && o.FileName != "" {
			return nil, fmt.Errorf("csi: secret %q resolved to %d files (it is likely a certificate secret); "+
				"use \"items\" to rename them, not \"fileName\"", o.SecretName, len(r.Files))
		}
		for _, f := range r.Files {
			mountName, err := targetFileName(o, f.Name)
			if err != nil {
				return nil, fmt.Errorf("csi: secret %q: %w", o.SecretName, err)
			}
			data, err := base64.StdEncoding.DecodeString(f.DataBase64)
			if err != nil {
				return nil, fmt.Errorf("csi: secret %q file %q: invalid base64 from server: %w", o.SecretName, f.Name, err)
			}
			resp.Files = append(resp.Files, &v1alpha1.File{
				Path:     mountName,
				Mode:     0o600,
				Contents: data,
			})
		}
		resp.ObjectVersion = append(resp.ObjectVersion, &v1alpha1.ObjectVersion{
			Id:      o.SecretName,
			Version: r.Version,
		})
	}

	p.log().Info("csi mount", "pod_namespace", podNamespace, "pod_name", podName,
		"service_account", podSA, "objects", len(objects), "files", len(resp.Files))
	return resp, nil
}

// targetFileName resolves the mounted path for one materialized file,
// applying a SecretProviderClass's fileName/items override, and rejects
// anything that would escape the mount directory.
func targetFileName(o objectSpec, materializedName string) (string, error) {
	name := materializedName
	switch {
	case len(o.Items) > 0:
		// Certificate-secret semantics: rename by the fixed cert/key/ca
		// role, not by whatever internal/vault happened to name the file.
		if semantic, ok := certFileSemantics[materializedName]; ok {
			if renamed := o.Items[semantic]; renamed != "" {
				name = renamed
			}
		}
	case o.FileName != "":
		name = o.FileName
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
		return "", fmt.Errorf("mount file name %q is not a safe relative path", name)
	}
	return clean, nil
}

// podToken extracts the bound token for p.Audience out of the
// csi.storage.k8s.io/serviceAccount.tokens attribute, which is only present
// when the CSIDriver object has spec.tokenRequests configured for that
// audience - see k8s-demo/csi/csidriver.yaml.
func (p *Provider) podToken(attrs map[string]string) (string, error) {
	raw := attrs["csi.storage.k8s.io/serviceAccount.tokens"]
	if raw == "" {
		return "", errors.New("no ServiceAccount token was provided by the driver - " +
			"is CSIDriver.spec.tokenRequests configured with this provider's audience?")
	}
	var tokens map[string]tokenInfo
	if err := json.Unmarshal([]byte(raw), &tokens); err != nil {
		return "", fmt.Errorf("parse serviceAccount.tokens: %w", err)
	}
	t, ok := tokens[p.Audience]
	if !ok || t.Token == "" {
		return "", fmt.Errorf("no token was issued for audience %q", p.Audience)
	}
	return t.Token, nil
}

//
// ---------- goca server client ----------
//

type fetchRequest struct {
	Secrets []string `json:"secrets"`
}

type fetchFile struct {
	Name       string `json:"name"`
	DataBase64 string `json:"data_base64"`
}

type fetchResult struct {
	SecretName string      `json:"secret_name"`
	Version    string      `json:"version,omitempty"`
	Files      []fetchFile `json:"files,omitempty"`
	Error      string      `json:"error,omitempty"`
}

type fetchResponse struct {
	Identity string        `json:"identity"`
	Results  []fetchResult `json:"results"`
}

// fetch calls the goca server's POST /api/v1/vault/fetch, forwarding the
// requesting pod's own token as the caller's credential - the server, not
// this provider, decides whether that identity may read each secret.
func (p *Provider) fetch(ctx context.Context, gocaAddress, token string, secretNames []string) ([]fetchResult, error) {
	payload, err := json.Marshal(fetchRequest{Secrets: secretNames})
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(gocaAddress, "/") + "/api/v1/vault/fetch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if p.AuthMethod != "" {
		req.Header.Set("X-Goca-Auth-Method", p.AuthMethod)
	}

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	var out fetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out.Results, nil
}
