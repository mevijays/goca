/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// GocaProvider configures a store to fetch secrets from goca
// (https://github.com/mevijays/goca), a self-hosted certificate authority
// with a built-in secret manager.
//
// Unlike goca's generic Webhook-provider integration, this provider mints a
// fresh, short-lived Kubernetes ServiceAccount token via the TokenRequest API
// on every fetch, for the ServiceAccount named in ServiceAccountRef - not a
// long-lived token read from a referenced Secret. There is nothing to
// provision or rotate: the operator's own ServiceAccount needs RBAC
// permission to create tokens for the target ServiceAccount
// (serviceaccounts/token, scoped by your own RBAC to whichever
// namespaces/ServiceAccounts should be able to authenticate as themselves -
// see docs/eso.md in the goca repository).
//
// goca verifies the minted token the same way it verifies a CSI provider's
// per-pod token: via TokenReview against the Kubernetes API server, under
// the trust domain named by AuthMethod. Authorization is per secret, via
// goca's own bindings (namespace, ServiceAccount, trust domain) - this
// provider carries no concept of a goca user or role, and is read-only:
// goca's workload-facing endpoint has no write path, by design.
type GocaProvider struct {
	// Server is the goca server's base URL, e.g. https://ca.example.com.
	// +kubebuilder:validation:MinLength:=1
	Server string `json:"server"`

	// Audience is the audience the minted token must be bound to. Must match
	// the audience of the goca CSI trust domain named by AuthMethod.
	// +optional
	// +kubebuilder:default:="goca-csi"
	Audience string `json:"audience,omitempty"`

	// AuthMethod names the goca CSI trust domain (a k8s_auth_methods row)
	// this store authenticates against, sent as the X-Goca-Auth-Method
	// header. Leave empty for goca's "default" trust domain (a single
	// cluster configured via config.yaml rather than the k8s_auth_methods
	// API).
	// +optional
	AuthMethod string `json:"authMethod,omitempty"`

	// ServiceAccountRef names the ServiceAccount whose identity goca
	// verifies this store's requests as. A fresh token is requested for it
	// via the TokenRequest API on every fetch - see the type's doc comment
	// for the RBAC this requires.
	ServiceAccountRef esmeta.ServiceAccountSelector `json:"serviceAccountRef"`

	// PEM-encoded CA bundle used to validate goca's TLS certificate. Only
	// used if Server is https. If neither this nor CAProvider is set, the
	// system root certificates are used.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`

	// The provider for the CA bundle to use to validate goca's TLS
	// certificate.
	// +optional
	CAProvider *CAProvider `json:"caProvider,omitempty"`
}
