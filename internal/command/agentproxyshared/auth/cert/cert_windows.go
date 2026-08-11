// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package cert

import (
	"crypto/tls"
	"fmt"

	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
)

// windowsCertStoreConfig carries the parameters needed to locate a client
// certificate and its private key in the Windows certificate store via CNG.
type windowsCertStoreConfig struct {
	enabled bool

	location   string // "local_machine" (default) or "current_user"
	provider   string
	commonName string
}

// newWindowsClientCertificateFunc returns a tls.Config.GetClientCertificate
// callback that sources the client certificate and private key from the
// Windows certificate store instead of from disk. The private key never
// leaves the store (it may be TPM- or HSM-backed); signing during the TLS
// handshake is delegated to it via CNG/CryptoAPI.
func newWindowsClientCertificateFunc(cfg windowsCertStoreConfig) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	store, err := openWindowsCertStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open windows certificate store: %w", err)
	}

	cert, ctx, _, err := store.CertByCommonName(cfg.commonName)
	if err != nil {
		return nil, fmt.Errorf("failed to locate certificate with common name %q in windows certificate store: %w", cfg.commonName, err)
	}
	if cert == nil || ctx == nil {
		return nil, fmt.Errorf("no certificate with common name %q found in windows certificate store", cfg.commonName)
	}
	leaf := cert
	key, err := store.CertKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire private key for certificate with common name %q: %w", cfg.commonName, err)
	}

	chain := [][]byte{leaf.Raw}
	if intermediate, err := store.Intermediate(); err == nil && intermediate != nil {
		chain = append(chain, intermediate.Raw)
	}

	tlsCert := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        leaf,
	}

	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return tlsCert, nil
	}, nil
}

// openWindowsCertStore opens the store read-only. The default open mode
// certtostore's OpenWinCertStore/OpenWinCertStoreCurrentUser use implicitly
// requests read-write access to the store; for LocalMachine that requires
// admin/SYSTEM-level access even though we only ever read a certificate and
// delegate signing to CNG. A non-admin account (e.g. a dedicated service
// account with the private key's ACL granted to it, but no broader access to
// the store itself) can fail to open the store at all as a result. Passing
// CERT_STORE_READONLY_FLAG avoids requesting more than we need.
func openWindowsCertStore(cfg windowsCertStoreConfig) (*certtostore.WinCertStore, error) {
	// The container, issuers, and legacyKey arguments to
	// DefaultWinCertStoreOptions only matter for certtostore's
	// Key()/Generate()/CertWithContext(), none of which we call - we always
	// find the certificate by common name via CertByCommonName() and use
	// CertKey(), which resolves the private key via the certificate's own
	// built-in key association and unconditionally requires a CNG
	// (NCrypt) key (CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG), so legacy CAPI
	// keys are never reachable through this path regardless.
	opts := certtostore.DefaultWinCertStoreOptions(cfg.provider, "", nil, nil, false)
	opts.StoreFlags = windows.CERT_STORE_READONLY_FLAG

	switch cfg.location {
	case "", "local_machine":
	case "current_user":
		opts.CurrentUser = true
	default:
		return nil, fmt.Errorf("unknown windows certificate store location %q", cfg.location)
	}

	return certtostore.OpenWinCertStoreWithOptions(opts)
}
