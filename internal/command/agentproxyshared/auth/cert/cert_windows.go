// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build windows

package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/certtostore"
)

// windowsCertStoreConfig carries the parameters needed to locate a client
// certificate and its private key in the Windows certificate store via CNG
// (or, if legacyKey is set, legacy CryptoAPI).
type windowsCertStoreConfig struct {
	enabled bool

	location            string // "local_machine" (default) or "current_user"
	provider            string
	container           string
	issuers             []string
	intermediateIssuers []string
	commonName          string
	legacyKey           bool
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

	var (
		leaf *x509.Certificate
		key  certtostore.Credential
	)

	if cfg.commonName != "" {
		cert, ctx, _, err := store.CertByCommonName(cfg.commonName)
		if err != nil {
			return nil, fmt.Errorf("failed to locate certificate with common name %q in windows certificate store: %w", cfg.commonName, err)
		}
		if cert == nil || ctx == nil {
			return nil, fmt.Errorf("no certificate with common name %q found in windows certificate store", cfg.commonName)
		}
		leaf = cert
		key, err = store.CertKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire private key for certificate with common name %q: %w", cfg.commonName, err)
		}
	} else {
		cert, ctx, err := store.CertWithContext()
		if err != nil {
			return nil, fmt.Errorf("failed to locate certificate in windows certificate store: %w", err)
		}
		if cert == nil || ctx == nil {
			return nil, errors.New("no matching certificate found in windows certificate store")
		}
		leaf = cert
		key, err = store.CertKey(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to acquire private key for certificate: %w", err)
		}
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

func openWindowsCertStore(cfg windowsCertStoreConfig) (*certtostore.WinCertStore, error) {
	switch cfg.location {
	case "", "local_machine":
		return certtostore.OpenWinCertStore(cfg.provider, cfg.container, cfg.issuers, cfg.intermediateIssuers, cfg.legacyKey)
	case "current_user":
		return certtostore.OpenWinCertStoreCurrentUser(cfg.provider, cfg.container, cfg.issuers, cfg.intermediateIssuers, cfg.legacyKey)
	default:
		return nil, fmt.Errorf("unknown windows certificate store location %q", cfg.location)
	}
}
