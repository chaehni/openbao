// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package cert

import (
	"crypto/tls"
	"errors"
)

// windowsCertStoreConfig carries the parameters needed to locate a client
// certificate and its private key in the Windows certificate store. On
// non-Windows platforms this is unsupported; see cert_windows.go.
type windowsCertStoreConfig struct {
	enabled bool

	location   string
	provider   string
	commonName string
}

func newWindowsClientCertificateFunc(windowsCertStoreConfig) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	return nil, errors.New("windows_cert_store is only supported when the agent is built for windows (GOOS=windows)")
}
