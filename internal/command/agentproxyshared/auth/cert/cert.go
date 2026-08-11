// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/command/agentproxyshared/auth"
)

type certMethod struct {
	logger    hclog.Logger
	mountPath string
	name      string

	caCert     string
	clientCert string
	clientKey  string
	reload     bool

	// windowsCertStore, when true, sources the client certificate and its
	// private key from the Windows certificate store (via CNG/CryptoAPI)
	// instead of from clientCert/clientKey on disk. It is mutually
	// exclusive with clientCert/clientKey.
	windowsCertStore windowsCertStoreConfig

	// Client is the cached client to use if cert info was provided.
	client *api.Client
}

var _ auth.AuthMethodWithClient = &certMethod{}

func NewCertAuthMethod(conf *auth.AuthConfig) (auth.AuthMethod, error) {
	if conf == nil {
		return nil, errors.New("empty config")
	}

	// Not concerned if the conf.Config is empty as the 'name'
	// parameter is optional when using TLS Auth

	c := &certMethod{
		logger:    conf.Logger,
		mountPath: conf.MountPath,
	}

	if conf.Config != nil {
		nameRaw, ok := conf.Config["name"]
		if !ok {
			nameRaw = ""
		}
		c.name, ok = nameRaw.(string)
		if !ok {
			return nil, errors.New("could not convert 'name' config value to string")
		}

		caCertRaw, ok := conf.Config["ca_cert"]
		if ok {
			c.caCert, ok = caCertRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'ca_cert' config value to string")
			}
		}

		clientCertRaw, ok := conf.Config["client_cert"]
		if ok {
			c.clientCert, ok = clientCertRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'cert_file' config value to string")
			}
		}

		clientKeyRaw, ok := conf.Config["client_key"]
		if ok {
			c.clientKey, ok = clientKeyRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'cert_key' config value to string")
			}
		}

		reload, ok := conf.Config["reload"]
		if ok {
			c.reload, ok = reload.(bool)
			if !ok {
				return nil, errors.New("could not convert 'reload' config value to bool")
			}
		}

		// windows_cert_store is not a separate enable flag: it's inferred
		// from whether any windows_cert_store_* field is present, the same
		// way client_cert/client_key imply their own use without a
		// separate boolean.
		var sawWindowsCertStoreConfig bool

		locationRaw, ok := conf.Config["windows_cert_store_location"]
		if ok {
			sawWindowsCertStoreConfig = true
			c.windowsCertStore.location, ok = locationRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'windows_cert_store_location' config value to string")
			}
		}
		switch c.windowsCertStore.location {
		case "", "local_machine", "current_user":
		default:
			return nil, fmt.Errorf("invalid 'windows_cert_store_location' value %q: must be 'local_machine' or 'current_user'", c.windowsCertStore.location)
		}

		c.windowsCertStore.provider = "Microsoft Software Key Storage Provider"
		providerRaw, ok := conf.Config["windows_cert_store_provider"]
		if ok {
			sawWindowsCertStoreConfig = true
			c.windowsCertStore.provider, ok = providerRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'windows_cert_store_provider' config value to string")
			}
		}

		containerRaw, ok := conf.Config["windows_cert_store_container"]
		if ok {
			sawWindowsCertStoreConfig = true
			c.windowsCertStore.container, ok = containerRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'windows_cert_store_container' config value to string")
			}
		}

		commonNameRaw, ok := conf.Config["windows_cert_store_common_name"]
		if ok {
			sawWindowsCertStoreConfig = true
			c.windowsCertStore.commonName, ok = commonNameRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'windows_cert_store_common_name' config value to string")
			}
		}

		issuersRaw, ok := conf.Config["windows_cert_store_issuers"]
		if ok {
			sawWindowsCertStoreConfig = true
			var err error
			c.windowsCertStore.issuers, err = parseutil.ParseCommaStringSlice(issuersRaw)
			if err != nil {
				return nil, fmt.Errorf("could not parse 'windows_cert_store_issuers' config value: %w", err)
			}
		}

		intermediateIssuersRaw, ok := conf.Config["windows_cert_store_intermediate_issuers"]
		if ok {
			sawWindowsCertStoreConfig = true
			var err error
			c.windowsCertStore.intermediateIssuers, err = parseutil.ParseCommaStringSlice(intermediateIssuersRaw)
			if err != nil {
				return nil, fmt.Errorf("could not parse 'windows_cert_store_intermediate_issuers' config value: %w", err)
			}
		}

		legacyKeyRaw, ok := conf.Config["windows_cert_store_legacy_key"]
		if ok {
			sawWindowsCertStoreConfig = true
			c.windowsCertStore.legacyKey, ok = legacyKeyRaw.(bool)
			if !ok {
				return nil, errors.New("could not convert 'windows_cert_store_legacy_key' config value to bool")
			}
		}

		c.windowsCertStore.enabled = c.windowsCertStore.commonName != "" || c.windowsCertStore.container != "" || len(c.windowsCertStore.issuers) > 0

		if c.windowsCertStore.enabled && (c.clientCert != "" || c.clientKey != "") {
			return nil, errors.New("'client_cert'/'client_key' cannot be used together with windows_cert_store_* configuration")
		}

		if sawWindowsCertStoreConfig && !c.windowsCertStore.enabled {
			return nil, errors.New("windows_cert_store_* configuration requires either 'windows_cert_store_common_name' or 'windows_cert_store_container'/'windows_cert_store_issuers' to locate the certificate")
		}
	}

	return c, nil
}

func (c *certMethod) Authenticate(_ context.Context, client *api.Client) (string, http.Header, map[string]any, error) {
	c.logger.Trace("beginning authentication")

	authMap := map[string]any{}

	if c.name != "" {
		authMap["name"] = c.name
	}

	return fmt.Sprintf("%s/login", c.mountPath), nil, authMap, nil
}

func (c *certMethod) NewCreds() chan struct{} {
	return nil
}

func (c *certMethod) CredSuccess() {}

func (c *certMethod) Shutdown() {}

// AuthClient uses the existing client's address and returns a new client with
// the auto-auth method's certificate information if that's provided in its
// config map.
func (c *certMethod) AuthClient(client *api.Client) (*api.Client, error) {
	c.logger.Trace("deriving auth client to use")

	clientToAuth := client

	if c.windowsCertStore.enabled || c.caCert != "" || (c.clientKey != "" && c.clientCert != "") {
		// Return cached client if present
		if c.client != nil && !c.reload {
			return c.client, nil
		}

		config := api.DefaultConfig()
		if config.Error != nil {
			return nil, config.Error
		}
		config.Address = client.Address()

		t := &api.TLSConfig{
			CACert: c.caCert,
		}
		if !c.windowsCertStore.enabled {
			t.ClientCert = c.clientCert
			t.ClientKey = c.clientKey
		}

		// Setup TLS config
		if err := config.ConfigureTLS(t); err != nil {
			return nil, err
		}

		if c.windowsCertStore.enabled {
			getClientCertificate, err := newWindowsClientCertificateFunc(c.windowsCertStore)
			if err != nil {
				return nil, fmt.Errorf("failed to configure windows certificate store client certificate: %w", err)
			}

			transport, ok := config.HttpClient.Transport.(*http.Transport)
			if !ok || transport.TLSClientConfig == nil {
				return nil, errors.New("unexpected HTTP transport, cannot configure windows certificate store client certificate")
			}
			transport.TLSClientConfig.GetClientCertificate = getClientCertificate
		}

		var err error
		clientToAuth, err = api.NewClient(config)
		if err != nil {
			return nil, err
		}
		if ns := client.Headers().Get(consts.NamespaceHeaderName); ns != "" {
			clientToAuth.SetNamespace(ns)
		}

		// Cache the client for future use
		c.client = clientToAuth
	}

	return clientToAuth, nil
}
