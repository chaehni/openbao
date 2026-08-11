// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/v2/internal/command/agentproxyshared/auth"
)

func TestCertAuthMethod_Authenticate(t *testing.T) {
	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"name": "foo",
		},
	}

	method, err := NewCertAuthMethod(config)
	if err != nil {
		t.Fatal(err)
	}

	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	loginPath, _, authMap, err := method.Authenticate(t.Context(), client)
	if err != nil {
		t.Fatal(err)
	}

	expectedLoginPath := path.Join(config.MountPath, "/login")
	if loginPath != expectedLoginPath {
		t.Fatalf("mismatch on login path: got: %s, expected: %s", loginPath, expectedLoginPath)
	}

	expectedAuthMap := map[string]any{
		"name": config.Config["name"],
	}
	if !reflect.DeepEqual(authMap, expectedAuthMap) {
		t.Fatalf("mismatch on login path:\ngot:\n\t%v\nexpected:\n\t%v", authMap, expectedAuthMap)
	}
}

func TestCertAuthMethod_AuthClient_withoutCerts(t *testing.T) {
	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"name": "without-certs",
		},
	}

	method, err := NewCertAuthMethod(config)
	if err != nil {
		t.Fatal(err)
	}

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	clientToUse, err := method.(auth.AuthMethodWithClient).AuthClient(client)
	if err != nil {
		t.Fatal(err)
	}

	if client != clientToUse {
		t.Fatal("error: expected AuthClient to return back original client")
	}
}

func TestCertAuthMethod_AuthClient_withCerts(t *testing.T) {
	clientCert, err := os.Open("./test-fixtures/keys/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer clientCert.Close()

	clientKey, err := os.Open("./test-fixtures/keys/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer clientKey.Close()

	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"name":        "with-certs",
			"client_cert": clientCert.Name(),
			"client_key":  clientKey.Name(),
		},
	}

	method, err := NewCertAuthMethod(config)
	if err != nil {
		t.Fatal(err)
	}

	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	clientToUse, err := method.(auth.AuthMethodWithClient).AuthClient(client)
	if err != nil {
		t.Fatal(err)
	}

	if client == clientToUse {
		t.Fatal("expected client from AuthClient to be different from original client")
	}

	// Call AuthClient again to get back the cached client
	cachedClient, err := method.(auth.AuthMethodWithClient).AuthClient(client)
	if err != nil {
		t.Fatal(err)
	}

	if cachedClient != clientToUse {
		t.Fatal("expected client from AuthClient to return back a cached client")
	}
}

func TestCertAuthMethod_AuthClient_withCertsReload(t *testing.T) {
	clientCert, err := os.Open("./test-fixtures/keys/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	defer clientCert.Close()

	clientKey, err := os.Open("./test-fixtures/keys/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	defer clientKey.Close()

	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"name":        "with-certs-reloaded",
			"client_cert": clientCert.Name(),
			"client_key":  clientKey.Name(),
			"reload":      true,
		},
	}

	method, err := NewCertAuthMethod(config)
	if err != nil {
		t.Fatal(err)
	}

	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	clientToUse, err := method.(auth.AuthMethodWithClient).AuthClient(client)
	if err != nil {
		t.Fatal(err)
	}

	if client == clientToUse {
		t.Fatal("expected client from AuthClient to be different from original client")
	}

	// Call AuthClient again to get back a new client with reloaded certificates
	reloadedClient, err := method.(auth.AuthMethodWithClient).AuthClient(client)
	if err != nil {
		t.Fatal(err)
	}

	if reloadedClient == clientToUse {
		t.Fatal("expected client from AuthClient to return back a new client")
	}
}

func TestCertAuthMethod_WindowsCertStore_ConflictsWithClientCert(t *testing.T) {
	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"windows_cert_store_common_name": "example",
			"client_cert":                    "./test-fixtures/keys/cert.pem",
			"client_key":                     "./test-fixtures/keys/key.pem",
		},
	}

	if _, err := NewCertAuthMethod(config); err == nil {
		t.Fatal("expected error when combining windows_cert_store_* config with client_cert/client_key")
	}
}

func TestCertAuthMethod_WindowsCertStore_RequiresLocator(t *testing.T) {
	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"windows_cert_store_location": "current_user",
		},
	}

	if _, err := NewCertAuthMethod(config); err == nil {
		t.Fatal("expected error when windows_cert_store_* config is present without a common name")
	}
}

func TestCertAuthMethod_WindowsCertStore_InvalidLocation(t *testing.T) {
	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"windows_cert_store_common_name": "example",
			"windows_cert_store_location":    "not-a-real-location",
		},
	}

	if _, err := NewCertAuthMethod(config); err == nil {
		t.Fatal("expected error for invalid windows_cert_store_location")
	}
}

func TestCertAuthMethod_WindowsCertStore_ParsesConfig(t *testing.T) {
	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"windows_cert_store_common_name": "example",
			"windows_cert_store_location":    "current_user",
			"windows_cert_store_provider":    "Microsoft Platform Crypto Provider",
		},
	}

	method, err := NewCertAuthMethod(config)
	if err != nil {
		t.Fatal(err)
	}

	c, ok := method.(*certMethod)
	if !ok {
		t.Fatal("expected *certMethod")
	}

	if !c.windowsCertStore.enabled {
		t.Fatal("expected windowsCertStore to be enabled")
	}
	if c.windowsCertStore.commonName != "example" {
		t.Fatalf("unexpected common name: %s", c.windowsCertStore.commonName)
	}
	if c.windowsCertStore.location != "current_user" {
		t.Fatalf("unexpected location: %s", c.windowsCertStore.location)
	}
	if c.windowsCertStore.provider != "Microsoft Platform Crypto Provider" {
		t.Fatalf("unexpected provider: %s", c.windowsCertStore.provider)
	}
}

func TestCertAuthMethod_WindowsCertStore_DefaultProvider(t *testing.T) {
	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"windows_cert_store_common_name": "example",
		},
	}

	method, err := NewCertAuthMethod(config)
	if err != nil {
		t.Fatal(err)
	}

	c := method.(*certMethod)
	if c.windowsCertStore.provider != "Microsoft Software Key Storage Provider" {
		t.Fatalf("unexpected default provider: %s", c.windowsCertStore.provider)
	}
}

// On non-Windows platforms, AuthClient must fail clearly rather than silently
// falling back to an unauthenticated client, since callers rely on cert auth
// actually presenting a client certificate.
func TestCertAuthMethod_WindowsCertStore_UnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this test exercises the non-windows stub")
	}

	config := &auth.AuthConfig{
		Logger:    hclog.NewNullLogger(),
		MountPath: "cert-test",
		Config: map[string]any{
			"windows_cert_store_common_name": "example",
		},
	}

	method, err := NewCertAuthMethod(config)
	if err != nil {
		t.Fatal(err)
	}

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	_, err = method.(auth.AuthMethodWithClient).AuthClient(client)
	if err == nil {
		t.Fatal("expected error configuring windows certificate store client certificate on a non-windows platform")
	}
	if !strings.Contains(err.Error(), "windows") {
		t.Fatalf("expected error to mention windows, got: %v", err)
	}
}
