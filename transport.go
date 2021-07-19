/*
Copyright 2017 Frederic Branczyk All rights reserved.

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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

func initTransport(upstreamCAFile, upstreamClientCertFile, upstreamClientKeyFile string) (http.RoundTripper, error) {
	if upstreamCAFile == "" && upstreamClientCertFile == "" && upstreamClientKeyFile == "" {
		return http.DefaultTransport, nil
	}

	// http.Transport sourced from go 1.10.7
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       &tls.Config{},
	}

	// If RootCAs is nil, the system root certificates will be used.
	if upstreamCAFile != "" {
		roots, err := loadRootCA(upstreamCAFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig.RootCAs = roots
	}

	if upstreamClientCertFile != "" && upstreamClientKeyFile != "" {
		clientCert, err := loadClientCertificateCredentials(upstreamClientCertFile, upstreamClientKeyFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
	}
	return transport, nil
}

func loadRootCA(upstreamCAFile string) (*x509.CertPool, error) {
	rootPEM, err := ioutil.ReadFile(upstreamCAFile)
	if err != nil {
		return nil, fmt.Errorf("error reading upstream CA file: %v", err)
	}

	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(rootPEM)); !ok {
		return nil, errors.New("error parsing upstream CA certificate")
	}
	return roots, nil
}

// injectClientCertificateCredentials adds the provided client certificate and
// key to the given HTTP transport. This is used when authenticating to
// upstreams using client certificate credentials.
func loadClientCertificateCredentials(certificateFilePath, keyFilePath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certificateFilePath, keyFilePath)
	if err != nil {
		return tls.Certificate{}, nil
	}

	return cert, nil
}
