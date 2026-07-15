package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func buildInboundSSHServerConfig(user, password, authorizedKeysPath, hostKeyPath string) (*ssh.ServerConfig, error) {
	cfg := &ssh.ServerConfig{}

	if password != "" {
		cfg.PasswordCallback = func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if user != "" && conn.User() != user {
				return nil, fmt.Errorf("unexpected user %q", conn.User())
			}
			if subtle.ConstantTimeCompare([]byte(password), pass) != 1 {
				return nil, errors.New("password rejected")
			}
			return nil, nil
		}
	}

	if authorizedKeysPath != "" {
		authorizedKeys, err := loadAuthorizedKeys(authorizedKeysPath)
		if err != nil {
			return nil, err
		}
		cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if user != "" && conn.User() != user {
				return nil, fmt.Errorf("unexpected user %q", conn.User())
			}
			if _, ok := authorizedKeys[string(key.Marshal())]; !ok {
				return nil, errors.New("public key rejected")
			}
			return nil, nil
		}
	}

	if cfg.PasswordCallback == nil && cfg.PublicKeyCallback == nil {
		return nil, errors.New("client requires at least one inbound auth method: -password or -authorized-keys")
	}

	signer, err := loadPrivateKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load host key: %w", err)
	}
	cfg.AddHostKey(signer)
	return cfg, nil
}

func buildOutboundSSHClientConfig(user, password, keyPath, knownHostsPath string, insecureHostKey bool, timeout time.Duration) (*ssh.ClientConfig, error) {
	var auth []ssh.AuthMethod
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}
	if keyPath != "" {
		signer, err := loadPrivateKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("load private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if len(auth) == 0 {
		return nil, errors.New("server requires at least one outbound auth method: -password or -key")
	}

	hostKeyCallback, err := buildHostKeyCallback(knownHostsPath, insecureHostKey)
	if err != nil {
		return nil, err
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}, nil
}

func buildHostKeyCallback(knownHostsPath string, insecureHostKey bool) (ssh.HostKeyCallback, error) {
	if insecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if knownHostsPath == "" {
		return nil, errors.New("server requires -known-hosts or explicit -insecure-skip-host-key-check")
	}
	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return callback, nil
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func loadAuthorizedKeys(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load authorized_keys: %w", err)
	}

	keys := make(map[string]struct{})
	for len(data) > 0 {
		key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse authorized_keys: %w", err)
		}
		keys[string(key.Marshal())] = struct{}{}
		data = rest
	}
	if len(keys) == 0 {
		return nil, errors.New("authorized_keys contained no keys")
	}
	return keys, nil
}
