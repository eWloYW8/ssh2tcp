package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const defaultHostKeyPath = ".ssh2tcp/host_key"

var userHomeDir = os.UserHomeDir

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

	signer, resolvedHostKeyPath, created, err := loadInboundHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load host key: %w", err)
	}
	if created {
		log.Printf("generated client host key at %s", resolvedHostKeyPath)
	} else if hostKeyPath == "" {
		log.Printf("using client host key at %s", resolvedHostKeyPath)
	}
	cfg.AddHostKey(signer)
	return cfg, nil
}

func buildOutboundSSHClientConfig(user, password, keyPath, knownHostsPath, hostKeyFingerprint string, insecureHostKey bool, timeout time.Duration) (*ssh.ClientConfig, error) {
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

	hostKeyCallback, err := buildHostKeyCallback(knownHostsPath, hostKeyFingerprint, insecureHostKey)
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

func buildHostKeyCallback(knownHostsPath, hostKeyFingerprint string, insecureHostKey bool) (ssh.HostKeyCallback, error) {
	hostKeyFingerprint = normalizeFingerprint(hostKeyFingerprint)

	selectedMethods := 0
	for _, enabled := range []bool{knownHostsPath != "", hostKeyFingerprint != "", insecureHostKey} {
		if enabled {
			selectedMethods++
		}
	}
	if selectedMethods > 1 {
		return nil, errors.New("server requires only one host key verification mode: -known-hosts, -host-key-fingerprint, or -insecure-skip-host-key-check")
	}

	if hostKeyFingerprint != "" {
		return trustedFingerprintCallback(hostKeyFingerprint), nil
	}
	if insecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if knownHostsPath == "" {
		return nil, errors.New("server requires -known-hosts, -host-key-fingerprint, or explicit -insecure-skip-host-key-check")
	}
	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return callback, nil
}

func trustedFingerprintCallback(expected string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		sha256Fingerprint := ssh.FingerprintSHA256(key)
		md5Fingerprint := ssh.FingerprintLegacyMD5(key)
		if expected == sha256Fingerprint || expected == md5Fingerprint {
			return nil
		}
		return fmt.Errorf("host key fingerprint mismatch for %s: got %s", hostname, sha256Fingerprint)
	}
}

func normalizeFingerprint(fingerprint string) string {
	fingerprint = strings.TrimSpace(fingerprint)
	lower := strings.ToLower(fingerprint)
	switch {
	case strings.HasPrefix(lower, "sha256:"):
		return "SHA256:" + fingerprint[len("sha256:"):]
	case strings.HasPrefix(lower, "md5:"):
		return "MD5:" + strings.ToLower(fingerprint[len("md5:"):])
	case fingerprint != "" && !strings.Contains(fingerprint, ":"):
		return "SHA256:" + fingerprint
	default:
		return fingerprint
	}
}

func loadInboundHostKey(path string) (ssh.Signer, string, bool, error) {
	if strings.TrimSpace(path) != "" {
		signer, err := loadPrivateKey(path)
		return signer, path, false, err
	}

	home, err := userHomeDir()
	if err != nil {
		return nil, "", false, err
	}
	resolvedPath := filepath.Join(home, defaultHostKeyPath)

	data, err := os.ReadFile(resolvedPath)
	if err == nil {
		signer, parseErr := ssh.ParsePrivateKey(data)
		return signer, resolvedPath, false, parseErr
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, resolvedPath, false, err
	}

	if err := os.MkdirAll(filepath.Dir(resolvedPath), 0700); err != nil {
		return nil, resolvedPath, false, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, resolvedPath, false, err
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "ssh2tcp autogenerated host key")
	if err != nil {
		return nil, resolvedPath, false, err
	}
	data = pem.EncodeToMemory(block)
	if err := os.WriteFile(resolvedPath, data, 0600); err != nil {
		return nil, resolvedPath, false, err
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, resolvedPath, false, err
	}
	return signer, resolvedPath, true, nil
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
