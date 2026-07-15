package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

const usageText = `ssh2tcp exposes an SSH connection layer over a plain TCP hop.

Usage:
  ssh2tcp client [flags]
  ssh2tcp server [flags]

client:
  Listens as an SSH server, authenticates inbound SSH clients, then connects to a
  plain ssh2tcp server endpoint.

server:
  Listens for plain ssh2tcp client endpoints, then connects and authenticates to
  the configured target SSH server.
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "client":
		err = runClientCommand(os.Args[2:])
	case "server":
		err = runServerCommand(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usageText)
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func runClientCommand(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cfg clientConfig
	var password, authorizedKeys, hostKey string
	fs.StringVar(&cfg.ListenAddress, "listen", ":2222", "SSH listen address")
	fs.StringVar(&cfg.ServerAddress, "server", "", "plain ssh2tcp server address")
	fs.StringVar(&cfg.User, "user", "", "required inbound SSH username; empty accepts any user")
	fs.StringVar(&password, "password", "", "inbound SSH password")
	fs.StringVar(&authorizedKeys, "authorized-keys", "", "OpenSSH authorized_keys file for inbound public key auth")
	fs.StringVar(&hostKey, "host-key", "", "private host key for the inbound SSH server")
	fs.DurationVar(&cfg.ConnectTimeout, "connect-timeout", 10*time.Second, "timeout for connecting to the plain ssh2tcp server")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.ServerAddress == "" {
		return errors.New("client requires -server")
	}
	if hostKey == "" {
		return errors.New("client requires -host-key")
	}

	sshConfig, err := buildInboundSSHServerConfig(cfg.User, password, authorizedKeys, hostKey)
	if err != nil {
		return err
	}
	cfg.SSHConfig = sshConfig
	return serveClient(cfg)
}

func runServerCommand(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cfg serverConfig
	var password, keyPath, knownHosts, hostKeyFingerprint string
	var insecureHostKey bool
	fs.StringVar(&cfg.ListenAddress, "listen", ":9000", "plain ssh2tcp listen address")
	fs.StringVar(&cfg.TargetAddress, "ssh-target", "", "target SSH server address")
	fs.StringVar(&cfg.TargetUser, "ssh-user", "", "target SSH username")
	fs.StringVar(&password, "password", "", "password for the target SSH server")
	fs.StringVar(&keyPath, "key", "", "private key for the target SSH server")
	fs.StringVar(&knownHosts, "known-hosts", "", "known_hosts file for target host key verification")
	fs.StringVar(&hostKeyFingerprint, "host-key-fingerprint", "", "trusted target SSH host key fingerprint, for example SHA256:...")
	fs.BoolVar(&insecureHostKey, "insecure-skip-host-key-check", false, "disable target SSH host key verification")
	fs.DurationVar(&cfg.ConnectTimeout, "connect-timeout", 10*time.Second, "timeout for connecting to the target SSH server")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.TargetAddress == "" {
		return errors.New("server requires -ssh-target")
	}
	if cfg.TargetUser == "" {
		return errors.New("server requires -ssh-user")
	}

	sshConfig, err := buildOutboundSSHClientConfig(cfg.TargetUser, password, keyPath, knownHosts, hostKeyFingerprint, insecureHostKey, cfg.ConnectTimeout)
	if err != nil {
		return err
	}
	cfg.SSHConfig = sshConfig
	return serveServer(cfg)
}
