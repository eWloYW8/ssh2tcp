package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRelaySupportsMultipleChannelsWithPasswordAuth(t *testing.T) {
	runRelayEndToEnd(t, false, 0)
}

func TestRelaySupportsMultipleChannelsWithPublicKeyAuth(t *testing.T) {
	runRelayEndToEnd(t, true, 0)
}

func TestRelaySupportsMultipleChannelsWithXOR(t *testing.T) {
	runRelayEndToEnd(t, false, 63)
}

func TestHostKeyCallbackAcceptsTrustedFingerprint(t *testing.T) {
	signer := testSigner(t)
	callback, err := buildHostKeyCallback("", ssh.FingerprintSHA256(signer.PublicKey()), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("target", nil, signer.PublicKey()); err != nil {
		t.Fatalf("trusted fingerprint rejected: %v", err)
	}
}

func TestHostKeyCallbackRejectsWrongFingerprint(t *testing.T) {
	signer := testSigner(t)
	wrongSigner := testSigner(t)
	callback, err := buildHostKeyCallback("", ssh.FingerprintSHA256(wrongSigner.PublicKey()), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("target", nil, signer.PublicKey()); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
}

func TestLoadInboundHostKeyCreatesAndReusesDefaultKey(t *testing.T) {
	oldUserHomeDir := userHomeDir
	t.Cleanup(func() { userHomeDir = oldUserHomeDir })
	home := t.TempDir()
	userHomeDir = func() (string, error) {
		return home, nil
	}

	firstSigner, path, created, err := loadInboundHostKey("")
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("default host key was not created")
	}
	if path != filepath.Join(home, defaultHostKeyPath) {
		t.Fatalf("host key path = %q, want %q", path, filepath.Join(home, defaultHostKeyPath))
	}

	secondSigner, secondPath, created, err := loadInboundHostKey("")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing default host key was recreated")
	}
	if secondPath != path {
		t.Fatalf("second host key path = %q, want %q", secondPath, path)
	}
	if !bytes.Equal(firstSigner.PublicKey().Marshal(), secondSigner.PublicKey().Marshal()) {
		t.Fatal("reloaded host key does not match generated key")
	}
}

func runRelayEndToEnd(t *testing.T, usePublicKey bool, xorKey byte) {
	t.Helper()

	targetSigner := testSigner(t)
	clientHostSigner := testSigner(t)
	userSigner := testSigner(t)

	targetServerConfig := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "target" && string(password) == "target-pass" {
				return nil, nil
			}
			return nil, errors.New("bad target password")
		},
	}
	targetServerConfig.AddHostKey(targetSigner)
	targetListener := listenTCP(t)
	var targetWG sync.WaitGroup
	targetWG.Add(1)
	go serveTestTargetSSH(t, targetListener, targetServerConfig, &targetWG)

	plainListener := listenTCP(t)
	targetClientConfig := &ssh.ClientConfig{
		User:            "target",
		Auth:            []ssh.AuthMethod{ssh.Password("target-pass")},
		HostKeyCallback: ssh.FixedHostKey(targetSigner.PublicKey()),
		Timeout:         5 * time.Second,
	}
	serverCfg := serverConfig{
		ListenAddress:  plainListener.Addr().String(),
		TargetAddress:  targetListener.Addr().String(),
		TargetUser:     "target",
		SSHConfig:      targetClientConfig,
		XORKey:         xorKey,
		ConnectTimeout: 5 * time.Second,
	}
	var plainWG sync.WaitGroup
	plainWG.Add(1)
	go serveOnePlainRelay(t, plainListener, serverCfg, &plainWG)

	inboundServerConfig := &ssh.ServerConfig{}
	if usePublicKey {
		inboundServerConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "inbound" && bytes.Equal(key.Marshal(), userSigner.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("bad inbound key")
		}
	} else {
		inboundServerConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "inbound" && string(password) == "inbound-pass" {
				return nil, nil
			}
			return nil, errors.New("bad inbound password")
		}
	}
	inboundServerConfig.AddHostKey(clientHostSigner)

	inboundListener := listenTCP(t)
	clientCfg := clientConfig{
		ListenAddress:  inboundListener.Addr().String(),
		ServerAddress:  plainListener.Addr().String(),
		User:           "inbound",
		SSHConfig:      inboundServerConfig,
		XORKey:         xorKey,
		ConnectTimeout: 5 * time.Second,
	}
	var inboundWG sync.WaitGroup
	inboundWG.Add(1)
	go serveOneInboundSSH(t, inboundListener, clientCfg, &inboundWG)

	auth := []ssh.AuthMethod{ssh.Password("inbound-pass")}
	if usePublicKey {
		auth = []ssh.AuthMethod{ssh.PublicKeys(userSigner)}
	}
	clientConfig := &ssh.ClientConfig{
		User:            "inbound",
		Auth:            auth,
		HostKeyCallback: ssh.FixedHostKey(clientHostSigner.PublicKey()),
		Timeout:         5 * time.Second,
	}
	conn, err := net.DialTimeout("tcp", inboundListener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, inboundListener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	go ssh.DiscardRequests(reqs)
	go rejectUnexpectedChannels(chans)

	const channelCount = 3
	var wg sync.WaitGroup
	for i := 0; i < channelCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ch, reqs, err := clientConn.OpenChannel("session", []byte{byte(i)})
			if err != nil {
				t.Errorf("open channel %d: %v", i, err)
				return
			}
			defer ch.Close()
			go ssh.DiscardRequests(reqs)

			input := []byte{byte('a' + i), byte('A' + i), byte(i)}
			if _, err := ch.Write(input); err != nil {
				t.Errorf("write channel %d: %v", i, err)
				return
			}
			if err := ch.CloseWrite(); err != nil {
				t.Errorf("close write channel %d: %v", i, err)
				return
			}

			got, err := io.ReadAll(ch)
			if err != nil {
				t.Errorf("read channel %d: %v", i, err)
				return
			}
			want := append([]byte("echo:"), input...)
			if !bytes.Equal(got, want) {
				t.Errorf("channel %d got %q, want %q", i, got, want)
			}
		}(i)
	}
	wg.Wait()

	clientConn.Close()
	inboundWG.Wait()
	plainWG.Wait()
	targetWG.Wait()
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func serveOneInboundSSH(t *testing.T, listener net.Listener, cfg clientConfig, wg *sync.WaitGroup) {
	t.Helper()
	defer wg.Done()
	conn, err := listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return
		}
		t.Errorf("accept inbound ssh: %v", err)
		return
	}
	if err := handleInboundSSH(conn, cfg); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Errorf("handle inbound ssh: %v", err)
	}
}

func serveOnePlainRelay(t *testing.T, listener net.Listener, cfg serverConfig, wg *sync.WaitGroup) {
	t.Helper()
	defer wg.Done()
	conn, err := listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return
		}
		t.Errorf("accept plain relay: %v", err)
		return
	}
	if err := handlePlainRelay(conn, cfg); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Errorf("handle plain relay: %v", err)
	}
}

func serveTestTargetSSH(t *testing.T, listener net.Listener, cfg *ssh.ServerConfig, wg *sync.WaitGroup) {
	t.Helper()
	defer wg.Done()
	conn, err := listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return
		}
		t.Errorf("accept target ssh: %v", err)
		return
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		t.Errorf("target ssh handshake: %v", err)
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	var channelWG sync.WaitGroup
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "only test session channels are supported")
			continue
		}
		accepted, reqs, err := ch.Accept()
		if err != nil {
			t.Errorf("target accept channel: %v", err)
			continue
		}
		go ssh.DiscardRequests(reqs)
		channelWG.Add(1)
		go func(channel ssh.Channel) {
			defer channelWG.Done()
			defer channel.Close()
			data, err := io.ReadAll(channel)
			if err != nil {
				t.Errorf("target read channel: %v", err)
				return
			}
			_, _ = channel.Write(append([]byte("echo:"), data...))
			_ = channel.CloseWrite()
		}(accepted)
	}
	channelWG.Wait()
}

func rejectUnexpectedChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		ch.Reject(ssh.UnknownChannelType, "unexpected channel")
	}
}
