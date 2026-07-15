# ssh2tcp (by GPT-5.5 xhigh)

`ssh2tcp` splits an SSH connection into two encrypted SSH legs with one plain TCP
hop in the middle. The middle hop carries plaintext SSH connection-layer events:
global requests, channel opens, channel data, extended data, channel requests,
EOF, and close.

This is not a one-channel byte pipe. A single inbound SSH connection can use many
SSH channels, including `session`, `direct-tcpip`, `forwarded-tcpip`, and custom
channel types that Go's SSH package can represent.

## Topology

```text
ssh client
  -> ssh2tcp client  (SSH server, authenticates inbound user)
  -> plain TCP hop   (ssh2tcp frame protocol, no encryption/auth)
  -> ssh2tcp server  (SSH client, authenticates to target)
  -> target SSH server
```

## Build

```powershell
go build ./...
```

## Run

Start the server side near the target SSH server:

```powershell
ssh2tcp server `
  -listen :9000 `
  -ssh-target 127.0.0.1:22 `
  -ssh-user target-user `
  -key C:\Users\you\.ssh\id_ed25519 `
  -known-hosts C:\Users\you\.ssh\known_hosts
```

Start the client side where users connect:

```powershell
ssh2tcp client `
  -listen :2222 `
  -server 127.0.0.1:9000 `
  -user tunnel-user `
  -password tunnel-password `
  -host-key C:\path\to\ssh2tcp_host_key
```

Then connect through it:

```powershell
ssh -p 2222 tunnel-user@127.0.0.1
```

## Notes

The plain TCP hop intentionally has no encryption or authentication. Put it only
on a trusted network or wrap it in a transport you trust.

Go's `golang.org/x/crypto/ssh` package does not expose decrypted raw SSH packet
bytes. This implementation therefore forwards the SSH connection layer
semantically instead of promising byte-for-byte SSH transport packet preservation.
That is the layer where SSH multiplexed channels and global requests live.

