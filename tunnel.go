package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type clientConfig struct {
	ListenAddress  string
	ServerAddress  string
	User           string
	SSHConfig      *ssh.ServerConfig
	ConnectTimeout time.Duration
}

type serverConfig struct {
	ListenAddress  string
	TargetAddress  string
	TargetUser     string
	SSHConfig      *ssh.ClientConfig
	ConnectTimeout time.Duration
}

func serveClient(cfg clientConfig) error {
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("client listening for SSH on %s; forwarding to plain server %s", listener.Addr(), cfg.ServerAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := handleInboundSSH(conn, cfg); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("client connection %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func serveServer(cfg serverConfig) error {
	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("server listening for plain clients on %s; forwarding to target SSH %s", listener.Addr(), cfg.TargetAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := handlePlainRelay(conn, cfg); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("server connection %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleInboundSSH(conn net.Conn, cfg clientConfig) error {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg.SSHConfig)
	if err != nil {
		return fmt.Errorf("ssh server handshake: %w", err)
	}
	defer sshConn.Close()

	plain, err := net.DialTimeout("tcp", cfg.ServerAddress, cfg.ConnectTimeout)
	if err != nil {
		return fmt.Errorf("connect plain server: %w", err)
	}
	defer plain.Close()

	log.Printf("accepted SSH %s as %q; plain relay %s", sshConn.RemoteAddr(), sshConn.User(), plain.RemoteAddr())
	return relaySSHConnection(sshConn, chans, reqs, plain, relayClientSide)
}

func handlePlainRelay(conn net.Conn, cfg serverConfig) error {
	defer conn.Close()

	target, err := net.DialTimeout("tcp", cfg.TargetAddress, cfg.ConnectTimeout)
	if err != nil {
		return fmt.Errorf("connect target SSH: %w", err)
	}
	defer target.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(target, cfg.TargetAddress, cfg.SSHConfig)
	if err != nil {
		return fmt.Errorf("ssh client handshake: %w", err)
	}
	defer sshConn.Close()

	log.Printf("accepted plain %s; target SSH %s", conn.RemoteAddr(), sshConn.RemoteAddr())
	return relaySSHConnection(sshConn, chans, reqs, conn, relayServerSide)
}

type relaySide int

const (
	relayClientSide relaySide = iota
	relayServerSide
)

func (s relaySide) firstChannelID() uint64 {
	if s == relayClientSide {
		return 1
	}
	return 2
}

type relay struct {
	sshConn ssh.Conn
	chans   <-chan ssh.NewChannel
	reqs    <-chan *ssh.Request
	stream  *frameStream

	nextMu     sync.Mutex
	nextChanID uint64
	nextReqID  uint64

	mu                  sync.Mutex
	channels            map[uint64]*proxiedChannel
	pendingChannelOpens map[uint64]chan channelOpenResult
	pendingGlobalReqs   map[uint64]chan globalRequestResult
	pendingChannelReqs  map[uint64]chan channelRequestResult

	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type proxiedChannel struct {
	id uint64
	ch ssh.Channel
}

func relaySSHConnection(sshConn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, plain net.Conn, side relaySide) error {
	r := &relay{
		sshConn:             sshConn,
		chans:               chans,
		reqs:                reqs,
		stream:              newFrameStream(plain),
		nextChanID:          side.firstChannelID(),
		nextReqID:           side.firstChannelID(),
		channels:            make(map[uint64]*proxiedChannel),
		pendingChannelOpens: make(map[uint64]chan channelOpenResult),
		pendingGlobalReqs:   make(map[uint64]chan globalRequestResult),
		pendingChannelReqs:  make(map[uint64]chan channelRequestResult),
		done:                make(chan struct{}),
	}

	if err := r.stream.writeHello(); err != nil {
		return err
	}
	if err := r.stream.readHello(); err != nil {
		return err
	}

	errCh := make(chan error, 3)
	r.wg.Add(3)
	go r.runFrameReader(errCh)
	go r.runLocalChannelReader(errCh)
	go r.runLocalGlobalRequestReader(errCh)

	err := <-errCh
	r.close()
	r.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (r *relay) runFrameReader(errCh chan<- error) {
	defer r.wg.Done()
	for {
		f, err := r.stream.readFrame()
		if err != nil {
			errCh <- err
			return
		}
		r.handleFrame(f)
	}
}

func (r *relay) runLocalChannelReader(errCh chan<- error) {
	defer r.wg.Done()
	for {
		select {
		case <-r.done:
			errCh <- nil
			return
		case ch, ok := <-r.chans:
			if !ok {
				errCh <- nil
				return
			}
			go r.handleLocalChannelOpen(ch)
		}
	}
}

func (r *relay) runLocalGlobalRequestReader(errCh chan<- error) {
	defer r.wg.Done()
	for {
		select {
		case <-r.done:
			errCh <- nil
			return
		case req, ok := <-r.reqs:
			if !ok {
				errCh <- nil
				return
			}
			go r.forwardLocalGlobalRequest(req)
		}
	}
}

func (r *relay) close() {
	r.closeOnce.Do(func() {
		close(r.done)
		_ = r.stream.Close()
		_ = r.sshConn.Close()
		r.mu.Lock()
		for _, ch := range r.pendingChannelOpens {
			close(ch)
		}
		for _, ch := range r.pendingGlobalReqs {
			close(ch)
		}
		for _, ch := range r.pendingChannelReqs {
			close(ch)
		}
		for _, pch := range r.channels {
			_ = pch.ch.Close()
		}
		r.mu.Unlock()
	})
}

func (r *relay) allocateChannelID() uint64 {
	r.nextMu.Lock()
	defer r.nextMu.Unlock()
	id := r.nextChanID
	r.nextChanID += 2
	return id
}

func (r *relay) allocateRequestID() uint64 {
	r.nextMu.Lock()
	defer r.nextMu.Unlock()
	id := r.nextReqID
	r.nextReqID += 2
	return id
}

func (r *relay) addChannel(id uint64, ch ssh.Channel) {
	r.mu.Lock()
	r.channels[id] = &proxiedChannel{id: id, ch: ch}
	r.mu.Unlock()
}

func (r *relay) removeChannel(id uint64) {
	r.mu.Lock()
	delete(r.channels, id)
	r.mu.Unlock()
}

func (r *relay) channel(id uint64) (ssh.Channel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pch, ok := r.channels[id]
	if !ok {
		return nil, false
	}
	return pch.ch, true
}

func (r *relay) handleFrame(f frame) {
	switch f := f.(type) {
	case globalRequestFrame:
		go r.handleRemoteGlobalRequest(f)
	case globalReplyFrame:
		r.completeGlobalRequest(f)
	case channelOpenFrame:
		go r.handleRemoteChannelOpen(f)
	case channelOpenResultFrame:
		r.completeChannelOpen(f)
	case channelDataFrame:
		r.writeChannelData(f.channelID, f.data, false)
	case channelExtendedDataFrame:
		r.writeChannelData(f.channelID, f.data, true)
	case channelRequestFrame:
		go r.handleRemoteChannelRequest(f)
	case channelRequestResultFrame:
		r.completeChannelRequest(f)
	case channelEOFFrame:
		r.closeChannelWrite(f.channelID)
	case channelCloseFrame:
		r.closeChannel(f.channelID)
	}
}

func (r *relay) handleLocalChannelOpen(newChannel ssh.NewChannel) {
	id := r.allocateChannelID()
	resultCh := make(chan channelOpenResult, 1)

	r.mu.Lock()
	r.pendingChannelOpens[id] = resultCh
	r.mu.Unlock()

	err := r.stream.writeFrame(channelOpenFrame{
		channelID:   id,
		channelType: newChannel.ChannelType(),
		extraData:   newChannel.ExtraData(),
	})
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		r.dropPendingChannelOpen(id)
		return
	}

	result, ok := waitChannelOpenResult(r.done, resultCh)
	r.dropPendingChannelOpen(id)
	if !ok {
		newChannel.Reject(ssh.ConnectionFailed, "relay closed")
		return
	}
	if !result.ok {
		newChannel.Reject(result.reason, result.message)
		return
	}

	ch, reqs, err := newChannel.Accept()
	if err != nil {
		_ = r.stream.writeFrame(channelCloseFrame{channelID: id})
		return
	}
	r.addChannel(id, ch)
	r.startChannelPumps(id, ch, reqs)
}

func waitChannelOpenResult(done <-chan struct{}, resultCh <-chan channelOpenResult) (channelOpenResult, bool) {
	select {
	case <-done:
		return channelOpenResult{}, false
	case result, ok := <-resultCh:
		return result, ok
	}
}

func (r *relay) dropPendingChannelOpen(id uint64) {
	r.mu.Lock()
	delete(r.pendingChannelOpens, id)
	r.mu.Unlock()
}

func (r *relay) handleRemoteChannelOpen(f channelOpenFrame) {
	ch, reqs, err := r.sshConn.OpenChannel(f.channelType, f.extraData)
	if err != nil {
		reason := ssh.ConnectionFailed
		message := err.Error()
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			reason = openErr.Reason
			message = openErr.Message
		}
		_ = r.stream.writeFrame(channelOpenResultFrame{
			channelID: f.channelID,
			ok:        false,
			reason:    reason,
			message:   message,
		})
		return
	}

	r.addChannel(f.channelID, ch)
	if err := r.stream.writeFrame(channelOpenResultFrame{channelID: f.channelID, ok: true}); err != nil {
		_ = ch.Close()
		r.removeChannel(f.channelID)
		return
	}
	r.startChannelPumps(f.channelID, ch, reqs)
}

func (r *relay) completeChannelOpen(f channelOpenResultFrame) {
	r.mu.Lock()
	ch := r.pendingChannelOpens[f.channelID]
	r.mu.Unlock()
	if ch == nil {
		return
	}
	ch <- channelOpenResult{
		ok:      f.ok,
		reason:  f.reason,
		message: f.message,
	}
}

func (r *relay) startChannelPumps(id uint64, ch ssh.Channel, reqs <-chan *ssh.Request) {
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		r.forwardChannelData(id, ch, false)
	}()
	go func() {
		defer wg.Done()
		r.forwardChannelData(id, ch.Stderr(), true)
	}()
	go func() {
		defer wg.Done()
		r.forwardChannelRequests(id, reqs)
	}()
	go func() {
		wg.Wait()
		r.removeChannel(id)
		_ = r.stream.writeFrame(channelCloseFrame{channelID: id})
	}()
}

func (r *relay) forwardChannelData(id uint64, reader interface {
	Read([]byte) (int, error)
}, extended bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			data := append([]byte(nil), buf[:n]...)
			var writeErr error
			if extended {
				writeErr = r.stream.writeFrame(channelExtendedDataFrame{channelID: id, data: data})
			} else {
				writeErr = r.stream.writeFrame(channelDataFrame{channelID: id, data: data})
			}
			if writeErr != nil {
				r.close()
				return
			}
		}
		if err != nil {
			if !extended {
				_ = r.stream.writeFrame(channelEOFFrame{channelID: id})
			}
			return
		}
	}
}

func (r *relay) forwardChannelRequests(id uint64, reqs <-chan *ssh.Request) {
	for req := range reqs {
		requestID := uint64(0)
		var resultCh chan channelRequestResult
		if req.WantReply {
			requestID = r.allocateRequestID()
			resultCh = make(chan channelRequestResult, 1)
			r.mu.Lock()
			r.pendingChannelReqs[requestID] = resultCh
			r.mu.Unlock()
		}

		err := r.stream.writeFrame(channelRequestFrame{
			requestID: requestID,
			channelID: id,
			name:      req.Type,
			wantReply: req.WantReply,
			payload:   req.Payload,
		})
		if err != nil {
			if req.WantReply {
				req.Reply(false, nil)
				r.dropPendingChannelRequest(requestID)
			}
			r.close()
			return
		}

		if req.WantReply {
			result, ok := waitChannelRequestResult(r.done, resultCh)
			r.dropPendingChannelRequest(requestID)
			req.Reply(ok && result.ok, nil)
		}
	}
}

func waitChannelRequestResult(done <-chan struct{}, resultCh <-chan channelRequestResult) (channelRequestResult, bool) {
	select {
	case <-done:
		return channelRequestResult{}, false
	case result, ok := <-resultCh:
		return result, ok
	}
}

func (r *relay) dropPendingChannelRequest(id uint64) {
	r.mu.Lock()
	delete(r.pendingChannelReqs, id)
	r.mu.Unlock()
}

func (r *relay) writeChannelData(id uint64, data []byte, extended bool) {
	ch, ok := r.channel(id)
	if !ok {
		return
	}
	var err error
	if extended {
		_, err = ch.Stderr().Write(data)
	} else {
		_, err = ch.Write(data)
	}
	if err != nil {
		r.closeChannel(id)
	}
}

func (r *relay) closeChannelWrite(id uint64) {
	ch, ok := r.channel(id)
	if !ok {
		return
	}
	_ = ch.CloseWrite()
}

func (r *relay) closeChannel(id uint64) {
	ch, ok := r.channel(id)
	if !ok {
		return
	}
	_ = ch.Close()
	r.removeChannel(id)
}

func (r *relay) handleRemoteChannelRequest(f channelRequestFrame) {
	ch, ok := r.channel(f.channelID)
	var accepted bool
	if ok {
		var err error
		accepted, err = ch.SendRequest(f.name, f.wantReply, f.payload)
		if err != nil {
			accepted = false
		}
	}
	if f.wantReply {
		_ = r.stream.writeFrame(channelRequestResultFrame{requestID: f.requestID, ok: accepted})
	}
}

func (r *relay) completeChannelRequest(f channelRequestResultFrame) {
	r.mu.Lock()
	ch := r.pendingChannelReqs[f.requestID]
	r.mu.Unlock()
	if ch == nil {
		return
	}
	ch <- channelRequestResult{ok: f.ok}
}

func (r *relay) forwardLocalGlobalRequest(req *ssh.Request) {
	requestID := uint64(0)
	var resultCh chan globalRequestResult
	if req.WantReply {
		requestID = r.allocateRequestID()
		resultCh = make(chan globalRequestResult, 1)
		r.mu.Lock()
		r.pendingGlobalReqs[requestID] = resultCh
		r.mu.Unlock()
	}

	err := r.stream.writeFrame(globalRequestFrame{
		requestID: requestID,
		name:      req.Type,
		wantReply: req.WantReply,
		payload:   req.Payload,
	})
	if err != nil {
		if req.WantReply {
			req.Reply(false, nil)
			r.dropPendingGlobalRequest(requestID)
		}
		r.close()
		return
	}

	if req.WantReply {
		result, ok := waitGlobalRequestResult(r.done, resultCh)
		r.dropPendingGlobalRequest(requestID)
		req.Reply(ok && result.ok, result.payload)
	}
}

func waitGlobalRequestResult(done <-chan struct{}, resultCh <-chan globalRequestResult) (globalRequestResult, bool) {
	select {
	case <-done:
		return globalRequestResult{}, false
	case result, ok := <-resultCh:
		return result, ok
	}
}

func (r *relay) dropPendingGlobalRequest(id uint64) {
	r.mu.Lock()
	delete(r.pendingGlobalReqs, id)
	r.mu.Unlock()
}

func (r *relay) handleRemoteGlobalRequest(f globalRequestFrame) {
	ok, payload, err := r.sshConn.SendRequest(f.name, f.wantReply, f.payload)
	if err != nil {
		ok = false
		payload = nil
	}
	if f.wantReply {
		_ = r.stream.writeFrame(globalReplyFrame{
			requestID: f.requestID,
			ok:        ok,
			payload:   payload,
		})
	}
}

func (r *relay) completeGlobalRequest(f globalReplyFrame) {
	r.mu.Lock()
	ch := r.pendingGlobalReqs[f.requestID]
	r.mu.Unlock()
	if ch == nil {
		return
	}
	ch <- globalRequestResult{ok: f.ok, payload: f.payload}
}

type channelOpenResult struct {
	ok      bool
	reason  ssh.RejectionReason
	message string
}

type globalRequestResult struct {
	ok      bool
	payload []byte
}

type channelRequestResult struct {
	ok bool
}
