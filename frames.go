package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	frameHello = "ssh2tcp-conn-layer-v1\n"
	maxFrame   = 64 * 1024 * 1024
)

const (
	frameTypeGlobalRequest byte = iota + 1
	frameTypeGlobalReply
	frameTypeChannelOpen
	frameTypeChannelOpenResult
	frameTypeChannelData
	frameTypeChannelExtendedData
	frameTypeChannelRequest
	frameTypeChannelRequestResult
	frameTypeChannelEOF
	frameTypeChannelClose
)

type frame interface {
	frameType() byte
	encode(*bytes.Buffer)
}

type frameStream struct {
	conn    net.Conn
	writeMu sync.Mutex
}

func newFrameStream(conn net.Conn) *frameStream {
	return &frameStream{conn: conn}
}

func (s *frameStream) Close() error {
	return s.conn.Close()
}

func (s *frameStream) writeHello() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.conn.Write([]byte(frameHello))
	return err
}

func (s *frameStream) readHello() error {
	buf := make([]byte, len(frameHello))
	if _, err := io.ReadFull(s.conn, buf); err != nil {
		return err
	}
	if string(buf) != frameHello {
		return fmt.Errorf("unexpected relay protocol hello %q", string(buf))
	}
	return nil
}

func (s *frameStream) writeFrame(f frame) error {
	var payload bytes.Buffer
	payload.WriteByte(f.frameType())
	f.encode(&payload)

	if payload.Len() > maxFrame {
		return fmt.Errorf("frame too large: %d", payload.Len())
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(payload.Len()))

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(header[:]); err != nil {
		return err
	}
	_, err := s.conn.Write(payload.Bytes())
	return err
}

func (s *frameStream) readFrame() (frame, error) {
	var header [4]byte
	if _, err := io.ReadFull(s.conn, header[:]); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxFrame {
		return nil, fmt.Errorf("invalid frame size %d", size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(s.conn, payload); err != nil {
		return nil, err
	}

	reader := bytes.NewReader(payload)
	frameType, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	f, err := decodeFrame(frameType, reader)
	if err != nil {
		return nil, err
	}
	return f, nil
}

type globalRequestFrame struct {
	requestID uint64
	name      string
	wantReply bool
	payload   []byte
}

func (globalRequestFrame) frameType() byte { return frameTypeGlobalRequest }
func (f globalRequestFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.requestID)
	writeString(buf, f.name)
	writeBool(buf, f.wantReply)
	writeBytes(buf, f.payload)
}

type globalReplyFrame struct {
	requestID uint64
	ok        bool
	payload   []byte
}

func (globalReplyFrame) frameType() byte { return frameTypeGlobalReply }
func (f globalReplyFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.requestID)
	writeBool(buf, f.ok)
	writeBytes(buf, f.payload)
}

type channelOpenFrame struct {
	channelID   uint64
	channelType string
	extraData   []byte
}

func (channelOpenFrame) frameType() byte { return frameTypeChannelOpen }
func (f channelOpenFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.channelID)
	writeString(buf, f.channelType)
	writeBytes(buf, f.extraData)
}

type channelOpenResultFrame struct {
	channelID uint64
	ok        bool
	reason    ssh.RejectionReason
	message   string
}

func (channelOpenResultFrame) frameType() byte { return frameTypeChannelOpenResult }
func (f channelOpenResultFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.channelID)
	writeBool(buf, f.ok)
	writeUint32(buf, uint32(f.reason))
	writeString(buf, f.message)
}

type channelDataFrame struct {
	channelID uint64
	data      []byte
}

func (channelDataFrame) frameType() byte { return frameTypeChannelData }
func (f channelDataFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.channelID)
	writeBytes(buf, f.data)
}

type channelExtendedDataFrame struct {
	channelID uint64
	data      []byte
}

func (channelExtendedDataFrame) frameType() byte { return frameTypeChannelExtendedData }
func (f channelExtendedDataFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.channelID)
	writeBytes(buf, f.data)
}

type channelRequestFrame struct {
	requestID uint64
	channelID uint64
	name      string
	wantReply bool
	payload   []byte
}

func (channelRequestFrame) frameType() byte { return frameTypeChannelRequest }
func (f channelRequestFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.requestID)
	writeUint64(buf, f.channelID)
	writeString(buf, f.name)
	writeBool(buf, f.wantReply)
	writeBytes(buf, f.payload)
}

type channelRequestResultFrame struct {
	requestID uint64
	ok        bool
}

func (channelRequestResultFrame) frameType() byte { return frameTypeChannelRequestResult }
func (f channelRequestResultFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.requestID)
	writeBool(buf, f.ok)
}

type channelEOFFrame struct {
	channelID uint64
}

func (channelEOFFrame) frameType() byte { return frameTypeChannelEOF }
func (f channelEOFFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.channelID)
}

type channelCloseFrame struct {
	channelID uint64
}

func (channelCloseFrame) frameType() byte { return frameTypeChannelClose }
func (f channelCloseFrame) encode(buf *bytes.Buffer) {
	writeUint64(buf, f.channelID)
}

func decodeFrame(frameType byte, r *bytes.Reader) (frame, error) {
	fr := &frameReader{r: r}
	var f frame
	switch frameType {
	case frameTypeGlobalRequest:
		f = globalRequestFrame{
			requestID: fr.uint64(),
			name:      fr.string(),
			wantReply: fr.bool(),
			payload:   fr.bytes(),
		}
	case frameTypeGlobalReply:
		f = globalReplyFrame{
			requestID: fr.uint64(),
			ok:        fr.bool(),
			payload:   fr.bytes(),
		}
	case frameTypeChannelOpen:
		f = channelOpenFrame{
			channelID:   fr.uint64(),
			channelType: fr.string(),
			extraData:   fr.bytes(),
		}
	case frameTypeChannelOpenResult:
		f = channelOpenResultFrame{
			channelID: fr.uint64(),
			ok:        fr.bool(),
			reason:    ssh.RejectionReason(fr.uint32()),
			message:   fr.string(),
		}
	case frameTypeChannelData:
		f = channelDataFrame{channelID: fr.uint64(), data: fr.bytes()}
	case frameTypeChannelExtendedData:
		f = channelExtendedDataFrame{channelID: fr.uint64(), data: fr.bytes()}
	case frameTypeChannelRequest:
		f = channelRequestFrame{
			requestID: fr.uint64(),
			channelID: fr.uint64(),
			name:      fr.string(),
			wantReply: fr.bool(),
			payload:   fr.bytes(),
		}
	case frameTypeChannelRequestResult:
		f = channelRequestResultFrame{requestID: fr.uint64(), ok: fr.bool()}
	case frameTypeChannelEOF:
		f = channelEOFFrame{channelID: fr.uint64()}
	case frameTypeChannelClose:
		f = channelCloseFrame{channelID: fr.uint64()}
	default:
		return nil, fmt.Errorf("unknown frame type %d", frameType)
	}
	if err := fr.done(); err != nil {
		return nil, err
	}
	return f, nil
}

func writeUint64(buf *bytes.Buffer, v uint64) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	buf.Write(tmp[:])
}

func writeUint32(buf *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	buf.Write(tmp[:])
}

func writeBool(buf *bytes.Buffer, v bool) {
	if v {
		buf.WriteByte(1)
		return
	}
	buf.WriteByte(0)
}

func writeString(buf *bytes.Buffer, v string) {
	writeBytes(buf, []byte(v))
}

func writeBytes(buf *bytes.Buffer, v []byte) {
	writeUint32(buf, uint32(len(v)))
	buf.Write(v)
}

type frameReader struct {
	r   *bytes.Reader
	err error
}

func (fr *frameReader) uint64() uint64 {
	if fr.err != nil {
		return 0
	}
	var tmp [8]byte
	if _, err := io.ReadFull(fr.r, tmp[:]); err != nil {
		fr.err = err
		return 0
	}
	return binary.BigEndian.Uint64(tmp[:])
}

func (fr *frameReader) uint32() uint32 {
	if fr.err != nil {
		return 0
	}
	var tmp [4]byte
	if _, err := io.ReadFull(fr.r, tmp[:]); err != nil {
		fr.err = err
		return 0
	}
	return binary.BigEndian.Uint32(tmp[:])
}

func (fr *frameReader) bool() bool {
	if fr.err != nil {
		return false
	}
	v, err := fr.r.ReadByte()
	if err != nil {
		fr.err = err
		return false
	}
	return v != 0
}

func (fr *frameReader) string() string {
	return string(fr.bytes())
}

func (fr *frameReader) bytes() []byte {
	size := fr.uint32()
	if fr.err != nil {
		return nil
	}
	if uint64(size) > uint64(fr.r.Len()) {
		fr.err = io.ErrUnexpectedEOF
		_, _ = fr.r.Seek(0, io.SeekEnd)
		return nil
	}

	out := make([]byte, size)
	if _, err := io.ReadFull(fr.r, out); err != nil {
		fr.err = err
		return nil
	}
	return out
}

func (fr *frameReader) done() error {
	if fr.err != nil {
		return fr.err
	}
	if fr.r.Len() != 0 {
		return errors.New("trailing frame data")
	}
	return nil
}
