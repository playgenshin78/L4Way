package securechannel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/flynn/noise"
)

const (
	maxCiphertextSize = noise.MaxMsgLen
	maxPlaintextSize  = maxCiphertextSize - 16
	rekeyRecordCount  = uint64(1 << 20)
)

type encryptedConn struct {
	net.Conn
	send *noise.CipherState
	recv *noise.CipherState

	writeMu    sync.Mutex
	readMu     sync.Mutex
	readBuffer []byte
	sent       uint64
	received   uint64
}

func newEncryptedConn(raw net.Conn, send, receive *noise.CipherState) (net.Conn, error) {
	if raw == nil || send == nil || receive == nil {
		return nil, errors.New("encrypted connection requires a socket and two cipher states")
	}
	return &encryptedConn{Conn: raw, send: send, recv: receive}, nil
}

func (c *encryptedConn) Write(plaintext []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(plaintext) != 0 {
		chunkSize := len(plaintext)
		if chunkSize > maxPlaintextSize {
			chunkSize = maxPlaintextSize
		}
		ciphertext, err := c.send.Encrypt(nil, nil, plaintext[:chunkSize])
		if err != nil {
			return written, err
		}
		if err := writeFrame(c.Conn, ciphertext); err != nil {
			return written, err
		}
		c.sent++
		if c.sent%rekeyRecordCount == 0 {
			c.send.Rekey()
		}
		written += chunkSize
		plaintext = plaintext[chunkSize:]
	}
	return written, nil
}

func (c *encryptedConn) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readBuffer) == 0 {
		ciphertext, err := readFrame(c.Conn)
		if err != nil {
			return 0, err
		}
		plaintext, err := c.recv.Decrypt(nil, nil, ciphertext)
		if err != nil {
			return 0, errors.New("AES-GCM record authentication failed")
		}
		c.received++
		if c.received%rekeyRecordCount == 0 {
			c.recv.Rekey()
		}
		c.readBuffer = plaintext
	}
	copied := copy(destination, c.readBuffer)
	c.readBuffer = c.readBuffer[copied:]
	return copied, nil
}

func writeFrame(writer io.Writer, message []byte) error {
	if len(message) == 0 || len(message) > maxCiphertextSize {
		return errors.New("Noise frame size is invalid")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(message)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, message)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func readFrame(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 || size > maxCiphertextSize {
		return nil, errors.New("Noise frame size is invalid")
	}
	message := make([]byte, size)
	if _, err := io.ReadFull(reader, message); err != nil {
		return nil, err
	}
	return message, nil
}
