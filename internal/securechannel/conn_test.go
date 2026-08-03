package securechannel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type shortWriter struct {
	buffer bytes.Buffer
	limit  int
}

func (w *shortWriter) Write(data []byte) (int, error) {
	if len(data) > w.limit {
		data = data[:w.limit]
	}
	return w.buffer.Write(data)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{limit: 1}
	message := []byte("encrypted-record")
	if err := writeFrame(writer, message); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	encoded := writer.buffer.Bytes()
	if len(encoded) != len(message)+2 {
		t.Fatalf("encoded length = %d, want %d", len(encoded), len(message)+2)
	}
	if size := binary.BigEndian.Uint16(encoded[:2]); int(size) != len(message) {
		t.Fatalf("encoded size = %d, want %d", size, len(message))
	}
	if !bytes.Equal(encoded[2:], message) {
		t.Fatalf("encoded payload = %q, want %q", encoded[2:], message)
	}
}

func TestWriteFrameRejectsNoProgress(t *testing.T) {
	if err := writeFrame(zeroWriter{}, []byte("record")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write frame error = %v, want io.ErrShortWrite", err)
	}
}
