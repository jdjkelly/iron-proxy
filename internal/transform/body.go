package transform

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

// ErrBodyTooLarge is returned by Buffer when the body exceeds maxBytes.
var ErrBodyTooLarge = errors.New("body exceeds max buffer size")

// ReplayableBody wraps an io.ReadCloser with opt-in buffering and rewind support.
// By default, Read() streams from the underlying reader with no buffering.
// Call Buffer() to materialize the body into memory for inspection/rewind.
type ReplayableBody struct {
	mu       sync.Mutex
	original io.ReadCloser
	buf      *bytes.Reader // set after Buffer() is called
	maxBytes int64         // largest maxBytes seen
	buffered bool
}

// NewReplayableBody wraps an existing body for use in the transform pipeline.
func NewReplayableBody(body io.ReadCloser) *ReplayableBody {
	if body == nil {
		body = io.NopCloser(bytes.NewReader(nil))
	}
	return &ReplayableBody{original: body}
}

// Buffer reads the entire body into memory up to maxBytes.
// Returns ErrBodyTooLarge if the body exceeds maxBytes.
// After Buffer(), the body supports Seek(0) to rewind.
// Idempotent: subsequent calls are no-ops (largest maxBytes wins).
func (b *ReplayableBody) Buffer(maxBytes int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.buffered && maxBytes <= b.maxBytes {
		return nil // already buffered with sufficient limit
	}

	if b.buffered {
		// Already buffered but caller wants a larger limit.
		// Body is already fully read, so just update the limit.
		if int64(b.buf.Len()) > maxBytes {
			return ErrBodyTooLarge
		}
		b.maxBytes = maxBytes
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(b.original, maxBytes+1))
	if err != nil {
		return err
	}

	if int64(len(data)) > maxBytes {
		return ErrBodyTooLarge
	}

	b.original.Close()
	b.buf = bytes.NewReader(data)
	b.buffered = true
	b.maxBytes = maxBytes

	return nil
}

// Read implements io.Reader. Streams from the original reader if unbuffered,
// or from the in-memory buffer if buffered.
func (b *ReplayableBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.buffered {
		return b.buf.Read(p)
	}
	return b.original.Read(p)
}

// Seek implements io.Seeker. Only works after Buffer() has been called.
// Only offset=0, whence=io.SeekStart is supported (rewind).
func (b *ReplayableBody) Seek(offset int64, whence int) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.buffered {
		return 0, errors.New("cannot seek unbuffered body")
	}
	return b.buf.Seek(offset, whence)
}

// Close closes the underlying reader.
func (b *ReplayableBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.buffered {
		return nil
	}
	return b.original.Close()
}
