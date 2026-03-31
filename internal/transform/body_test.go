package transform

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplayableBody_StreamWithoutBuffer(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")))

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestReplayableBody_BufferAndRewind(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")))

	require.NoError(t, body.Buffer(1024))

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))

	// Rewind and read again
	_, err = body.Seek(0, io.SeekStart)
	require.NoError(t, err)

	data, err = io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestReplayableBody_BufferTooLarge(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello world")))

	err := body.Buffer(5)
	require.ErrorIs(t, err, ErrBodyTooLarge)
}

func TestReplayableBody_BufferIdempotent(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")))

	require.NoError(t, body.Buffer(1024))
	require.NoError(t, body.Buffer(512)) // smaller limit, already buffered — no-op
	require.NoError(t, body.Buffer(2048)) // larger limit — also fine

	_, err := body.Seek(0, io.SeekStart)
	require.NoError(t, err)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(data))
}

func TestReplayableBody_SeekWithoutBuffer(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")))

	_, err := body.Seek(0, io.SeekStart)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot seek unbuffered body")
}

func TestReplayableBody_NilBody(t *testing.T) {
	body := NewReplayableBody(nil)

	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestReplayableBody_CloseUnbuffered(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")))
	require.NoError(t, body.Close())
}

func TestReplayableBody_CloseBuffered(t *testing.T) {
	body := NewReplayableBody(io.NopCloser(strings.NewReader("hello")))
	require.NoError(t, body.Buffer(1024))
	require.NoError(t, body.Close())
}
