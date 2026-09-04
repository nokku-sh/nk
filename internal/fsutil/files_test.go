package fsutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		data     []byte
		perm     os.FileMode
		errMsg   string
	}{
		{
			name:     "write new file successfully",
			filename: filepath.Join(tmpDir, "test.txt"),
			data:     []byte("hello world"),
			perm:     0o600,
		},
		{
			name:     "write empty data",
			filename: filepath.Join(tmpDir, "empty.txt"),
			data:     []byte{},
			perm:     0o600,
		},
		{
			name:     "write to existing file",
			filename: filepath.Join(tmpDir, "existing.txt"),
			data:     []byte("original"),
			perm:     0o600,
		},
		{
			name:     "overwrite existing file",
			filename: filepath.Join(tmpDir, "existing.txt"),
			data:     []byte("updated"),
			perm:     0o600,
		},
		{
			name:     "error empty filename",
			filename: "",
			data:     []byte("test"),
			perm:     0o600,
			errMsg:   "empty filename",
		},
		{
			name:     "error path is directory",
			filename: tmpDir,
			data:     []byte("test"),
			perm:     0o600,
			errMsg:   "not a regular file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteFile(tt.filename, tt.data, tt.perm)
			if tt.errMsg != "" {
				assert.ErrorContains(t, err, tt.errMsg)
				return
			}
			require.NoError(t, err)
			got, err := os.ReadFile(tt.filename)
			require.NoError(t, err)
			assert.Equal(t, string(tt.data), string(got))
		})
	}
}

func TestFileExists(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	f, err := os.CreateTemp(tmpDir, "exist")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "existing file returns true", path: f.Name(), want: true},
		{name: "non-existing file returns false", path: filepath.Join(tmpDir, "nonexistent.txt"), want: false},
		{name: "directory returns false", path: tmpDir, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FileExists(tt.path))
		})
	}
}
