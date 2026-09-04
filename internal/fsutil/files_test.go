package fsutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestWriteIfChanged(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	old := time.Unix(1000000000, 0)

	path := filepath.Join(tmpDir, "file.txt")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))
	require.NoError(t, os.Chtimes(path, old, old))

	t.Run("identical content is not rewritten", func(t *testing.T) {
		require.NoError(t, WriteIfChanged(path, []byte("original"), 0o600))
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, old, fi.ModTime(), "file was rewritten despite identical content")
	})

	t.Run("different content triggers a write", func(t *testing.T) {
		require.NoError(t, WriteIfChanged(path, []byte("updated"), 0o600))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "updated", string(got))
		fi, err := os.Stat(path)
		require.NoError(t, err)
		assert.NotEqual(t, old, fi.ModTime())
	})

	t.Run("new file is written", func(t *testing.T) {
		p := filepath.Join(tmpDir, "new.txt")
		require.NoError(t, WriteIfChanged(p, []byte("data"), 0o600))
		got, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, "data", string(got))
	})

	t.Run("same size different content triggers a write", func(t *testing.T) {
		p := filepath.Join(tmpDir, "samesize.txt")
		require.NoError(t, os.WriteFile(p, []byte("aaaaa"), 0o600))
		require.NoError(t, os.Chtimes(p, old, old))

		require.NoError(t, WriteIfChanged(p, []byte("bbbbb"), 0o600))
		fi, err := os.Stat(p)
		require.NoError(t, err)
		assert.NotEqual(t, old, fi.ModTime(), "same-size content diff must not take the no-op path")
	})
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
