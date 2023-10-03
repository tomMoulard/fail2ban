package files_test

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/files"
)

func Example() {
	// Get file content
	text, err := files.GetFileContent("test-file.txt")
	if err != nil {
		panic(err)
	}

	// Print file content
	println(text)

	// Output:
	//
}

func TestGetFileContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fileName string
		err      string
	}{
		{name: "Open file", fileName: "test-file.txt", err: ""},
		{
			name:     "file do not exist",
			fileName: "test-file-2.txt",
			err:      "error opening file: open test-file-2.txt: no such file or directory",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			text1, err := files.GetFileContent(tt.fileName)
			if err != nil {
				assert.Equal(t, tt.err, err.Error())

				return
			}

			file, err := os.Open(tt.fileName)
			require.NoError(t, err)
			defer func() { require.NoError(t, file.Close()) }()

			text, err := io.ReadAll(file)
			require.NoError(t, err)

			assert.Equal(t, string(text), text1)
		})
	}
}
