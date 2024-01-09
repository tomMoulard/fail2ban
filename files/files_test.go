package files_test

import (
	"io"
	"os"
	"testing"

	"github.com/fliot/fail2ban/files"
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
				if tt.err != err.Error() {
					t.Errorf("GetFileContent() = %q, want %q", err.Error(), tt.err)
				}

				return
			}

			file, err := os.Open(tt.fileName)
			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			text, err := io.ReadAll(file)
			if err != nil {
				t.Fatal(err)
			}

			if text1 != string(text) {
				t.Errorf("GetFileContent() = %q, want %q", text1, string(text))
			}
		})
	}
}
