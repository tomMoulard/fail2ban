package files_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/eiko-team/eiko/misc/files"
)

func TestGetFileContent(t *testing.T) {
	tests := []struct {
		name     string
		fileName string
		err      string
	}{
		{name: "Open file", fileName: "test-file.txt", err: ""},
		{name: "file do not exist",
			fileName: "test-file-2.txt",
			err:      "open test-file-2.txt: no such file or directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text1, err := files.GetFileContent(tt.fileName)
			if err != nil && err.Error() != tt.err {
				t.Errorf("GetFileContent() error = %v, wantErr %v", err, tt.err)
				return
			}
			if tt.err == "" {
				file, err := os.Open(tt.fileName)
				if err != nil {
					t.Error(err)
				}
				defer file.Close()

				text, err := ioutil.ReadAll(file)
				if err != nil {
					t.Error(err)
				}

				text2 := string(text)

				if text1 != text2 {
					t.Error("Did not get the same file out")
				}
			}
		})
	}
}
