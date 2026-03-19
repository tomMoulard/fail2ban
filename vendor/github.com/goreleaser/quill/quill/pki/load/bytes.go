package load

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

func BytesFromFileOrEnv(path string) ([]byte, error) {
	if strings.HasPrefix(path, "env:") {
		// comes from an env var...
		fields := strings.Split(path, "env:")
		if len(fields) < 2 {
			return nil, fmt.Errorf("key path has 'env:' prefix, but cannot parse env variable: %q", path)
		}
		envVar := fields[1]

		value := os.Getenv(envVar)
		if value == "" {
			return nil, fmt.Errorf("no key found in environment variable %q", envVar)
		}

		keyBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
		return keyBytes, nil
	}

	// comes from the config...

	if _, err := os.Stat(path); err != nil {

		decodedKey, err := base64.StdEncoding.DecodeString(path)
		if err != nil {
			return nil, fmt.Errorf("unable to base64 decode key: %w", err)
		}

		return decodedKey, nil
	}

	// comes from a file...

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	return io.ReadAll(f)
}
