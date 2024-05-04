package status

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Source: https://github.com/traefik/traefik/blob/05d2c86074a21d482945b9994d85e3b66de0480d/pkg/types/http_code_range.go

// HTTPCodeRanges holds HTTP code ranges.
type HTTPCodeRanges [][2]int

// NewHTTPCodeRanges creates HTTPCodeRanges from a given []string.
// Break out the http status code ranges into a low int and high int
// for ease of use at runtime.
func NewHTTPCodeRanges(strBlocks []string) (HTTPCodeRanges, error) {
	blocks := make(HTTPCodeRanges, 0, len(strBlocks))

	for _, block := range strBlocks {
		codes := strings.Split(block, "-")
		// if only a single HTTP code was configured, assume the best and create the correct configuration on the user's behalf
		if len(codes) == 1 {
			codes = append(codes, codes[0])
		}

		lowCode, err := strconv.Atoi(codes[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse HTTP code: %w", err)
		}

		highCode, err := strconv.Atoi(codes[1])
		if err != nil {
			return nil, fmt.Errorf("failed to parse HTTP code: %w", err)
		}

		blocks = append(blocks, [2]int{lowCode, highCode})
	}

	return blocks, nil
}

// Contains tests whether the passed status code is within one of its HTTP code ranges.
func (h HTTPCodeRanges) Contains(statusCode int) bool {
	return slices.ContainsFunc(h, func(block [2]int) bool {
		return statusCode >= block[0] && statusCode <= block[1]
	})
}
