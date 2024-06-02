package status

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		ranges     HTTPCodeRanges
		statusCode int
		expected   assert.BoolAssertionFunc
	}{
		{
			name:       "empty",
			ranges:     HTTPCodeRanges{},
			statusCode: 200,
			expected:   assert.False,
		},
		{
			name:       "single",
			ranges:     HTTPCodeRanges{{200, 200}},
			statusCode: 200,
			expected:   assert.True,
		},
		{
			name:       "single out of range high",
			ranges:     HTTPCodeRanges{{200, 200}},
			statusCode: 201,
			expected:   assert.False,
		},
		{
			name:       "single out of range low",
			ranges:     HTTPCodeRanges{{200, 200}},
			statusCode: 199,
			expected:   assert.False,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			test.expected(t, test.ranges.Contains(test.statusCode))
		})
	}
}
