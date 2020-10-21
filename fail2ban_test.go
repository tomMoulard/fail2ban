package htransformation_test

import (
	"testing"

	plug "github.com/tommoulard/fail2ban"
)

func TestDummy(t *testing.T) {
	cfg := plug.CreateConfig()
	t.Log(cfg)
}
