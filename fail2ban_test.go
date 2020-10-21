package fail2ban_test

import (
	"testing"

	plug "github.com/tommoulard/fail2ban"
)

func TestDummy(t *testing.T) {
	cfg := plug.CreateConfig()
	t.Log(cfg)
}

func TestImportIp(t *testing.T) {
    tests := []struct {
		name    string
        list    plug.List
        strWant []string
        err     error
	}{
        {
            name: "empty list",
            list: plug.List{
				Ip:   []string{},
				Files: []string{},
			},
            strWant: []string {},
            err: nil,
        },
    }
    for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
            got, e := plug.ImportIP (tt.list)
            if e != tt.err {
                t.Errorf("wanted '%s' got '%s'", tt.err, e)
            }
            if len(got) != len(tt.strWant) {
                t.Errorf("wanted '%s' got '%s'", tt.strWant, got)
            }
        })
    }
}
