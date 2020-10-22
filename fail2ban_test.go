package fail2ban_test

import (
	"errors"
	"testing"

	plug "github.com/tommoulard/fail2ban"
)

func TestDummy(t *testing.T) {
	cfg := plug.CreateConfig()
	t.Log(cfg)
}

func TestTransformRules(t *testing.T) {
	tests := []struct {
		name   string
		send   plug.Rules
		expect plug.RulesTransformed
		err    error
	}{
		{
			name:   "dummy",
			send:   plug.CreateRules(),
			expect: plug.RulesTransformed{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, e := plug.TransformRule(tt.send)
			if e != nil && (tt.err == nil || e.Error() != tt.err.Error()) {
				t.Errorf("TransformRule_err: wanted '%s' got '%s'",
					tt.err, e)
			}
			// if tt.expect.bantime == got.bantime {
			// t.Errorf("TransformRule: wanted '%+v' got '%+v'",
			// tt.expect, got)
			// }
		})
	}
}

func TestImportIP(t *testing.T) {
	tests := []struct {
		name    string
		list    plug.List
		strWant []string
		err     error
	}{
		{
			name: "empty list",
			list: plug.List{
				IP:    []string{},
				Files: []string{},
			},
			strWant: []string{},
			err:     nil,
		},

		{
			name: "simple import",
			list: plug.List{
				IP:    []string{"192.168.0.0", "0.0.0.0", "255.255.255.255"},
				Files: []string{"tests/test-ipfile.txt"},
			},
			strWant: []string{"192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00", "192.168.0.0", "0.0.0.0", "255.255.255.255"},
			err:     nil,
		},

		{
			name: "import only file",
			list: plug.List{
				IP:    []string{},
				Files: []string{"tests/test-ipfile.txt"},
			},
			strWant: []string{"192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00"},
			err:     nil,
		},

		{
			name: "import two file",
			list: plug.List{
				IP:    []string{},
				Files: []string{"tests/test-ipfile.txt", "tests/test-ipfile.txt"},
			},
			strWant: []string{"192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00", "192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00"},
			err:     nil,
		},

		{
			name: "import only ip",
			list: plug.List{
				IP:    []string{"192.168.0.0", "0.0.0.0", "255.255.255.255"},
				Files: []string{},
			},
			strWant: []string{"192.168.0.0", "0.0.0.0", "255.255.255.255"},
			err:     nil,
		},

		{
			name: "import no file",
			list: plug.List{
				IP:    []string{},
				Files: []string{"tests/idontexist.txt"},
			},
			strWant: []string{},
			err:     errors.New("open tests/idontexist.txt: no such file or directory"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, e := plug.ImportIP(tt.list)
			t.Logf("%+v", got)
			if e != nil && e.Error() != tt.err.Error() {
				t.Errorf("wanted '%s' got '%s'", tt.err, e)
			}
			if len(got) != len(tt.strWant) {
				t.Errorf("wanted '%d' got '%d'", len(tt.strWant), len(got))
			}

			for i, elt := range tt.strWant {
				if got[i] != elt {
					t.Errorf("wanted '%s' got '%s'", elt, got[i])
				}
			}
		})
	}
}
