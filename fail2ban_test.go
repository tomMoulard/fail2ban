package fail2ban

import (
	"errors"
	"testing"
)

func TestDummy(t *testing.T) {
	t.Parallel()

	cfg := CreateConfig()
	t.Log(cfg)
}

func TestTransformRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		send   Rules
		expect RulesTransformed
		err    error
	}{
		{
			name: "dummy",
			send: Rules{
				Bantime:  "300s",
				Findtime: "120s",
				Enabled:  true,
			},
			expect: RulesTransformed{},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, e := TransformRule(tt.send)
			if e != nil && (tt.err == nil || e.Error() != tt.err.Error()) {
				t.Errorf("TransformRule_err: wanted '%s' got '%s'",
					tt.err, e)
			}
			if tt.expect.bantime == got.bantime {
				t.Errorf("TransformRule: wanted '%+v' got '%+v'",
					tt.expect, got)
			}
		})
	}
}

func TestImportIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		list    List
		strWant []string
		err     error
	}{
		{
			name: "empty list",
			list: List{
				IP:    []string{},
				Files: []string{},
			},
			strWant: []string{},
			err:     nil,
		},

		{
			name: "simple import",
			list: List{
				IP:    []string{"192.168.0.0", "0.0.0.0", "255.255.255.255"},
				Files: []string{"tests/test-ipfile.txt"},
			},
			strWant: []string{"192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00", "192.168.0.0", "0.0.0.0", "255.255.255.255"},
			err:     nil,
		},

		{
			name: "import only file",
			list: List{
				IP:    []string{},
				Files: []string{"tests/test-ipfile.txt"},
			},
			strWant: []string{"192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00"},
			err:     nil,
		},

		{
			name: "import two file",
			list: List{
				IP:    []string{},
				Files: []string{"tests/test-ipfile.txt", "tests/test-ipfile.txt"},
			},
			strWant: []string{"192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00", "192.168.0.0", "255.0.0.0", "42.42.42.42", "13.38.70.00"},
			err:     nil,
		},

		{
			name: "import only ip",
			list: List{
				IP:    []string{"192.168.0.0", "0.0.0.0", "255.255.255.255"},
				Files: []string{},
			},
			strWant: []string{"192.168.0.0", "0.0.0.0", "255.255.255.255"},
			err:     nil,
		},

		{
			name: "import no file",
			list: List{
				IP:    []string{},
				Files: []string{"tests/idontexist.txt"},
			},
			strWant: []string{},
			err:     errors.New("error when getting file content: Error opening file: open tests/idontexist.txt: no such file or directory"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, e := ImportIP(tt.list)
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
