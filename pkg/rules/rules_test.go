package rules

import "testing"

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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, e := TransformRule(test.send)
			if e != nil && (test.err == nil || e.Error() != test.err.Error()) {
				t.Errorf("TransformRule_err: wanted %q got %q",
					test.err, e)
			}

			if test.expect.Bantime == got.Bantime {
				t.Errorf("TransformRule: wanted '%+v' got '%+v'",
					test.expect, got)
			}
		})
	}
}
