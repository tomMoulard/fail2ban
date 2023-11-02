package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
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
				t.Errorf("TransformRule_err: wanted %q got %q",
					tt.err, e)
			}
			if tt.expect.Bantime == got.Bantime {
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
			err:     errors.New("error when getting file content: error opening file: open tests/idontexist.txt: no such file or directory"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, e := ImportIP(tt.list)
			t.Logf("%+v", got)
			if e != nil && e.Error() != tt.err.Error() {
				t.Errorf("wanted %q got %q", tt.err, e)
			}
			if len(got) != len(tt.strWant) {
				t.Errorf("wanted '%d' got '%d'", len(tt.strWant), len(got))
			}

			for i, elt := range tt.strWant {
				if got[i] != elt {
					t.Errorf("wanted %q got %q", elt, got[i])
				}
			}
		})
	}
}

func TestFail2Ban(t *testing.T) {
	t.Parallel()

	remoteAddr := "10.0.0.0"
	tests := []struct {
		name         string
		url          string
		cfg          Config
		newError     bool
		expectStatus int
	}{
		{
			name: "no bantime",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Findtime: "300s",
					Maxretry: 20,
				},
			},
			newError:     true,
			expectStatus: http.StatusOK,
		},
		{
			name: "no findtime",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Maxretry: 20,
				},
			},
			newError:     true,
			expectStatus: http.StatusOK,
		},
		{
			name: "rule enabled",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 20,
				},
			},
			newError:     false,
			expectStatus: http.StatusOK,
		},
		{
			name: "rule not enabled beside being blacklisted",
			cfg: Config{
				Rules: Rules{
					Enabled: false,
				},
				Blacklist: List{
					IP: []string{remoteAddr},
				},
			},
			newError:     false,
			expectStatus: http.StatusOK,
		},
		{
			name: "bad regexp",
			url:  "/test",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 10,
					Urlregexps: []Urlregexp{
						{
							Regexp: "/(test",
							Mode:   "allow",
						},
					},
				},
			},
			newError: true,
		},
		{
			name: "invalid Regexp mode",
			url:  "/test",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 20,
					Urlregexps: []Urlregexp{
						{
							Regexp: "/test",
							Mode:   "not-an-actual-mode",
						},
					},
				},
			},
			newError:     false,
			expectStatus: http.StatusOK, // request not blacklisted
		},
		{
			name: "url whitelisted",
			url:  "/test",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 10,
					Urlregexps: []Urlregexp{
						{
							Regexp: "/test",
							Mode:   "allow",
						},
					},
				},
			},
			newError:     false,
			expectStatus: http.StatusOK,
		},
		{
			name: "url blacklisted",
			url:  "/test",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 10,
					Urlregexps: []Urlregexp{
						{
							Regexp: "/test",
							Mode:   "block",
						},
					},
				},
			},
			newError:     false,
			expectStatus: http.StatusForbidden,
		},
		{
			name: "whitelist",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 20,
				},
				Whitelist: List{
					IP: []string{remoteAddr},
				},
			},
			newError:     false,
			expectStatus: http.StatusOK,
		},
		{
			name: "blacklist",
			cfg: Config{
				Rules: Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 20,
				},
				Blacklist: List{
					IP: []string{remoteAddr},
				},
			},
			newError:     false,
			expectStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			nextCount := atomic.Int32{}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				nextCount.Add(1)
			})

			handler, err := New(context.Background(), next, &tt.cfg, "fail2ban_test")
			if err != nil {
				if tt.newError != (err != nil) {
					t.Errorf("newError: wanted '%t' got '%t'", tt.newError, err != nil)
				}

				return
			}

			url := "/"
			if tt.url != "" {
				url = tt.url
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.RemoteAddr = remoteAddr + ":1234"
			for i := 0; i < 10; i++ {
				rw := httptest.NewRecorder()
				handler.ServeHTTP(rw, req)
				if rw.Code != tt.expectStatus {
					t.Fatalf("code: got %d, expected %d", rw.Code, tt.expectStatus)
				}
			}
		})
	}
}

func TestShouldAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Fail2Ban
		remoteIP string
		reqURL   string
		expect   bool
	}{
		{
			name: "first request",
			cfg: &Fail2Ban{
				ipViewed: map[string]IPViewed{},
			},
			expect: true,
		},
		{
			name: "second request",
			cfg: &Fail2Ban{
				ipViewed: map[string]IPViewed{
					"10.0.0.0": {
						viewed: time.Now(),
						nb:     1,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   true,
		},
		{
			name: "blacklisted request",
			cfg: &Fail2Ban{
				rules: RulesTransformed{
					Bantime: 300 * time.Second,
				},
				ipViewed: map[string]IPViewed{
					"10.0.0.0": {
						viewed:      time.Now(),
						nb:          1,
						blacklisted: true,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   false,
		},
		{
			name: "should unblock request", // since no request during bantime
			cfg: &Fail2Ban{
				rules: RulesTransformed{
					Bantime: 300 * time.Second,
				},
				ipViewed: map[string]IPViewed{
					"10.0.0.0": {
						viewed:      time.Now().Add(-600 * time.Second),
						nb:          1,
						blacklisted: true,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   true,
		},
		{
			name: "should block request", // since too much request during findtime
			cfg: &Fail2Ban{
				rules: RulesTransformed{
					MaxRetry: 1,
					Findtime: 300 * time.Second,
				},
				ipViewed: map[string]IPViewed{
					"10.0.0.0": {
						viewed: time.Now().Add(600 * time.Second),
						nb:     1,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   false,
		},
		{
			name: "should check request",
			cfg: &Fail2Ban{
				rules: RulesTransformed{
					MaxRetry: 3,
					Findtime: 300 * time.Second,
				},
				ipViewed: map[string]IPViewed{
					"10.0.0.0": {
						viewed: time.Now().Add(600 * time.Second),
						nb:     1,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   true,
		},
		{
			name: "allow regexp",
			cfg: &Fail2Ban{
				rules: RulesTransformed{
					Bantime:        300 * time.Second,
					URLRegexpAllow: []*regexp.Regexp{regexp.MustCompile("/test")}, // comment me.
				},
				ipViewed: map[string]IPViewed{
					"10.0.0.0": {
						viewed:      time.Now(),
						nb:          1,
						blacklisted: true,
					},
				},
			},
			remoteIP: "10.0.0.0",
			reqURL:   "/test",
			expect:   true,
		},
		{
			name: "block regexp",
			cfg: &Fail2Ban{
				rules: RulesTransformed{
					URLRegexpBan: []*regexp.Regexp{regexp.MustCompile("/test")}, // comment me.
				},
				ipViewed: map[string]IPViewed{},
			},
			reqURL: "/test",
			expect: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.cfg.ShouldAllow(tt.remoteIP, tt.reqURL)
			if tt.expect != got {
				t.Errorf("wanted '%t' got '%t'", tt.expect, got)
			}
		})
	}
}

// https://github.com/tomMoulard/fail2ban/issues/67
func TestDeadlockWebsocket(t *testing.T) {
	t.Parallel()

	writeChan := make(chan any)
	concurentWSCount := atomic.Int32{}
	next := websocket.Handler(func(ws *websocket.Conn) {
		concurentWSCount.Add(1)
		<-writeChan
		t.Cleanup(func() {
			concurentWSCount.Add(-1)
		})

		_, _ = io.Copy(ws, ws)
	})

	cfg := CreateConfig()
	cfg.Rules.Maxretry = 20

	handler, err := New(context.Background(), next, cfg, "fail2ban_test")
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(handler)
	defer s.Close()

	wsURL := "ws" + strings.TrimPrefix(s.URL, "http")
	conns := make([]*websocket.Conn, 10)

	for i := 0; i < 10; i++ {
		ws, err := websocket.Dial(wsURL, "", "http://localhost")
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = ws.Close() }()

		conns[i] = ws
	}

	close(writeChan)

	for i := 0; i < 10; i++ {
		msg := fmt.Sprintf("hello %d", i)

		n, err := conns[i].Write([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}

		p := make([]byte, n)

		_, err = conns[i].Read(p)
		if err != nil {
			t.Fatal(err)
		}

		if msg != string(p) {
			t.Errorf("wanted %q got %q", msg, string(p))
		}
	}

	if concurentWSCount.Load() != 10 {
		t.Errorf("wanted %d got %d", 10, concurentWSCount.Load())
	}
}
