package fail2ban

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tomMoulard/fail2ban/pkg/rules"
	"golang.org/x/net/websocket"
)

func TestDummy(t *testing.T) {
	t.Parallel()

	cfg := CreateConfig()
	t.Log(cfg)
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
			err:     errors.New("error when getting file content: open tests/idontexist.txt: no such file or directory"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, e := ImportIP(test.list)
			t.Logf("%+v", got)

			if e != nil && e.Error() != test.err.Error() {
				t.Errorf("wanted %q got %q", test.err, e)
			}

			if len(got) != len(test.strWant) {
				t.Errorf("wanted '%d' got '%d'", len(test.strWant), len(got))
			}

			for i, elt := range test.strWant {
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
		cfg          *Config
		newError     bool
		expectStatus int
	}{
		{
			name: "no bantime",
			cfg: &Config{
				Rules: rules.Rules{
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
			cfg: &Config{
				Rules: rules.Rules{
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
			cfg: &Config{
				Rules: rules.Rules{
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
			name: "rule not enabled beside being denylisted",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled: false,
				},
				Denylist: List{
					IP: []string{remoteAddr},
				},
			},
			newError:     false,
			expectStatus: http.StatusOK,
		},
		{
			name: "bad regexp",
			url:  "/test",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 10,
					Urlregexps: []rules.Urlregexp{
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
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 20,
					Urlregexps: []rules.Urlregexp{
						{
							Regexp: "/test",
							Mode:   "not-an-actual-mode",
						},
					},
				},
			},
			newError:     false,
			expectStatus: http.StatusOK, // request not denylisted
		},
		{
			name: "url allowlisted",
			url:  "/test",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 10,
					Urlregexps: []rules.Urlregexp{
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
			name: "url denylisted",
			url:  "/test",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 10,
					Urlregexps: []rules.Urlregexp{
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
			name: "allowlist",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 20,
				},
				Allowlist: List{
					IP: []string{remoteAddr},
				},
			},
			newError:     false,
			expectStatus: http.StatusOK,
		},
		{
			name: "denylist",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:  true,
					Bantime:  "300s",
					Findtime: "300s",
					Maxretry: 20,
				},
				Denylist: List{
					IP: []string{remoteAddr},
				},
			},
			newError:     false,
			expectStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			nextCount := atomic.Int32{}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				nextCount.Add(1)
			})

			handler, err := New(t.Context(), next, test.cfg, "fail2ban_test")
			if err != nil {
				if test.newError != (err != nil) {
					t.Errorf("newError: wanted '%t' got '%t'", test.newError, err != nil)
				}

				return
			}

			url := "/"
			if test.url != "" {
				url = test.url
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.RemoteAddr = remoteAddr + ":1234"

			for range 10 {
				rw := httptest.NewRecorder()
				handler.ServeHTTP(rw, req)

				if rw.Code != test.expectStatus {
					t.Fatalf("code: got %d, expected %d", rw.Code, test.expectStatus)
				}
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

	handler, err := New(t.Context(), next, cfg, "fail2ban_test")
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(handler)
	defer s.Close()

	wsURL := "ws" + strings.TrimPrefix(s.URL, "http")
	conns := make([]*websocket.Conn, 10)

	for i := range 10 {
		ws, err := websocket.Dial(wsURL, "", "http://localhost")
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = ws.Close() }()

		conns[i] = ws
	}

	close(writeChan)

	for i := range 10 {
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

func TestFail2Ban_SuccessiveRequests(t *testing.T) {
	t.Parallel()

	remoteAddr := "10.0.0.0"
	tests := []struct {
		name          string
		cfg           *Config
		handlerStatus []int // HTTP code the internal HTTP handler should return
		expectStatus  []int // HTTP code the downstream client should request after passing through fail2ban
	}{
		{
			name: "rule enabled, 200 code does not increment count or ban",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:    true,
					Bantime:    "300s",
					Findtime:   "300s",
					Maxretry:   3,
					StatusCode: "404",
				},
			},
			// multiple OKs in a row should not result in a ban
			handlerStatus: []int{http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK},
			expectStatus:  []int{http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK},
		},
		{
			name: "rule enabled, single 404 does not ban",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:    true,
					Bantime:    "300s",
					Findtime:   "300s",
					Maxretry:   3,
					StatusCode: "404",
				},
			},
			handlerStatus: []int{http.StatusNotFound, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK},
			expectStatus:  []int{http.StatusNotFound, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK},
		},
		{
			name: "rule enabled, multiple 404 causes ban",
			cfg: &Config{
				Rules: rules.Rules{
					Enabled:    true,
					Bantime:    "300s",
					Findtime:   "300s",
					Maxretry:   3,
					StatusCode: "404",
				},
			},
			// the remaining OKs will not reach the client as it is banned
			handlerStatus: []int{http.StatusNotFound, http.StatusOK, http.StatusNotFound, http.StatusNotFound, http.StatusOK, http.StatusOK, http.StatusOK, http.StatusOK},
			expectStatus:  []int{http.StatusNotFound, http.StatusOK, http.StatusNotFound, http.StatusForbidden, http.StatusForbidden, http.StatusForbidden, http.StatusForbidden, http.StatusForbidden},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				testno, err := strconv.Atoi(r.Header.Get("Testno"))
				if err != nil {
					t.Fatalf("Error parsing header: %v", err)
				}

				w.WriteHeader(testno)
			})

			handler, _ := New(context.Background(), next, test.cfg, "fail2ban_test")

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = remoteAddr + ":1234"

			for i := range test.handlerStatus {
				rw := httptest.NewRecorder()

				req.Header.Set("Testno", strconv.Itoa(test.handlerStatus[i])) // pass the expected value to the mock handler (fail2ban response code may differ)
				handler.ServeHTTP(rw, req)

				if rw.Code != test.expectStatus[i] {
					t.Fatalf("request [%d] code: got %d, expected %d", i, rw.Code, test.expectStatus[i])
				}
			}
		})
	}
}
