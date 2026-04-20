package healthcheck

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopLogger struct{}

func (noopLogger) Debugf(string, ...any) {}
func (noopLogger) Info(string)           {}
func (noopLogger) Infof(string, ...any)  {}
func (noopLogger) Warnf(string, ...any)  {}
func (noopLogger) Error(string)          {}

func Test_Checker_fullcheck(t *testing.T) {
	t.Parallel()

	t.Run("canceled real dialer", func(t *testing.T) {
		t.Parallel()

		dialer := &net.Dialer{}
		addresses := []string{"badaddress:9876", "cloudflare.com:443", "google.com:443"}

		checker := &Checker{
			dialer:       dialer,
			tlsDialAddrs: addresses,
		}

		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		err := checker.fullPeriodicCheck(canceledCtx)

		require.Error(t, err)
		assert.EqualError(t, err, "TCP+TLS dial: context canceled")
	})

	// Regression: without the len(c.tlsDialAddrs) == 0 guard, `try % 0`
	// panics with "runtime error: integer divide by zero" — observed in
	// production when fullPeriodicCheck fires before config-apply has
	// populated tlsDialAddrs. The guard must return a descriptive error
	// without panicking so the outer withRetries wrapper can log and the
	// healthcheck goroutine can survive to the next tick.
	t.Run("empty tlsDialAddrs does not panic", func(t *testing.T) {
		t.Parallel()

		dialer := &net.Dialer{}
		checker := &Checker{
			dialer:       dialer,
			tlsDialAddrs: nil,
			logger:       noopLogger{},
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		assert.NotPanics(t, func() {
			err := checker.fullPeriodicCheck(ctx)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no TLS dial addresses configured")
		})
	})

	t.Run("dial localhost:0", func(t *testing.T) {
		t.Parallel()

		const timeout = 100 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		listenConfig := &net.ListenConfig{}
		listener, err := listenConfig.Listen(ctx, "tcp4", "localhost:0")
		require.NoError(t, err)
		t.Cleanup(func() {
			err = listener.Close()
			assert.NoError(t, err)
		})

		listeningAddress := listener.Addr()

		dialer := &net.Dialer{}
		checker := &Checker{
			dialer:       dialer,
			tlsDialAddrs: []string{listeningAddress.String()},
		}

		err = checker.fullPeriodicCheck(ctx)

		assert.NoError(t, err)
	})
}

func Test_smallCheckTypeToString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input    string
		expected string
	}{
		"icmp": {
			input:    smallCheckICMP,
			expected: "ICMP echo",
		},
		"dns": {
			input:    smallCheckDNS,
			expected: "plain DNS over UDP",
		},
		// Regression: without the `default:` placeholder return, this
		// `panic(...)` in the default arm kills the whole container when
		// the Go zero-value "" reaches the function during startup races
		// or config-apply reorderings.
		"zero-value does not panic": {
			input:    "",
			expected: "unknown()",
		},
		"unknown token does not panic": {
			input:    "bogus",
			expected: "unknown(bogus)",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var got string
			assert.NotPanics(t, func() {
				got = smallCheckTypeToString(testCase.input)
			})
			assert.Equal(t, testCase.expected, got)
		})
	}
}

func Test_makeAddressToDial(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		address       string
		addressToDial string
		err           error
	}{
		"host without port": {
			address:       "test.com",
			addressToDial: "test.com:443",
		},
		"host with port": {
			address:       "test.com:80",
			addressToDial: "test.com:80",
		},
		"bad address": {
			address: "test.com::",
			err:     fmt.Errorf("splitting host and port from address: address test.com::: too many colons in address"), //nolint:lll
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			addressToDial, err := makeAddressToDial(testCase.address)

			assert.Equal(t, testCase.addressToDial, addressToDial)
			if testCase.err != nil {
				assert.EqualError(t, err, testCase.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
