package bootstrap

import (
	"testing"
)

func TestIsTruthy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"true", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"on", true},
		{"false", false},
		{"", false},
		{"0", false},
	} {
		if got := isTruthy(tc.in); got != tc.want {
			t.Errorf("isTruthy(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSeedRedirectURI(t *testing.T) {
	t.Setenv("AUTO_SEED_REDIRECT_URI", "")
	t.Setenv("CORS_ORIGIN", "https://app.example.com")
	if got := seedRedirectURI(); got != "https://app.example.com/callback" {
		t.Fatalf("got %q", got)
	}
}
