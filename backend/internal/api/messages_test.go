package api

import "testing"

func TestValidE164(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"+14155551234", true},
		{"+919876543210", true},
		{"+123", false},
		{"14155551234", false},
		{"+1abc5551234", false},
		{"", false},
	}
	for _, c := range cases {
		if got := validE164(c.in); got != c.ok {
			t.Fatalf("validE164(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
}

func TestDigitsOnly(t *testing.T) {
	if got := digitsOnly("+91-987 (654) 3210"); got != "919876543210" {
		t.Fatalf("digitsOnly = %q", got)
	}
}
