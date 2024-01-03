package csp

import (
	"fmt"
	"reflect"
	"testing"
)

const errorString = "\nGot:\t%v\nWant:\t%v\n"

func TestIsKeyWordSource(t *testing.T) {
	cases := map[string]struct {
		vals []string
		want bool
	}{
		"no keywords": {
			vals: []string{"*", "https:", "example.com"},
			want: false,
		},
		"keywords but no single-quotes": {
			vals: []string{"none", "self", "unsafe-inline"},
			want: false,
		},
		"keywords": {
			vals: []string{"'none'", "'self'", "'unsafe-inline'"},
			want: true,
		},
	}
	for name, c := range cases {
		for i, v := range c.vals {
			t.Run(fmt.Sprintf("%s %d", name, i), func(t *testing.T) {
				if got := IsKeywordSource(v); got != c.want {
					t.Fatalf(errorString, got, c.want)
				}
			})
		}
	}
}

func TestCanon(t *testing.T) {
	cases := map[string]struct {
		vals []string
		want string
	}{
		"no keywords": {
			vals: []string{"example.com/FooBar", "  example.com/FooBar     "},
			want: "example.com/FooBar",
		},
		"keywords": {
			vals: []string{"self", "    self   ", "'self'"},
			want: "'self'",
		},
	}
	for name, c := range cases {
		for i, v := range c.vals {
			t.Run(fmt.Sprintf("%s %d", name, i), func(t *testing.T) {
				if got := canon(v); got != c.want {
					t.Fatalf(errorString, got, c.want)
				}
			})
		}
	}
}

func TestCanons(t *testing.T) {
	cases := map[string]struct {
		vals []string
		want []string
	}{
		"no keywords": {
			vals: []string{"*", "  example.com/FooBar     "},
			want: []string{"*", "example.com/FooBar"},
		},
		"with keywords": {
			vals: []string{"unsafe-inline  ", "https://example.com"},
			want: []string{"'unsafe-inline'", "https://example.com"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := canons(c.vals); !reflect.DeepEqual(got, c.want) {
				t.Fatalf(errorString, got, c.want)
			}
		})
	}
}

func TestPolicy(t *testing.T) {
	cases := map[string]struct {
		directives Directives
		want       string
	}{
		"single": {
			directives: Directives{
				DefaultSrc: []string{"acme.com", "example.com"},
			},
			want: "default-src acme.com example.com;",
		},
		"multiple": {
			directives: Directives{
				DefaultSrc: []string{"self"},
				StyleSrc:   []string{"self", "example.com"},
				ReportTo:   "jd@example.com",
			},
			want: "default-src 'self'; report-to jd@example.com; style-src 'self' example.com;",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Policy(c.directives); got != c.want {
				t.Fatalf(errorString, got, c.want)
			}
		})
	}
}

func TestBasicAndBasicTight(t *testing.T) {
	cases := map[string]struct {
		policy string
		want   string
	}{
		"basic": {
			policy: Basic(),
			want:   "default-src 'self'; form-action 'self'; frame-ancestors 'self';",
		},
		"basic tight": {
			policy: BasicTight(),
			want:   "connect-src 'self'; default-src 'none'; form-action 'self'; frame-ancestors 'self'; img-src 'self'; script-src 'self'; style-src 'self';",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.policy != c.want {
				t.Fatalf(errorString, c.policy, c.want)
			}
		})
	}
}
