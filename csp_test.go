package csp

import (
	"fmt"
	"reflect"
	"testing"
)

const errorString = "\nGot:\t%v\nWanted:\t%v\n"

func TestIsKeyWordSource(t *testing.T) {
	type unit struct {
		vals []string
		want bool
	}
	cases := map[string]unit{
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
	for name, tc := range cases {
		for i, v := range tc.vals {
			t.Run(fmt.Sprintf("%s %d", name, i), func(t *testing.T) {
				got := IsKeywordSource(v)
				if got != tc.want {
					t.Fatalf(errorString, got, tc.want)
				}
			})
		}
	}
}

func TestCanon(t *testing.T) {
	type unit struct {
		vals []string
		want string
	}
	cases := map[string]unit{
		"no keywords": {
			vals: []string{"example.com/FooBar", "  example.com/FooBar     "},
			want: "example.com/FooBar",
		},
		"keywords": {
			vals: []string{"self", "    self   ", "'self'"},
			want: "'self'",
		},
	}
	for name, tc := range cases {
		for i, v := range tc.vals {
			t.Run(fmt.Sprintf("%s %d", name, i), func(t *testing.T) {
				got := canon(v)
				if got != tc.want {
					t.Fatalf(errorString, got, tc.want)
				}
			})
		}
	}
}

func TestCanons(t *testing.T) {
	type unit struct {
		vals []string
		want []string
	}
	cases := map[string]unit{
		"no keywords": {
			vals: []string{"*", "  example.com/FooBar     "},
			want: []string{"*", "example.com/FooBar"},
		},
		"with keywords": {
			vals: []string{"unsafe-inline  ", "https://example.com"},
			want: []string{"'unsafe-inline'", "https://example.com"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := canons(tc.vals)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf(errorString, got, tc.want)
			}
		})
	}
}

func TestPolicy(t *testing.T) {
	type unit struct {
		directives Directives
		want       string
	}
	cases := map[string]unit{
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
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := Policy(tc.directives)
			if got != tc.want {
				t.Fatalf(errorString, got, tc.want)
			}
		})
	}
}

func TestBasic(t *testing.T) {
	want := "default-src 'self'; form-action 'self'; frame-ancestors 'self';"
	got := Basic()
	if got != want {
		t.Errorf(errorString, got, want)
	}
}

func TestBasicTight(t *testing.T) {
	want := "connect-src 'self'; default-src 'none'; form-action 'self'; frame-ancestors 'self'; img-src 'self'; script-src 'self'; style-src 'self';"
	got := BasicTight()
	if got != want {
		t.Errorf(errorString, got, want)
	}
}
