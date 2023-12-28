package csp

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// HeaderKey is the canonical form of the Content Security Policy header key.
const HeaderKey = "Content-Security-Policy"

// Acceptable webrtc values.
const (
	WebRTCAllow = "'allow'"
	WebRTCBlock = "'block'"
)

// Acceptable keyword sources used in directive values.
const (
	SourceNone                 = "'none'"
	SourceSelf                 = "'self'"
	SourceUnsafeInline         = "'unsafe-inline'"
	SourceUnsafeEval           = "'unsafe-eval'"
	SourceStrictDynamic        = "'strict-dynamic'"
	SourceUnsafeHashes         = "'unsafe-hashes'"
	SourceReportSample         = "'report-sample'"
	SourceUnsafeAllowRedirects = "'unsafe-allow-redirects'"
	SourceWasmUnsafeEval       = "'wasm-unsafe-eval'"
)

// CName is a mapping of the csp package's variable names to directive
// names as outlined in Content Security Policy Level 3.
var CName = map[string]string{
	"BaseURI":        "base-uri",
	"ChildSrc":       "child-src",
	"ConnectSrc":     "connect-src",
	"DefaultSrc":     "default-src",
	"FontSrc":        "font-src",
	"FormAction":     "form-action",
	"FrameAncestors": "frame-ancestors",
	"FrameSrc":       "frame-src",
	"ImgSrc":         "img-src",
	"ManifestSrc":    "manifest-src",
	"MediaSrc":       "media-src",
	"ObjectSrc":      "object-src",
	"ReportTo":       "report-to",
	"Sandbox":        "sandbox",
	"ScriptSrc":      "script-src",
	"ScriptSrcAttr":  "script-src-attr",
	"ScriptSrcElem":  "script-src-elem",
	"StyleSrc":       "style-src",
	"StyleSrcAttr":   "style-src-attr",
	"StyleSrcElem":   "style-src-elem",
	"WebRTC":         "webrtc",
	"WorkerSrc":      "worker-src",
}

// IsKeywordSource returns true if s is a valid keyword source used in directive
// values. As of Content Security Policy Level 3, they are required to be
// enclosed in single-quotes.
func IsKeywordSource(s string) bool {
	sources := []string{
		SourceNone,
		SourceSelf,
		SourceUnsafeInline,
		SourceUnsafeEval,
		SourceStrictDynamic,
		SourceUnsafeHashes,
		SourceReportSample,
		SourceUnsafeAllowRedirects,
		SourceWasmUnsafeEval,
		WebRTCAllow,
		WebRTCBlock,
	}
	return slices.Contains(sources, s)
}

// canon returns s trimmed of leading and trailing white space. If s is a
// keyword source, it is also lowered and enclosed in single-quotes.
func canon(s string) string {
	c := strings.TrimSpace(s)
	if kw := "'" + strings.ToLower(c) + "'"; IsKeywordSource(kw) {
		return kw
	}
	return c
}

// canons returns a slice of strings where every s in ss is trimmed of leading
// and trailing white space. If s a keyword sources, it is also lowered and
// enclosed in single-quotes.
func canons(ss []string) []string {
	cs := make([]string, len(ss))
	for i, s := range ss {
		cs[i] = canon(s)
	}
	return cs
}

// Directives represent possible Content Security Policy rules.
type Directives struct {
	BaseURI        []string
	ChildSrc       []string
	ConnectSrc     []string
	DefaultSrc     []string
	FontSrc        []string
	FormAction     []string
	FrameAncestors []string
	FrameSrc       []string
	ImgSrc         []string
	ManifestSrc    []string
	MediaSrc       []string
	ObjectSrc      []string
	ReportTo       string
	Sandbox        string
	ScriptSrc      []string
	ScriptSrcAttr  []string
	ScriptSrcElem  []string
	StyleSrc       []string
	StyleSrcAttr   []string
	StyleSrcElem   []string
	WebRTC         string
	WorkerSrc      []string
}

// Policy returns a white space joined string of policy of directives.
func Policy(ds Directives) string {
	const dFormat = "%s %s; "
	var policy strings.Builder
	val := reflect.ValueOf(&ds).Elem()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		dName := CName[val.Type().Field(i).Name]
		switch field.Kind() {
		case reflect.Slice:
			if slice := field.Interface().([]string); len(slice) > 0 {
				dVal := strings.Join(canons(slice), " ")
				policy.WriteString(fmt.Sprintf(dFormat, dName, dVal))
			}
		case reflect.String:
			if dVal := canon(field.String()); dVal != "" {
				policy.WriteString(fmt.Sprintf(dFormat, dName, dVal))
			}
		}
	}
	return strings.TrimSpace(policy.String())
}

// Basic returns a simple, non-strict CSP policy where 'self' is set on the
// following directives:
//   - default-src
//   - form-action
//   - frame-ancestors
func Basic() string {
	self := []string{SourceSelf}
	return Policy(Directives{
		DefaultSrc:     self,
		FormAction:     self,
		FrameAncestors: self,
	})
}

// BasicTight returns a tightened form of the simple, non-strict CSP policy
// where default-src is set to 'none', and 'self' is set on the following
// directives:
//   - connect-src
//   - form-action
//   - frame-ancestors
//   - img-src
//   - script-src
//   - style-src
func BasicTight() string {
	self := []string{SourceSelf}
	return Policy(Directives{
		DefaultSrc:     []string{SourceNone},
		ConnectSrc:     self,
		FormAction:     self,
		FrameAncestors: self,
		ImgSrc:         self,
		ScriptSrc:      self,
		StyleSrc:       self,
	})
}
