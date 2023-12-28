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

// Acceptable keyword-sources used in directive values.
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

// IsKeywordSource returns true if s is a valid keyword-source as described in
// Content Security Policy Level 3; they are required to be enclosed in
// single-quotes.
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
// keyword-source, it is also lowered and enclosed in single-quotes.
func canon(s string) string {
	c := strings.TrimSpace(s)
	if kw := "'" + strings.ToLower(c) + "'"; IsKeywordSource(kw) {
		return kw
	}
	return c
}

// canons returns a slice of strings where every s in ss is trimmed of leading
// and trailing white space. If s a keyword-source, it is also lowered and
// enclosed in single-quotes.
func canons(ss []string) []string {
	cs := make([]string, len(ss))
	for i, s := range ss {
		cs[i] = canon(s)
	}
	return cs
}

// Directives represent possible Content Security Policy rules that enable
// developers to manage particular features of their websites.
type Directives struct {
	// (base-uri) BaseURI is a document directive that restricts the URLs which
	// can be used in a HTML <base> element.
	BaseURI []string

	// (child-src) ChildSrc is a fetch directive that restricts the sources for
	// child navigables such as <frame> and <iframe> and Worker execution
	// contexts.
	ChildSrc []string

	// (connect-src) ConnectSrc is a fetch directive that restricts the URLs
	// which can be loaded using script interfaces (e.g. fetch(), <a ping>, XHR,
	// EventSource, WebSockets). If not allowed, the browser emulates a 400 Bad
	// Request HTTP status code.
	ConnectSrc []string

	// (default-src) DefaultSrc is a fetch directive that serves as the fallback
	// for other fetch directives.
	DefaultSrc []string

	// (font-src) FontSrc is a fetch directive that restricts the URLs from
	// which font resources may be loaded.
	FontSrc []string

	// (form-action) FormAction is a navigation directive that restricts the
	// URLs which can be used as the target of a form submissions from a given
	// context.
	FormAction []string

	// (frame-ancestors) FrameAncestors is a navigation directive that restricts
	// the URLS which can embed the resource using <frame>, <iframe>, <object>,
	// or <embed>.
	FrameAncestors []string

	// (frame-src) FrameSrc is a fetch directive that restricts the URLs which
	// may be loaded into child navigables.
	FrameSrc []string

	// (img-src) ImgSrc is a fetch directive that restricts the URLs from which
	// image resources may be loaded.
	ImgSrc []string

	// (manifest-src) ManifestSrc is a fetch directive that restricts the URLs
	// from which application manifests may be loaded.
	ManifestSrc []string

	// (media-src) MediaSrc is a fetch directive that restricts the URLs from
	// which video, audio, and associated text track resources may be loaded.
	MediaSrc []string

	// (object-src) ObjectSrc is a fetch directive that restricts the URLs from
	// which plugin content may be loaded.
	ObjectSrc []string

	// (report-to) ReportTo is a reporting directive that defines an endpoint to
	// which violation reports should be sent.
	ReportTo string

	// (sandbox) Sandbox is a navigation directive that specifies an HTML
	// sandbox policy which the user agent will apply to a resource, as if it
	// had been included in an <iframe> with a sandbox property.
	Sandbox string

	// (script-src) ScriptSrc is a fetch directive that restricts the locations
	// from which scripts may be executed and serves as a default fallback for
	// all script-like destinations.
	ScriptSrc []string

	// (script-src-attr) ScriptSrcAttr is a fetch directive that applies to
	// event handlers and, if present, it will override the script-src directive
	// for relevant checks.
	ScriptSrcAttr []string

	// (script-src-elem) ScriptSrcElem is a fetch directive that applies to all
	// script requests and script blocks.
	ScriptSrcElem []string

	// (style-src) StyleSrc is a fetch directive that restricts the locations
	// from which style may be applied to a Document.
	StyleSrc []string

	// (style-src-attr) StyleSrcAttr is a fetch directive that governs the
	// behaviour of style attributes.
	StyleSrcAttr []string

	// (style-src-elem) StyleSrcElem is a fetch directive that governs the
	// behaviour of styles except for styles defined in inline attributes.
	StyleSrcElem []string

	// (webrtc) WebRTC is a directive that restricts whether connections may be
	// established via WebRTC - possible values are "'allow'" or "'block'".
	WebRTC string

	// (worker-src) WorkerSrc is a directive that restricts the URLs which may
	// be loaded as a Worker, SharedWorker, or ServiceWorker.
	WorkerSrc []string
}

// Policy returns a white space joined string of all directives where each
// directive ends in a semi-colon.
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

// Basic returns a simple, non-strict CSP policy where sources is restricted to
// 'self' for the following directives:
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
// where sources is restricted to 'none' as a fallback and restricted to 'self'
// for following directives:
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
