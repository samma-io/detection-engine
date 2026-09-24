package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Scrubbing exists because the filtered bucket is tagged
// contains_PII_data = "true" / data_classification = "restricted", and a
// sidecar derived from it is committed to git forever.
//
// Real records are worth having for their SHAPE -- the field names, the
// nesting, the value formats nobody remembers. None of that requires the
// identifiers. So every value that looks like a person, a host or a credential
// is replaced with a documentation-range equivalent of the same form, and the
// structure is left exactly as the source emitted it.
//
// The replacements deliberately keep the shape: an email stays an email, an
// ARN stays a parseable ARN, an IPv4 stays four octets. A rule matching with
// |contains or |cidr must still behave the same way against the scrubbed
// record, and scrubbing that changed the shape would quietly invalidate the
// test rather than protect anyone.
var (
	reEmail   = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	reIPv4    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reAcct    = regexp.MustCompile(`\b\d{12}\b`)
	reLongTok = regexp.MustCompile(`\b[A-Za-z0-9+/_\-]{32,}={0,2}\b`)
)

// privateIPv4 keeps RFC1918 and loopback addresses, which describe topology
// rather than a person and are often the reason a rule fires at all.
func privateIPv4(s string) bool {
	switch {
	case strings.HasPrefix(s, "10."), strings.HasPrefix(s, "192.168."), strings.HasPrefix(s, "127."):
		return true
	case strings.HasPrefix(s, "172."):
		var a, b int
		if _, err := fmt.Sscanf(s, "%d.%d.", &a, &b); err == nil && b >= 16 && b <= 31 {
			return true
		}
	}
	return false
}

// scrubString replaces identifying substrings while preserving form.
func scrubString(s string) string {
	// 0.0.0.0/0 and ::/0 are security-relevant values, not addresses of
	// anything, and several rules match them exactly.
	if s == "0.0.0.0/0" || s == "::/0" || s == "0.0.0.0" {
		return s
	}
	s = reEmail.ReplaceAllString(s, "redacted@example.com")
	s = reIPv4.ReplaceAllStringFunc(s, func(ip string) string {
		if privateIPv4(ip) {
			return ip
		}
		return "203.0.113.10" // TEST-NET-3, reserved for documentation
	})
	s = reAcct.ReplaceAllString(s, "123456789012")
	s = reLongTok.ReplaceAllStringFunc(s, func(t string) string {
		// Leave anything that is clearly structural rather than a credential.
		if strings.Contains(t, ".amazonaws.com") || strings.HasPrefix(t, "arn:") {
			return t
		}
		return "REDACTED"
	})
	return s
}

// scrubbedNames are fields whose value is a person or a credential regardless
// of what it looks like, so pattern matching is not enough.
var scrubbedNames = map[string]string{
	"username":     "example-user",
	"user_name":    "example-user",
	"actor":        "example-user",
	"user":         "example-user",
	"principalid":  "EXAMPLEPRINCIPALID",
	"accesskeyid":  "AKIAEXAMPLEEXAMPLE",
	"hashed_token": "REDACTED",
	"email":        "redacted@example.com",
	"actor_email":  "redacted@example.com",
	"displayname":  "Example User",
}

// scrub walks a decoded record, returning a copy safe to commit.
func scrub(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if repl, ok := scrubbedNames[strings.ToLower(k)]; ok {
				if _, isStr := val.(string); isStr {
					out[k] = repl
					continue
				}
			}
			out[k] = scrub(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = scrub(val)
		}
		return out
	case string:
		return scrubString(x)
	default:
		return v
	}
}

func scrubRecord(rec map[string]any) map[string]any {
	s, _ := scrub(rec).(map[string]any)
	return s
}
