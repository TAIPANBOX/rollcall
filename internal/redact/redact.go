// Package redact removes secrets from text before it reaches an error, a log
// line or a status message.
package redact

import (
	"slices"
	"strings"
)

// Marker replaces each secret in redacted text.
const Marker = "[redacted]"

// Redact returns s with every non-empty secret replaced by Marker. Longer
// secrets are matched first, so a secret that contains another is replaced
// whole. The replacement is one pass over s, so a marker is never rescanned.
func Redact(s string, secrets ...string) string {
	list := slices.DeleteFunc(slices.Clone(secrets), func(x string) bool { return x == "" })
	if len(list) == 0 {
		return s
	}
	slices.SortStableFunc(list, func(a, b string) int { return len(b) - len(a) })
	pairs := make([]string, 0, 2*len(list))
	for _, secret := range list {
		pairs = append(pairs, secret, Marker)
	}
	return strings.NewReplacer(pairs...).Replace(s)
}
