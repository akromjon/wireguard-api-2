package main

import (
	"bytes"
	"fmt"
	"strings"
)

// quickOnlyKeys are the [Interface] keys that wg-quick / awg-quick consume
// themselves and that `wg syncconf` does not accept.
var quickOnlyKeys = []string{
	"Address", "MTU", "DNS", "Table",
	"PreUp", "PreDown", "PostUp", "PostDown", "SaveConfig",
}

// stripQuickConfig returns conf exactly as `wg-quick strip` / `awg-quick strip`
// prints it, without forking a shell script on every apply:
//   - lines are read like bash `read -r`: surrounding spaces and tabs are
//     trimmed, a final fragment without a newline counts only if non-empty;
//   - inside an [Interface] section the wg-quick-only keys are dropped
//     (case-insensitive, comments ignored for the key match);
//   - every other line is kept, trimmed, followed by a newline, and the output
//     ends with one extra newline (from `echo`).
//
// A SaveConfig value other than true/false is an error, as in wg-quick.
// NUL bytes are dropped first, as bash `read` does.
func stripQuickConfig(conf []byte) ([]byte, error) {
	conf = bytes.ReplaceAll(conf, []byte{0}, nil)
	lines := strings.Split(string(conf), "\n")
	last := len(lines) - 1

	var out bytes.Buffer
	inInterface := false
	for i, raw := range lines {
		line := strings.Trim(raw, " \t")
		if i == last && line == "" {
			break
		}

		stripped, _, _ := strings.Cut(line, "#")
		key, value, found := strings.Cut(stripped, "=")
		if !found {
			value = stripped
		}
		key = strings.Trim(key, " \t\n\v\f\r")
		value = strings.Trim(value, " \t\n\v\f\r")

		if strings.HasPrefix(key, "[") {
			inInterface = false
		}
		if strings.EqualFold(key, "[Interface]") {
			inInterface = true
		}
		if inInterface && isQuickOnlyKey(key) {
			if strings.EqualFold(key, "SaveConfig") &&
				!strings.EqualFold(value, "true") && !strings.EqualFold(value, "false") {
				return nil, fmt.Errorf("SaveConfig value %q is neither true nor false", value)
			}
			continue
		}

		out.WriteString(line)
		out.WriteByte('\n')
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func isQuickOnlyKey(key string) bool {
	for _, k := range quickOnlyKeys {
		if strings.EqualFold(key, k) {
			return true
		}
	}
	return false
}
