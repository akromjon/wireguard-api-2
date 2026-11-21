package main

import (
	"bytes"
	"log"
	"os/exec"
	"strings"
)

// headerProtectionKeyLine reports whether line is a HeaderProtectionKey
// assignment and returns its trimmed value. The key name is matched
// case-insensitively; the value is returned as written.
func headerProtectionKeyLine(line []byte) (string, bool) {
	name, value, found := strings.Cut(string(line), "=")
	if !found || !strings.EqualFold(strings.TrimSpace(name), "HeaderProtectionKey") {
		return "", false
	}
	return strings.TrimSpace(value), true
}

// headerProtectionKeyOf returns the value of the first HeaderProtectionKey
// line in conf.
func headerProtectionKeyOf(conf []byte) (string, bool) {
	for _, line := range bytes.Split(conf, []byte("\n")) {
		if v, ok := headerProtectionKeyLine(line); ok {
			return v, true
		}
	}
	return "", false
}

// dropHeaderProtectionKey removes every HeaderProtectionKey line from conf.
func dropHeaderProtectionKey(conf []byte) []byte {
	var out bytes.Buffer
	for _, line := range bytes.SplitAfter(conf, []byte("\n")) {
		if _, ok := headerProtectionKeyLine(line); ok {
			continue
		}
		out.Write(line)
	}
	return out.Bytes()
}

// filterHeaderProtectionKey drops the HeaderProtectionKey line from the
// stripped config when the live interface already holds the same key, so the
// apply does not re-set it. In every other case the text is returned unchanged.
// Key values are never logged.
func filterHeaderProtectionKey(stripped []byte) []byte {
	want, ok := headerProtectionKeyOf(stripped)
	if !ok {
		return stripped
	}
	out, err := exec.Command(wgCmd, "showconf", wgParams.ServerWGNIC).Output()
	if err != nil {
		log.Printf("header key kept in apply: %s showconf failed: %v", wgCmd, err)
		return stripped
	}
	live, ok := headerProtectionKeyOf(out)
	if !ok {
		log.Printf("header key kept in apply: live interface has no key")
		return stripped
	}
	if live != want {
		log.Printf("header key kept in apply: live key differs")
		return stripped
	}
	return dropHeaderProtectionKey(stripped)
}
