package main

import "fmt"

// validateBulkNames checks the name list of a bulk request (add-bulk, claim).
// It returns "" when the list is acceptable, otherwise the message for the
// HTTP 400 answer. Callers must run it before touching anything.
func validateBulkNames(names []string) string {
	if len(names) == 0 {
		return "names must contain at least one client name"
	}
	if len(names) > maxBulkUsers {
		return fmt.Sprintf("names must not contain more than %d client names", maxBulkUsers)
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !clientNameRegex.MatchString(name) {
			return fmt.Sprintf("invalid client name %q: %s", name, invalidClientNameMessage)
		}
		if seen[name] {
			return fmt.Sprintf("duplicate client name %q in request", name)
		}
		seen[name] = true
	}
	return ""
}
