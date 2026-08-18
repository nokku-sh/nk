package state

import "strings"

// IsServiceAccount reports whether the configured token is a service-account
// API key. kagi API keys are "<keyID>.<secret>"; the dot separates the two,
// exactly like the server's dispatch rule.
func (s *State) IsServiceAccount() bool {
	key, secret, found := strings.Cut(s.Token, ".")
	return found && key != "" && secret != ""
}
