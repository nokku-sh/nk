package state

import "strings"

// IsServiceAccount reports whether the configured token is a service-account
// API key. kagi API keys are "<keyID>.<secret>"; the dot separates the two,
// exactly like the server's dispatch rule.
func (s *State) IsServiceAccount() bool {
	key, secret, found := strings.Cut(s.Token, ".")
	return found && key != "" && secret != ""
}

// ServiceAccountID returns the ID of the service account. The service account
// id is resolved from the server after the key authenticates (via
// GetServiceAccount), so it is not derived from the token itself.
func (s *State) ServiceAccountID() string {
	if s.ServiceAccount == nil {
		return ""
	}
	return s.ServiceAccount.ID
}
