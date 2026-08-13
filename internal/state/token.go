package state

import "strings"

func (s *State) IsServiceAccount() bool {
	return strings.HasPrefix(s.Token, "nks_")
}

// ServiceAccountID returns the ID of the service account token.
func (s *State) ServiceAccountID() string {
	if s.Token == "" {
		return ""
	}
	return strings.Split(s.Token, "_")[1]
}
