package state

import "strings"

// Service account tokens are injected via --token or NK_TOKEN for headless
// use and are never persisted.
const serviceAccountToken = "nks"

func (s *State) IsServiceAccount() bool {
	return strings.HasPrefix(s.Token, serviceAccountToken+"_")
}
