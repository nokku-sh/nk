package state

import "strings"

// saPrefix marks service-account tokens minted by the backend. The backend's
// authentication dispatches on the same prefix, and service accounts
// authenticate with a plain Bearer header, without DPoP binding.
const saPrefix = "nokku_sa_"

// IsServiceAccount reports whether the configured token is a service-account
// token injected via --token or the environment.
func (s *State) IsServiceAccount() bool {
	return strings.HasPrefix(s.Token, saPrefix)
}
