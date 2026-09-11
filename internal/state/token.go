package state

import "strings"

// saPrefix marks service-account tokens. Unlike device sessions they
// authenticate with a plain Bearer header, without DPoP binding.
const saPrefix = "nokku_sa_"

// IsServiceAccount reports whether Token came from --token or the environment.
func (s *State) IsServiceAccount() bool {
	return strings.HasPrefix(s.Token, saPrefix)
}
