package manual

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderPrincipalFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ids  []string
		want string
	}{
		{name: "empty input renders empty", ids: nil, want: ""},
		{name: "sorts and terminates with a newline", ids: []string{"id-b", "id-a"}, want: "id-a\nid-b\n"},
		{name: "drops duplicates", ids: []string{"id-b", "id-a", "id-b"}, want: "id-a\nid-b\n"},
		{name: "drops empty ids", ids: []string{"", "id-a", ""}, want: "id-a\n"},
		{name: "all empty renders empty", ids: []string{"", ""}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, string(RenderPrincipalFile(tt.ids)))
		})
	}
}

func TestRenderDropIn(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"TrustedUserCAKeys /etc/ssh/nokku_ca.pub\n"+
			"AuthorizedPrincipalsFile /etc/ssh/nokku_principals/%u\n",
		string(RenderDropIn(CAPath, PrincipalsDir)))

	assert.Equal(t,
		"TrustedUserCAKeys /tmp/ca.pub\n"+
			"AuthorizedPrincipalsFile /tmp/principals/%u\n",
		string(RenderDropIn("/tmp/ca.pub", "/tmp/principals")))
}

func TestLocalAccounts(t *testing.T) {
	t.Parallel()

	getent := strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin",
		"sync:x:5:0:sync:/sbin:/bin/sync",
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash",
		"bob:x:1001:1001:Bob:/home/bob:/usr/bin/false",
		"svc:x:1002:1002:Service:/var/lib/svc:/usr/sbin/nologin",
		"carol:x:1003:1003:Carol:/home/carol:/bin/zsh",
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
		"broken:fewer:fields",
		"nauid:x:notanumber:0:x:/home/x:/bin/sh",
		":x:1004:1004:No name:/home/none:/bin/sh",
		"",
	}, "\n")

	assert.Equal(t, []string{"alice", "carol", "root"}, LocalAccounts(getent))
}

func TestLocalAccountsCapsAtOneHundred(t *testing.T) {
	t.Parallel()

	var b strings.Builder
	for i := range 150 {
		fmt.Fprintf(&b, "user%03d:x:%d:%d::/home/user%03d:/bin/bash\n", i, 1000+i, 1000+i, i)
	}

	accounts := LocalAccounts(b.String())
	assert.Len(t, accounts, 100)
	assert.Equal(t, "user000", accounts[0])
	assert.Equal(t, "user099", accounts[99])
}

func TestRootLoginAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		sshdT string
		want  bool
	}{
		{name: "yes", sshdT: "permitrootlogin yes\n", want: true},
		{name: "prohibit-password", sshdT: "permitrootlogin prohibit-password\n", want: true},
		{name: "without-password alias", sshdT: "permitrootlogin without-password\n", want: true},
		{name: "no", sshdT: "permitrootlogin no\n", want: false},
		{name: "forced-commands-only", sshdT: "permitrootlogin forced-commands-only\n", want: false},
		{name: "absent option keeps the default", sshdT: "port 22\n", want: true},
		{name: "empty dump", sshdT: "", want: true},
		{
			name:  "extracted from a full dump",
			sshdT: "port 22\npermitrootlogin no\npubkeyauthentication yes\n",
			want:  false,
		},
		{
			name:  "case insensitive key",
			sshdT: "PermitRootLogin prohibit-password\n",
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, RootLoginAllowed(tt.sshdT))
		})
	}
}
