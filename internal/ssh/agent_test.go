package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/nokku-sh/mon/tpm"
)

// e2eKey opens the TPM identity key: the real device when available, the
// in-process simulator otherwise.
func e2eKey(t *testing.T) *tpm.Key {
	t.Helper()
	if key, err := tpm.OpenKey(sshTPMSalt); err == nil {
		t.Log("using real TPM device")
		return key
	}
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Skipf("no TPM device and simulator unavailable: %v", err)
	}
	key, err := tpm.NewKey(sim, sshTPMSalt)
	if err != nil {
		_ = sim.Close()
		t.Fatalf("NewKey: %v", err)
	}
	t.Log("using TPM simulator")
	t.Cleanup(func() { _ = sim.Close() })
	return key
}

// TestAgentSSHDInterop proves the TPM identity flow end to end against a real
// sshd: the ssh client authenticates with a certificate whose private key
// only exists inside the TPM, served through the embedded agent.
func TestAgentSSHDInterop(t *testing.T) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Skip("sshd not available")
	}
	current, err := user.Current()
	if err != nil || current.Username == "" {
		t.Skip("cannot determine current user")
	}

	key := e2eKey(t)
	defer func() { _ = key.Close() }()

	sshPub, err := cryptossh.NewPublicKey(key.Public())
	require.NoError(t, err, "public key")

	// Sign the TPM public key with a throwaway CA, like the backend does.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caSigner, err := cryptossh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	cert := &cryptossh.Certificate{
		Key:             sshPub,
		Serial:          1,
		CertType:        cryptossh.UserCert,
		KeyId:           "e2e",
		ValidPrincipals: []string{current.Username},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner), "sign certificate")

	dir := t.TempDir()
	pubFile := filepath.Join(dir, "nokku.pub")
	certFile := filepath.Join(dir, "nokku-cert.pub")
	sockFile := filepath.Join(dir, "agent.sock")
	require.NoError(t, os.WriteFile(pubFile, cryptossh.MarshalAuthorizedKey(sshPub), 0o600))
	require.NoError(t, os.WriteFile(certFile, cryptossh.MarshalAuthorizedKey(cert), 0o600))
	caFile := filepath.Join(dir, "ca.pub")
	require.NoError(t, os.WriteFile(
		caFile,
		cryptossh.MarshalAuthorizedKey(caSigner.PublicKey()),
		0o600,
	))

	// Serve the TPM key on the agent socket, as ServeAgent does.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", sockFile)
	require.NoError(t, err, "listen")
	defer func() { _ = ln.Close() }()
	ring := agent.NewKeyring()
	require.NoError(t, ring.Add(agent.AddedKey{PrivateKey: key, Comment: "nokku (tpm)"}), "agent add")
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(ring, conn)
			}()
		}
	}()

	port := startSSHD(t, sshd, dir, caFile)

	baseArgs := []string{
		"-p", port,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"),
		"-o", "CertificateFile=" + certFile,
		"-o", "IdentityFile=" + pubFile, // public key only, key lives in the agent
		"-o", "LogLevel=DEBUG1",
	}
	env := []string{"SSH_AUTH_SOCK="} // never leak the user's real agent

	// With the TPM agent, certificate auth must succeed.
	out, err := sshCmd(env, append(baseArgs,
		"-o", "IdentityAgent="+sockFile,
		current.Username+"@127.0.0.1", "true",
	))
	require.NoError(t, err, "ssh with TPM agent failed:\n%s", out)

	// Without the agent there is no usable private key on disk: auth must
	// fail, proving the identity is not derivable from what is stored.
	out, err = sshCmd(env, append(baseArgs,
		"-o", "IdentityAgent=none",
		current.Username+"@127.0.0.1", "true",
	))
	assert.Error(t, err, "ssh without agent unexpectedly succeeded:\n%s", out)
}

func sshCmd(env, args []string) (string, error) {
	cmd := exec.Command("ssh", args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// startSSHD launches a same-user sshd trusting the test CA and returns its
// port.
func startSSHD(t *testing.T, sshd, dir, caFile string) string {
	t.Helper()

	hostKey := filepath.Join(dir, "host_key")
	keygen := exec.Command("ssh-keygen", "-t", "ed25519", "-f", hostKey, "-N", "", "-q")
	if out, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}

	portLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(portLn.Addr().(*net.TCPAddr).Port)
	if err = portLn.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := filepath.Join(dir, "sshd_config")
	config := fmt.Sprintf(`Port %s
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
UsePAM no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile none
TrustedUserCAKeys %s
StrictModes no
`, port, hostKey, filepath.Join(dir, "sshd.pid"), caFile)
	if err = os.WriteFile(cfg, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(sshd, "-f", cfg, "-D", "-e")
	logFile, err := os.Create(filepath.Join(dir, "sshd.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = logFile
	if err = cmd.Start(); err != nil {
		t.Fatalf("start sshd: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()
	})

	for range 50 {
		conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+port, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return port
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("sshd did not start; log:\n%s", readFile(t, filepath.Join(dir, "sshd.log")))
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err.Error()
	}
	return string(data)
}
