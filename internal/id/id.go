package id

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
)

func MachineID() string {
	hostname, err := os.Hostname() // fallback
	if err != nil {
		return "unknown"
	}

	id, err := machineID()
	if err != nil {
		return hostname
	}

	h := hmac.New(sha256.New, []byte("machine-id"))
	if _, err = h.Write([]byte(id)); err != nil {
		return hostname
	}

	return hex.EncodeToString(h.Sum(nil))
}
