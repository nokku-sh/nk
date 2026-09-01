package ui

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/term"
)

// colorEnabled is resolved once per process: colors are on only when stdout
// is a terminal and the user has not opted out via NO_COLOR.
var colorEnabled = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return IsTerminal(os.Stdout)
}()

// Color wraps s in the given SGR attribute code when colors are enabled.
// The code must not include the leading ESC[ or trailing "m".
func Color(code, s string) string {
	if !colorEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Bold(s string) string   { return Color("1", s) }
func Dim(s string) string    { return Color("2", s) }
func Red(s string) string    { return Color("31", s) }
func Green(s string) string  { return Color("32", s) }
func Yellow(s string) string { return Color("33", s) }

// IsTerminal reports whether f is an interactive terminal.
func IsTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// HumanizeDuration formats a non-negative duration as a compact,
// human-friendly string such as "3h 12m", "45s", or "900ms".
func HumanizeDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		days := int(d.Hours() / 24)
		h := int(d.Hours()) % 24
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, h)
	}
}
