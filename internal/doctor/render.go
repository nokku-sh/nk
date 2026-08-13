package doctor

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/nokku-sh/nk/internal/util"
)

// glyph maps a check status to its terminal symbol.
var glyph = map[Status]string{
	StatusOK:   "✔",
	StatusWarn: "⚠",
	StatusFail: "✖",
	StatusInfo: "ℹ",
}

// color maps a status to its colorizer.
func color(status Status) func(string) string {
	switch status {
	case StatusOK:
		return util.Green
	case StatusWarn:
		return util.Yellow
	case StatusFail:
		return util.Red
	case StatusInfo:
		return util.Dim
	default:
		return util.Dim
	}
}

// Print writes the report to w as human-readable text (or JSON when jsonOut
// is set).
func Print(w io.Writer, r Report, jsonOut bool) error {
	if jsonOut {
		return printJSON(w, r)
	}
	printText(w, r)
	return nil
}

func printJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func printText(w io.Writer, r Report) {
	for _, f := range r.Fixes {
		fmt.Fprintf(w, "  %s %s\n", util.Green("✔"), f)
	}
	if len(r.Fixes) > 0 {
		fmt.Fprintln(w)
	}

	width := maxNameWidth(r.Checks)
	var lastSection string
	for _, c := range r.Checks {
		if c.Section != lastSection {
			if lastSection != "" {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, util.Bold(c.Section))
			lastSection = c.Section
		}
		paint := color(c.Status)
		glyph := paint(glyph[c.Status])
		name := util.Bold(fmt.Sprintf("%-*s", width, c.Name))
		if c.Detail != "" {
			fmt.Fprintf(w, "  %s %s  %s\n", glyph, name, util.Dim(c.Detail))
		} else {
			fmt.Fprintf(w, "  %s %s\n", glyph, name)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, summarize(r))
}

func maxNameWidth(checks []Check) int {
	w := 0
	for _, c := range checks {
		if n := len(c.Name); n > w {
			w = n
		}
	}
	return w
}

func summarize(r Report) string {
	var ok, warn, fail int
	for _, c := range r.Checks {
		switch c.Status {
		case StatusOK:
			ok++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		case StatusInfo:
		}
	}

	line := fmt.Sprintf("Result: %d ok, %d warn, %d fail", ok, warn, fail)
	switch {
	case fail > 0:
		return util.Red(line + " (run `nk doctor --fix` or `nk login`)")
	case warn > 0:
		return util.Yellow(line + " (see warnings above)")
	default:
		return util.Green(line + " (all good)")
	}
}
