package main

import (
	"fmt"
	"os"

	"github.com/mizuchilabs/kata/sigx"

	"github.com/nokku-sh/nk/internal/cmd"
)

func main() {
	root := cmd.Root()
	if err := root.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", root.Name, err)
		os.Exit(1)
	}
}
