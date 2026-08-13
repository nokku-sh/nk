package main

import (
	"fmt"
	"os"

	"github.com/mizuchilabs/kata/sigx"

	"github.com/nokku-sh/nk/internal/cli"
)

func main() {
	if err := cli.Run(sigx.NotifyContext(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "nk: %v\n", err)
		os.Exit(1)
	}
}
