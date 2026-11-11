// Command vws-region-helper exposes the region daemon's privileged file boundary.
package main

import (
	"os"

	"github.com/popododo0720/vws-console-api/internal/regionhelper"
)

func main() {
	os.Exit(regionhelper.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
