// guardfil-advisory-demo evaluates synthetic fake-tool fixtures without dispatching anything.
package main

import (
	"fmt"
	"os"

	"github.com/reviaro/guardfil/internal/advisorydemo"
)

func main() {
	if err := advisorydemo.Run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
