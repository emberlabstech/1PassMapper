package main

import (
	"fmt"
	"os"
)

// failf formats an error message, prints it to standard error, and terminates the program with exit code 1.
func failf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
