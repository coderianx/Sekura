// Command sekura initializes Sekura's local configuration and encryption key.
package main

import (
	"log"

	"github.com/coderianx/Sekura/internal/config"
)

// main initializes configuration, provisions the application secret key, and
// exits the process if either operation fails.
func main() {
	err := config.Init()

	if err != nil {
		log.Fatal(err)
	}

	err = config.CreateSecretKey()

	if err != nil {
		log.Fatal(err)
	}
}
