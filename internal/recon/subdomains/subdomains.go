// Package subdomains provides subdomain enumeration methods.
package subdomains

import (
	_ "embed"
)

//go:embed wordlist.txt
var DefaultWordlist string

const DefaultWordlistPath = "embedded"

// Note: FromCRTSH is implemented in crtsh.go
// Note: BruteForce is implemented in bruteforce.go
