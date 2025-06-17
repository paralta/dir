// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package verify

var opts = &options{}

type options struct {
	FromStdin bool

	// Verification options
	OIDCIssuer   string
	OIDCIdentity string
	Key          string // Key to use for verification, e.g., 'env://COSIGN_PUBLIC_KEY'
}

func init() {
	flags := Command.Flags()
	flags.BoolVar(&opts.FromStdin, "stdin", false,
		"Read data from standard input. Useful for piping. Reads from file if empty. "+
			"Ignored if file is provided as an argument.",
	)

	// Verification options
	flags.StringVar(&opts.OIDCIssuer, "oidc-issuer", ".*",
		"OIDC Issuer to check against. Accepts regular expressions.")
	flags.StringVar(&opts.OIDCIdentity, "oidc-identity", ".*",
		"OIDC Identity to compare against. Accepts regular expressions.")
	flags.StringVar(&opts.Key, "key", "",
		"Key to use for verification, e.g., 'env://COSIGN_PUBLIC_KEY'")
}
