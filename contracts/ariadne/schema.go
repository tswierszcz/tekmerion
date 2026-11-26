// Package contract embeds the pinned Ariadne schema without depending on the working directory.
package contract

import _ "embed"

// Schema is the authoritative schema pinned by PIN.json.
//
//go:embed v1/contract.schema.json
var Schema []byte
