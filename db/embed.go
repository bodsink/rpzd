package db

import _ "embed"

// Schema contains the SQL schema for the rpzd database.
//
//go:embed schema.sql
var Schema string
