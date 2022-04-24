// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import kratos "github.com/ory/kratos-client-go"

// User represents a registered user (from Ory Kratos).
type User = kratos.Session
