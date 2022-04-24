// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

// References https://github.com/emersion/go-sasl/issues/18
import (
	"encoding/json"
	"fmt"
	"github.com/emersion/go-sasl"
)

const Xoauth2 = "XOAUTH2"

type Xoauth2Error struct {
	Status  string `json:"status"`
	Schemes string `json:"schemes"`
	Scope   string `json:"scope"`
}

func (err *Xoauth2Error) Error() string {
	return fmt.Sprintf("XOAUTH2 authentication error (%v)", err.Status)
}

type xoauth2Client struct {
	Username string
	Token    string
}

func (a *xoauth2Client) Start() (mech string, ir []byte, err error) {
	mech = Xoauth2
	ir = []byte("user=" + a.Username + "\x01auth=Bearer " + a.Token + "\x01\x01")
	return
}

func (a *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	// Server sent an error response
	xoauth2Err := &Xoauth2Error{}
	if err := json.Unmarshal(challenge, xoauth2Err); err != nil {
		return nil, err
	} else {
		return nil, xoauth2Err
	}
}

func NewXoauth2Client(username, token string) sasl.Client {
	return &xoauth2Client{username, token}
}
