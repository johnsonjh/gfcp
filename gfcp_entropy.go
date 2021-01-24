// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2021 Gridfinity, LLC. <admin@gridfinity.com>.
// Copyright © 2021 Jeffrey H. Johnson <jeff@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

package gfcp // import "go.gridfinity.dev/gfcp"

import (
	"crypto/rand"
	"io"
)

// Entropy defines a entropy source
type Entropy interface {
	Init()
	Fill(
		nonce []byte,
	)
}

// Nonce ...
type Nonce struct {
	seed []byte
}

// Init ...
func (
	n *Nonce,
) Init() {
}

// Fill ...
func (
	n *Nonce,
) Fill(
	nonce []byte,
) {
	var err error
	if n.seed[0] == 0 {
		_, err = io.ReadFull(
			rand.Reader,
			n.seed,
		)
		if err != nil {
			panic(
				"io.ReadFull failure",
			)
		}
	}
	copy(
		nonce,
		n.seed,
	)
}
