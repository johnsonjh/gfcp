// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.
// Copyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

package lkcp9 // import "go.gridfinity.dev/lkcp9"

import (
	hh "github.com/minio/highwayhash"
	//hh "crypto/md5"
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

// KcpNonceHH ...
type KcpNonceHH struct {
	seed [hh.Size]byte
}

// Init ...
func (
	n *KcpNonceHH,
) Init() {
}

// Fill ...
func (
	n *KcpNonceHH,
) Fill(
	nonce []byte,
) {
	var err error
	if n.seed[0] == 0 {
		_, err = io.ReadFull(
			rand.Reader,
			n.seed[:],
		)
		if err != nil {
			panic("io.ReadFull failure")
		}
	}
	n.seed = hh.Sum(
		n.seed[:],
		n.seed[:],
	)
	copy(
		nonce,
		n.seed[:],
	)
}
