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
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
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

// KcpNonceMD5 ...
type KcpNonceMD5 struct {
	seed [md5.Size]byte
}

// Init ...
func (
	n *KcpNonceMD5,
) Init() {
}

// Fill ...
func (
	n *KcpNonceMD5,
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
	n.seed = md5.Sum(
		n.seed[:],
	)
	copy(
		nonce,
		n.seed[:],
	)
}

// KcpNonceAES128 ...
type KcpNonceAES128 struct {
	seed  [aes.BlockSize]byte
	block cipher.Block
}

// Init ...
func (
	n *KcpNonceAES128,
) Init() {
	var err error
	var key [16]byte
	_, err = io.ReadFull(
		rand.Reader,
		key[:],
	)
	if err != nil {
		panic("io.ReadFull failure")
	}
	_, err = io.ReadFull(
		rand.Reader,
		n.seed[:],
	)
	if err != nil {
		panic("io.ReadFull failure")
	}
	block, _ := aes.NewCipher(
		key[:],
	)
	n.block = block
}

// Fill ...
func (
	n *KcpNonceAES128,
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
	n.block.Encrypt(
		n.seed[:],
		n.seed[:],
	)
	copy(
		nonce,
		n.seed[:],
	)
}
