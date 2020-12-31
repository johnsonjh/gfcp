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

type KcpNonceMD5 struct {
	seed [md5.Size]byte
}

func (
	n *KcpNonceMD5,
) Init() {}

func (
	n *KcpNonceMD5,
) Fill(
	nonce []byte,
) {
	if n.seed[0] == 0 {
		io.ReadFull(
			rand.Reader,
			n.seed[:],
		)
	}
	n.seed = md5.Sum(
		n.seed[:],
	)
	copy(
		nonce,
		n.seed[:],
	)
}

type KcpNonceAES128 struct {
	seed  [aes.BlockSize]byte
	block cipher.Block
}

func (
	n *KcpNonceAES128,
) Init() {
	var key [16]byte
	io.ReadFull(
		rand.Reader,
		key[:],
	)
	io.ReadFull(
		rand.Reader,
		n.seed[:],
	)
	block, _ := aes.NewCipher(
		key[:],
	)
	n.block = block
}

func (
	n *KcpNonceAES128,
) Fill(
	nonce []byte,
) {
	if n.seed[0] == 0 {
		io.ReadFull(
			rand.Reader,
			n.seed[:],
		)
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
