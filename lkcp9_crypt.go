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

// BlockCrypt defines crypto methods for a given byte slice
type BlockCrypt interface {
	Encrypt(
		dst,
		src []byte,
	)
	Decrypt(
		dst,
		src []byte,
	)
}

type noneBlockCrypt struct{}

// NewNoneBlockCrypt == NULL encryption
func NewNoneBlockCrypt(
	_ []byte,
) (
	BlockCrypt,
	error,
) {
	return new(
			noneBlockCrypt,
		),
		nil
}

func (
	c *noneBlockCrypt,
) Encrypt(
	dst,
	src []byte,
) {
	copy(
		dst,
		src,
	)
}

func (
	c *noneBlockCrypt,
) Decrypt(
	dst,
	src []byte,
) {
	copy(
		dst,
		src,
	)
}
