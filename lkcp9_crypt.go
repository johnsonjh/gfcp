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
	"hash/fnv"

	"github.com/templexxx/xor"
	"github.com/tjfoc/gmsm/sm4"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
)

const (
	chunk = 64
)

var (
	initialVector = []byte{
		167, 115, 79, 156,
		18, 172, 27, 1,
		164, 21, 242, 193,
		252, 120, 230, 107,
	}
	saltxor = `sH3CIVoF#rWLtJo6`
)

type digest struct {
	h   [5]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

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

type salsa20BlockCrypt struct {
	key [32]byte
}

// NewSalsa20BlockCrypt function
func NewSalsa20BlockCrypt(
	key []byte,
) (
	BlockCrypt,
	error,
) {
	c := new(
		salsa20BlockCrypt,
	)
	copy(
		c.key[:],
		key,
	)
	return c, nil
}

func (
	c *salsa20BlockCrypt,
) Encrypt(
	dst,
	src []byte,
) {
	salsa20.XORKeyStream(
		dst[8:],
		src[8:],
		src[:8],
		&c.key)
	copy(
		dst[:8],
		src[:8],
	)
}

func (
	c *salsa20BlockCrypt,
) Decrypt(
	dst,
	src []byte,
) {
	salsa20.XORKeyStream(
		dst[8:],
		src[8:],
		src[:8],
		&c.key)
	copy(
		dst[:8],
		src[:8],
	)
}

type sm4BlockCrypt struct {
	encbuf [sm4.BlockSize]byte
	decbuf [2 * sm4.BlockSize]byte
	block  cipher.Block
}

// NewSM4BlockCrypt function
func NewSM4BlockCrypt(
	key []byte,
) (
	BlockCrypt,
	error,
) {
	c := new(
		sm4BlockCrypt,
	)
	block, err := sm4.NewCipher(
		key,
	)
	if err != nil {
		return nil, err
	}
	c.block = block
	return c, nil
}

func (
	c *sm4BlockCrypt,
) Encrypt(
	dst,
	src []byte,
) {
	encrypt(
		c.block,
		dst,
		src,
		c.encbuf[:],
	)
}

func (
	c *sm4BlockCrypt,
) Decrypt(
	dst,
	src []byte,
) {
	decrypt(
		c.block,
		dst,
		src,
		c.decbuf[:],
	)
}

type aesBlockCrypt struct {
	encbuf [aes.BlockSize]byte
	decbuf [2 * aes.BlockSize]byte
	block  cipher.Block
}

// NewAESBlockCrypt function
func NewAESBlockCrypt(
	key []byte,
) (
	BlockCrypt,
	error,
) {
	c := new(
		aesBlockCrypt,
	)
	block, err := aes.NewCipher(
		key,
	)
	if err != nil {
		return nil, err
	}
	c.block = block
	return c, nil
}

func (
	c *aesBlockCrypt,
) Encrypt(
	dst,
	src []byte,
) {
	encrypt(
		c.block,
		dst,
		src,
		c.encbuf[:],
	)
}

func (
	c *aesBlockCrypt,
) Decrypt(
	dst,
	src []byte,
) {
	decrypt(
		c.block,
		dst,
		src,
		c.decbuf[:],
	)
}

type simpleXORBlockCrypt struct {
	xortbl []byte
}

// NewSimpleXORBlockCrypt function
func NewSimpleXORBlockCrypt(
	key []byte,
) (
	BlockCrypt,
	error,
) {
	c := new(
		simpleXORBlockCrypt,
	)
	c.xortbl = pbkdf2.Key(
		key,
		[]byte(saltxor),
		32,
		KcpMtuLimit,
		fnv.New128a,
	)
	return c, nil
}

func (
	c *simpleXORBlockCrypt,
) Encrypt(
	dst,
	src []byte,
) {
	xor.Bytes(
		dst,
		src,
		c.xortbl,
	)
}

func (
	c *simpleXORBlockCrypt,
) Decrypt(
	dst,
	src []byte,
) {
	xor.Bytes(
		dst,
		src,
		c.xortbl,
	)
}

type noneBlockCrypt struct{}

// NewNoneBlockCrypt function (null encryption)
func NewNoneBlockCrypt(
	key []byte,
) (
	BlockCrypt,
	error,
) {
	return new(
		noneBlockCrypt,
	), nil
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

func encrypt(
	block cipher.Block,
	dst,
	src,
	buf []byte,
) {
	switch block.BlockSize() {
	case 8:
		encrypt8(block, dst, src, buf)
	case 16:
		encrypt16(block, dst, src, buf)
	default:
		encryptVariant(block, dst, src, buf)
	}
}

func encrypt8(block cipher.Block, dst, src, buf []byte) {
	tbl := buf[:8]
	block.Encrypt(tbl, initialVector)
	n := len(
		src,
	) / 8
	base := 0
	repeat := n / 8
	left := n % 8
	for i := 0; i < repeat; i++ {
		s := src[base:][0:64]
		d := dst[base:][0:64]
		xor.BytesSrc1(
			d[0:8],
			s[0:8],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[0:8],
		)
		xor.BytesSrc1(
			d[8:16],
			s[8:16],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[8:16],
		)
		xor.BytesSrc1(
			d[16:24],
			s[16:24],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[16:24],
		)
		xor.BytesSrc1(
			d[24:32],
			s[24:32],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[24:32],
		)
		xor.BytesSrc1(
			d[32:40],
			s[32:40],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[32:40],
		)
		xor.BytesSrc1(
			d[40:48],
			s[40:48],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[40:48],
		)
		xor.BytesSrc1(
			d[48:56],
			s[48:56],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[48:56],
		)
		xor.BytesSrc1(
			d[56:64],
			s[56:64],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[56:64],
		)
		base += 64
	}
	switch left {
	case 7:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 8
		fallthrough
	case 6:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 8
		fallthrough
	case 5:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 8
		fallthrough
	case 4:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 8
		fallthrough
	case 3:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 8
		fallthrough
	case 2:
		xor.BytesSrc1(dst[base:], src[base:], tbl)
		block.Encrypt(tbl, dst[base:])
		base += 8
		fallthrough
	case 1:
		xor.BytesSrc1(dst[base:], src[base:], tbl)
		block.Encrypt(tbl, dst[base:])
		base += 8
		fallthrough
	case 0:
		xor.BytesSrc0(dst[base:], src[base:], tbl)
	}
}

func encrypt16(
	block cipher.Block,
	dst,
	src,
	buf []byte,
) {
	tbl := buf[:16]
	block.Encrypt(
		tbl,
		initialVector,
	)
	n := len(
		src,
	) / 16
	base := 0
	repeat := n / 8
	left := n % 8
	for i := 0; i < repeat; i++ {
		s := src[base:][0:128]
		d := dst[base:][0:128]
		xor.BytesSrc1(
			d[0:16],
			s[0:16],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[0:16],
		)
		xor.BytesSrc1(
			d[16:32],
			s[16:32],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[16:32],
		)
		xor.BytesSrc1(
			d[32:48],
			s[32:48],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[32:48],
		)
		xor.BytesSrc1(
			d[48:64],
			s[48:64],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[48:64],
		)
		xor.BytesSrc1(
			d[64:80],
			s[64:80],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[64:80],
		)
		xor.BytesSrc1(
			d[80:96],
			s[80:96],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[80:96],
		)
		xor.BytesSrc1(
			d[96:112],
			s[96:112],
			tbl,
		)
		block.Encrypt(
			tbl,
			d[96:112],
		)
		xor.BytesSrc1(
			d[112:128],
			s[112:128],
			tbl,
		)
		block.Encrypt(tbl, d[112:128])
		base += 128
	}
	switch left {
	case 7:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 16
		fallthrough
	case 6:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 16
		fallthrough
	case 5:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 16
		fallthrough
	case 4:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 16
		fallthrough
	case 3:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 16
		fallthrough
	case 2:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 16
		fallthrough
	case 1:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += 16
		fallthrough
	case 0:
		xor.BytesSrc0(dst[base:], src[base:], tbl)
	}
}

func encryptVariant(
	block cipher.Block,
	dst,
	src,
	buf []byte,
) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	block.Encrypt(
		tbl,
		initialVector,
	)
	n := len(
		src,
	) / blocksize
	base := 0
	repeat := n / 8
	left := n % 8
	for i := 0; i < repeat; i++ {
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
	}
	switch left {
	case 7:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		fallthrough
	case 6:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		fallthrough
	case 5:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		fallthrough
	case 4:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		fallthrough
	case 3:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		fallthrough
	case 2:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		fallthrough
	case 1:
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		block.Encrypt(
			tbl,
			dst[base:],
		)
		base += blocksize
		fallthrough
	case 0:
		xor.BytesSrc0(
			dst[base:],
			src[base:],
			tbl,
		)
	}
}

func decrypt(
	block cipher.Block,
	dst,
	src,
	buf []byte,
) {
	switch block.BlockSize() {
	case 8:
		decrypt8(
			block,
			dst,
			src,
			buf,
		)
	case 16:
		decrypt16(
			block,
			dst,
			src,
			buf,
		)
	default:
		decryptVariant(
			block,
			dst,
			src,
			buf,
		)
	}
}

func decrypt8(
	block cipher.Block,
	dst,
	src,
	buf []byte,
) {
	tbl := buf[0:8]
	next := buf[8:16]
	block.Encrypt(
		tbl,
		initialVector,
	)
	n := len(
		src,
	) / 8
	base := 0
	repeat := n / 8
	left := n % 8
	for i := 0; i < repeat; i++ {
		s := src[base:][0:64]
		d := dst[base:][0:64]
		block.Encrypt(
			next,
			s[0:8],
		)
		xor.BytesSrc1(
			d[0:8],
			s[0:8],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[8:16],
		)
		xor.BytesSrc1(
			d[8:16],
			s[8:16],
			next,
		)
		block.Encrypt(
			next,
			s[16:24],
		)
		xor.BytesSrc1(
			d[16:24],
			s[16:24],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[24:32],
		)
		xor.BytesSrc1(
			d[24:32],
			s[24:32],
			next,
		)
		block.Encrypt(
			next,
			s[32:40],
		)
		xor.BytesSrc1(
			d[32:40],
			s[32:40],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[40:48],
		)
		xor.BytesSrc1(
			d[40:48],
			s[40:48],
			next,
		)
		block.Encrypt(
			next,
			s[48:56],
		)
		xor.BytesSrc1(
			d[48:56],
			s[48:56],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[56:64],
		)
		xor.BytesSrc1(
			d[56:64],
			s[56:64],
			next,
		)
		base += 64
	}
	switch left {
	case 7:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 8
		fallthrough
	case 6:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 8
		fallthrough
	case 5:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl, next = next, tbl
		base += 8
		fallthrough
	case 4:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 8
		fallthrough
	case 3:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(dst[base:], src[base:], tbl)
		tbl, next = next, tbl
		base += 8
		fallthrough
	case 2:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 8
		fallthrough
	case 1:
		block.Encrypt(next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 8
		fallthrough
	case 0:
		xor.BytesSrc0(
			dst[base:],
			src[base:],
			tbl,
		)
	}
}

func decrypt16(
	block cipher.Block,
	dst,
	src,
	buf []byte,
) {
	tbl := buf[0:16]
	next := buf[16:32]
	block.Encrypt(
		tbl,
		initialVector,
	)
	n := len(
		src,
	) / 16
	base := 0
	repeat := n / 8
	left := n % 8
	for i := 0; i < repeat; i++ {
		s := src[base:][0:128]
		d := dst[base:][0:128]
		block.Encrypt(
			next,
			s[0:16],
		)
		xor.BytesSrc1(
			d[0:16],
			s[0:16],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[16:32],
		)
		xor.BytesSrc1(
			d[16:32],
			s[16:32],
			next,
		)
		block.Encrypt(
			next,
			s[32:48],
		)
		xor.BytesSrc1(
			d[32:48],
			s[32:48],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[48:64],
		)
		xor.BytesSrc1(
			d[48:64],
			s[48:64],
			next,
		)
		block.Encrypt(
			next,
			s[64:80],
		)
		xor.BytesSrc1(
			d[64:80],
			s[64:80],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[80:96],
		)
		xor.BytesSrc1(
			d[80:96],
			s[80:96],
			next,
		)
		block.Encrypt(
			next,
			s[96:112],
		)
		xor.BytesSrc1(
			d[96:112],
			s[96:112],
			tbl,
		)
		block.Encrypt(
			tbl,
			s[112:128],
		)
		xor.BytesSrc1(
			d[112:128],
			s[112:128],
			next,
		)
		base += 128
	}
	switch left {
	case 7:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 16
		fallthrough
	case 6:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl, next = next, tbl
		base += 16
		fallthrough
	case 5:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 16
		fallthrough
	case 4:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 16
		fallthrough
	case 3:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 16
		fallthrough
	case 2:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 16
		fallthrough
	case 1:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += 16
		fallthrough
	case 0:
		xor.BytesSrc0(
			dst[base:],
			src[base:],
			tbl,
		)
	}
}

func decryptVariant(
	block cipher.Block,
	dst,
	src,
	buf []byte,
) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	next := buf[blocksize:]
	block.Encrypt(
		tbl,
		initialVector,
	)
	n := len(
		src,
	) / blocksize
	base := 0
	repeat := n / 8
	left := n % 8
	for i := 0; i < repeat; i++ {
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		base += blocksize
		block.Encrypt(
			tbl,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			next,
		)
		base += blocksize
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		base += blocksize
		block.Encrypt(
			tbl,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			next,
		)
		base += blocksize
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		base += blocksize
		block.Encrypt(
			tbl,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			next,
		)
		base += blocksize
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		base += blocksize
		block.Encrypt(
			tbl,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			next,
		)
		base += blocksize
	}

	switch left {
	case 7:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += blocksize
		fallthrough
	case 6:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += blocksize
		fallthrough
	case 5:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl,
			next = next,
			tbl
		base += blocksize
		fallthrough
	case 4:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl, next = next, tbl
		base += blocksize
		fallthrough
	case 3:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl, next = next, tbl
		base += blocksize
		fallthrough
	case 2:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl, next = next, tbl
		base += blocksize
		fallthrough
	case 1:
		block.Encrypt(
			next,
			src[base:],
		)
		xor.BytesSrc1(
			dst[base:],
			src[base:],
			tbl,
		)
		tbl, next = next, tbl
		base += blocksize
		fallthrough
	case 0:
		xor.BytesSrc0(
			dst[base:],
			src[base:],
			tbl,
		)
	}
}
