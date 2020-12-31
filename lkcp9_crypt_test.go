// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.
// Copyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

package lkcp9_test

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"hash/crc32"
	"io"
	"testing"

	"go.gridfinity.dev/lkcp9"

	u "go.gridfinity.dev/leaktestfe"
)

func TestSM4(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	bc, err := lkcp9.NewSM4BlockCrypt(
		pass[:16],
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}
	cryptTest(
		t,
		bc,
	)
}

func TestAES(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	bc, err := lkcp9.NewAESBlockCrypt(
		pass[:32],
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}
	cryptTest(
		t,
		bc,
	)
}

func TestXOR(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	bc, err := lkcp9.NewSimpleXORBlockCrypt(
		pass[:32],
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}
	cryptTest(
		t,
		bc,
	)
}

func TestNone(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	bc, err := lkcp9.NewNoneBlockCrypt(pass[:32])
	if err != nil {
		t.Fatal(err)
	}
	cryptTest(
		t,
		bc,
	)
}

func TestSalsa20(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	bc, err := lkcp9.NewSalsa20BlockCrypt(
		pass[:32],
	)
	if err != nil {
		t.Fatal(
			err,
		)
	}
	cryptTest(
		t,
		bc,
	)
}

func cryptTest(
	t *testing.T,
	bc lkcp9.BlockCrypt,
) {
	defer u.Leakplug(
		t,
	)
	data := make(
		[]byte,
		lkcp9.KcpMtuLimit,
	)
	io.ReadFull(
		rand.Reader,
		data,
	)
	dec := make(
		[]byte,
		lkcp9.KcpMtuLimit,
	)
	enc := make(
		[]byte,
		lkcp9.KcpMtuLimit,
	)
	bc.Encrypt(
		enc,
		data,
	)
	bc.Decrypt(
		dec,
		enc,
	)
	if !bytes.Equal(
		data,
		dec,
	) {
		t.Fail()
	}
}

func BenchmarkSM4(b *testing.B) {
	bc, err := lkcp9.NewSM4BlockCrypt(pass[:16])
	if err != nil {
		b.Fatal(err)
	}
	benchCrypt(b, bc)
}

func BenchmarkAES128(b *testing.B) {
	bc, err := lkcp9.NewAESBlockCrypt(
		pass[:16],
	)
	if err != nil {
		b.Fatal(err)
	}
	benchCrypt(
		b,
		bc,
	)
}

func BenchmarkAES192(b *testing.B) {
	bc, err := lkcp9.NewAESBlockCrypt(
		pass[:24],
	)
	if err != nil {
		b.Fatal(
			err,
		)
	}
	benchCrypt(
		b,
		bc,
	)
}

func BenchmarkAES256(
	b *testing.B,
) {
	bc, err := lkcp9.NewAESBlockCrypt(
		pass[:32],
	)
	if err != nil {
		b.Fatal(
			err,
		)
	}
	benchCrypt(
		b,
		bc,
	)
}

func BenchmarkXOR(
	b *testing.B,
) {
	bc, err := lkcp9.NewSimpleXORBlockCrypt(
		pass[:32],
	)
	if err != nil {
		b.Fatal(
			err,
		)
	}
	benchCrypt(
		b,
		bc,
	)
}

func BenchmarkNone(
	b *testing.B,
) {
	bc, err := lkcp9.NewNoneBlockCrypt(
		pass[:32],
	)
	if err != nil {
		b.Fatal(err)
	}
	benchCrypt(
		b,
		bc,
	)
}

func BenchmarkSalsa20(b *testing.B) {
	bc, err := lkcp9.NewSalsa20BlockCrypt(pass[:32])
	if err != nil {
		b.Fatal(
			err,
		)
	}
	benchCrypt(
		b,
		bc,
	)
}

func benchCrypt(
	b *testing.B,
	bc lkcp9.BlockCrypt,
) {
	data := make(
		[]byte,
		lkcp9.KcpMtuLimit,
	)
	io.ReadFull(
		rand.Reader,
		data,
	)
	dec := make(
		[]byte,
		lkcp9.KcpMtuLimit,
	)
	enc := make(
		[]byte,
		lkcp9.KcpMtuLimit,
	)
	b.ReportAllocs()
	b.SetBytes(
		int64(len(
			enc,
		) * 2,
		),
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bc.Encrypt(
			enc,
			data,
		)
		bc.Decrypt(
			dec,
			enc,
		)
	}
}

func BenchmarkCRC32(
	b *testing.B,
) {
	content := make(
		[]byte,
		1024,
	)
	b.SetBytes(
		int64(
			len(
				content,
			),
		),
	)
	for i := 0; i < b.N; i++ {
		crc32.ChecksumIEEE(
			content,
		)
	}
}

func BenchmarkCsprngSystem(
	b *testing.B,
) {
	data := make([]byte, md5.Size)
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		io.ReadFull(rand.Reader, data)
	}
}

func BenchmarkCsprngMD5(b *testing.B) {
	var data [md5.Size]byte
	b.SetBytes(
		md5.Size,
	)
	for i := 0; i < b.N; i++ {
		data = md5.Sum(
			data[:],
		)
	}
}

func BenchmarkCsprngKcpNonceMD5(
	b *testing.B,
) {
	var ng lkcp9.KcpNonceMD5
	ng.Init()
	b.SetBytes(
		md5.Size,
	)
	data := make(
		[]byte,
		md5.Size,
	)
	for i := 0; i < b.N; i++ {
		ng.Fill(
			data,
		)
	}
}

func BenchmarkCsprngNonceAES128(
	b *testing.B,
) {
	var ng lkcp9.KcpNonceAES128
	ng.Init()
	b.SetBytes(
		aes.BlockSize,
	)
	data := make(
		[]byte,
		aes.BlockSize,
	)
	for i := 0; i < b.N; i++ {
		ng.Fill(
			data,
		)
	}
}
