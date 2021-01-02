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
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"io"
	"testing"

	hh "github.com/minio/highwayhash"

	"go.gridfinity.dev/lkcp9"

	u "go.gridfinity.dev/leaktestfe"
)

func TestNone(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	bc, err := lkcp9.NewNoneBlockCrypt(
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
		t.Log(
			fmt.Sprintf(
				"\n	enc=%v\n	dec=%v",
				enc,
				dec,
			),
		)
		t.Fail()
	}
}

func BenchmarkNone(
	b *testing.B,
) {
	bc, err := lkcp9.NewNoneBlockCrypt(
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
		int64(
			len(
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
	data := make(
		[]byte,
		hh.Size,
	)
	b.SetBytes(
		int64(
			len(
				data,
			),
		),
	)
	for i := 0; i < b.N; i++ {
		io.ReadFull(
			rand.Reader,
			data,
		)
	}
}

func BenchmarkCsprng(
	b *testing.B,
) {
	var data [hh.Size]byte
	b.SetBytes(
		hh.Size,
	)
	for i := 0; i < b.N; i++ {
		data = hh.Sum(
			data[:],
			data[:],
		)
	}
}

func BenchmarkCsprngKcpNonce(
	b *testing.B,
) {
	var ng lkcp9.KcpNonce
	ng.Init()
	b.SetBytes(
		hh.Size,
	)
	data := make(
		[]byte,
		hh.Size,
	)
	for i := 0; i < b.N; i++ {
		ng.Fill(
			data,
		)
	}
}
