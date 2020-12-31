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
	"encoding/binary"
	"math/rand"
	"testing"

	"go.gridfinity.dev/lkcp9"
)

func BenchmarkFECDecode(
	b *testing.B,
) {
	const (
		dataSize   = 10
		paritySize = 3
		payLoad    = 1500
	)
	decoder := lkcp9.KcpNewDECDecoder(
		1024,
		dataSize,
		paritySize,
	)
	b.ReportAllocs()
	b.SetBytes(
		payLoad,
	)
	for i := 0; i < b.N; i++ {
		if rand.Int()%(dataSize+paritySize) == 0 {
			continue
		}
		pkt := make(
			[]byte,
			payLoad,
		)
		binary.LittleEndian.PutUint32(
			pkt,
			uint32(i),
		)
		if i%(dataSize+paritySize) >= dataSize {
			binary.LittleEndian.PutUint16(
				pkt[4:],
				lkcp9.KTypeParity,
			)
		} else {
			binary.LittleEndian.PutUint16(
				pkt[4:],
				lkcp9.KTypeData,
			)
		}
		decoder.Decode(
			pkt,
		)
	}
}

func BenchmarkFECEncode(
	b *testing.B,
) {
	const dataSize = 10
	const paritySize = 3
	const payLoad = 1500
	b.ReportAllocs()
	b.SetBytes(
		payLoad,
	)
	Encoder := lkcp9.KcpNewDECEncoder(
		dataSize,
		paritySize,
		0,
	)
	for i := 0; i < b.N; i++ {
		data := make(
			[]byte,
			payLoad,
		)
		Encoder.Encode(
			data,
		)
	}
}
