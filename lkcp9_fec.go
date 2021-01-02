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
	"encoding/binary"
	"sync/atomic"

	"github.com/klauspost/reedsolomon"
)

const (
	fecHeaderSize      = 6
	fecHeaderSizePlus2 = fecHeaderSize + 2
	// KTypeData ...
	KTypeData = 0xf1
	// KTypeParity ...
	KTypeParity = 0xf2
)

// FecPacket ...
type FecPacket []byte

func (
	bts FecPacket,
) seqid() uint32 {
	return binary.LittleEndian.Uint32(
		bts,
	)
}

func (
	bts FecPacket,
) flag() uint16 {
	return binary.LittleEndian.Uint16(
		bts[4:],
	)
}

func (bts FecPacket) data() []byte {
	return bts[6:]
}

// FecDecoder ...
type FecDecoder struct {
	rxlimit      int
	dataShards   int
	parityShards int
	shardSize    int
	rx           []FecPacket
	DecodeCache  [][]byte
	flagCache    []bool
	zeros        []byte
	codec        reedsolomon.Encoder
}

// KcpNewDECDecoder ...
func KcpNewDECDecoder(
	rxlimit,
	dataShards,
	parityShards int,
) *FecDecoder {
	if dataShards <= 0 || parityShards <= 0 {
		return nil
	}
	if rxlimit < dataShards+parityShards {
		return nil
	}

	dec := new(
		FecDecoder,
	)
	dec.rxlimit = rxlimit
	dec.dataShards = dataShards
	dec.parityShards = parityShards
	dec.shardSize = dataShards + parityShards
	codec, err := reedsolomon.New(
		dataShards,
		parityShards,
	)
	if err != nil {
		return nil
	}
	dec.codec = codec
	dec.DecodeCache = make(
		[][]byte,
		dec.shardSize,
	)
	dec.flagCache = make(
		[]bool,
		dec.shardSize,
	)
	dec.zeros = make(
		[]byte,
		KcpMtuLimit,
	)
	return dec
}

// Decode ...
func (dec *FecDecoder) Decode(in FecPacket) (recovered [][]byte) {
	n := len(dec.rx) - 1
	insertIdx := 0
	for i := n; i >= 0; i-- {
		if in.seqid() == dec.rx[i].seqid() {
			return nil
		} else if _itimediff(in.seqid(), dec.rx[i].seqid()) > 0 {
			insertIdx = i + 1
			break
		}
	}

	// make a copy
	pkt := FecPacket(KxmitBuf.Get().([]byte)[:len(in)])
	copy(pkt, in)

	if insertIdx == n+1 {
		dec.rx = append(dec.rx, pkt)
	} else {
		dec.rx = append(dec.rx, FecPacket{})
		copy(dec.rx[insertIdx+1:], dec.rx[insertIdx:])
		dec.rx[insertIdx] = pkt
	}

	shardBegin := pkt.seqid() - pkt.seqid()%uint32(dec.shardSize)
	shardEnd := shardBegin + uint32(dec.shardSize) - 1

	searchBegin := insertIdx - int(pkt.seqid()%uint32(dec.shardSize))
	if searchBegin < 0 {
		searchBegin = 0
	}
	searchEnd := searchBegin + dec.shardSize - 1
	if searchEnd >= len(dec.rx) {
		searchEnd = len(dec.rx) - 1
	}

	if searchEnd-searchBegin+1 >= dec.dataShards {
		var numshard, numDataShard, first, maxlen int

		shards := dec.DecodeCache
		shardsflag := dec.flagCache
		for k := range dec.DecodeCache {
			shards[k] = nil
			shardsflag[k] = false
		}

		for i := searchBegin; i <= searchEnd; i++ {
			seqid := dec.rx[i].seqid()
			if _itimediff(seqid, shardEnd) > 0 {
				break
			} else if _itimediff(seqid, shardBegin) >= 0 {
				shards[seqid%uint32(dec.shardSize)] = dec.rx[i].data()
				shardsflag[seqid%uint32(dec.shardSize)] = true
				numshard++
				if dec.rx[i].flag() == KTypeData {
					numDataShard++
				}
				if numshard == 1 {
					first = i
				}
				if len(dec.rx[i].data()) > maxlen {
					maxlen = len(dec.rx[i].data())
				}
			}
		}

		if numDataShard == dec.dataShards {
			dec.rx = dec.freeRange(first, numshard, dec.rx)
		} else if numshard >= dec.dataShards {
			for k := range shards {
				if shards[k] != nil {
					dlen := len(shards[k])
					shards[k] = shards[k][:maxlen]
					copy(shards[k][dlen:], dec.zeros)
				} else {
					shards[k] = KxmitBuf.Get().([]byte)[:0]
				}
			}
			if err := dec.codec.ReconstructData(shards); err == nil {
				for k := range shards[:dec.dataShards] {
					if !shardsflag[k] {
						recovered = append(recovered, shards[k])
					}
				}
			}
			dec.rx = dec.freeRange(first, numshard, dec.rx)
		}
	}

	if len(dec.rx) > dec.rxlimit {
		if dec.rx[0].flag() == KTypeData {
			atomic.AddUint64(&DefaultSnsi.KcpFECRuntShards, 1)
		}
		dec.rx = dec.freeRange(0, 1, dec.rx)
	}
	return
}

func (dec *FecDecoder) freeRange(first, n int, q []FecPacket) []FecPacket {
	for i := first; i < first+n; i++ {
		// TODO(jhj): Switch to pointer to avoid allocation.
		KxmitBuf.Put([]byte(q[i]))
	}

	if first == 0 && n < cap(q)/2 {
		return q[n:]
	}
	copy(q[first:], q[first+n:])
	return q[:len(q)-n]
}

type (
	// FecEncoder ...
	FecEncoder struct {
		dataShards    int
		parityShards  int
		shardSize     int
		paws          uint32 // Protect Against Wrapped Sequence numbers
		next          uint32 // next seqid
		shardCount    int    // count the number of datashards collected
		maxSize       int    // track maximum data length in datashard
		headerOffset  int    // FEC header offset
		payloadOffset int    // FEC payload offset
		shardCache    [][]byte
		EncodeCache   [][]byte
		zeros         []byte
		codec         reedsolomon.Encoder
	}
)

// KcpNewDECEncoder ...
func KcpNewDECEncoder(dataShards, parityShards, offset int) *FecEncoder {
	if dataShards <= 0 || parityShards <= 0 {
		return nil
	}
	enc := new(
		FecEncoder,
	)
	enc.dataShards = dataShards
	enc.parityShards = parityShards
	enc.shardSize = dataShards + parityShards
	enc.paws = (0xFFFFFFFF/uint32(enc.shardSize) - 1) * uint32(enc.shardSize)
	enc.headerOffset = offset
	enc.payloadOffset = enc.headerOffset + fecHeaderSize
	codec, err := reedsolomon.New(
		dataShards,
		parityShards,
	)
	if err != nil {
		return nil
	}
	enc.codec = codec
	enc.EncodeCache = make(
		[][]byte,
		enc.shardSize,
	)
	enc.shardCache = make(
		[][]byte,
		enc.shardSize,
	)
	for k := range enc.shardCache {
		enc.shardCache[k] = make(
			[]byte,
			KcpMtuLimit,
		)
	}
	enc.zeros = make(
		[]byte,
		KcpMtuLimit,
	)
	return enc
}

// Encode ...
func (
	enc *FecEncoder,
) Encode(
	b []byte,
) (
	ps [][]byte,
) {
	enc.markData(
		b[enc.headerOffset:],
	)
	binary.LittleEndian.PutUint16(b[enc.payloadOffset:], uint16(len(b[enc.payloadOffset:])))
	sz := len(
		b,
	)
	enc.shardCache[enc.shardCount] = enc.shardCache[enc.shardCount][:sz]
	copy(enc.shardCache[enc.shardCount][enc.payloadOffset:], b[enc.payloadOffset:])
	enc.shardCount++
	if sz > enc.maxSize {
		enc.maxSize = sz
	}
	if enc.shardCount == enc.dataShards {
		for i := 0; i < enc.dataShards; i++ {
			shard := enc.shardCache[i]
			slen := len(
				shard,
			)
			copy(
				shard[slen:enc.maxSize],
				enc.zeros,
			)
		}
		cache := enc.EncodeCache
		for k := range cache {
			cache[k] = enc.shardCache[k][enc.payloadOffset:enc.maxSize]
		}
		if err := enc.codec.Encode(
			cache,
		); err == nil {
			ps = enc.shardCache[enc.dataShards:]
			for k := range ps {
				enc.markParity(
					ps[k][enc.headerOffset:],
				)
				ps[k] = ps[k][:enc.maxSize]
			}
		}
		enc.shardCount = 0
		enc.maxSize = 0
	}
	return
}

func (enc *FecEncoder) markData(data []byte) {
	binary.LittleEndian.PutUint32(data, enc.next)
	binary.LittleEndian.PutUint16(data[4:], KTypeData)
	enc.next++
}

func (enc *FecEncoder) markParity(data []byte) {
	binary.LittleEndian.PutUint32(data, enc.next)
	binary.LittleEndian.PutUint16(data[4:], KTypeParity)
	enc.next = (enc.next + 1) % enc.paws
}
