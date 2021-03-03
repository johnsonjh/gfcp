// Copyright © 2021 Jeffrey H. Johnson <trnsz@pobox.com>.  
// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2021 Gridfinity, LLC. <admin@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

package gfcp_test

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"go.gridfinity.dev/gfcp"
)

func iclock() int32 {
	return int32(gfcp.CurrentMs())
}

type DelayPacket struct {
	_ptr  []byte
	_size int
	_ts   int32
}

func (
	p *DelayPacket,
) Init(
	size int,
	src []byte,
) {
	p._ptr = make(
		[]byte,
		size,
	)
	p._size = size
	copy(
		p._ptr,
		src[:size],
	)
}

func (
	p *DelayPacket,
) ptr() []byte {
	return p._ptr
}

func (
	p *DelayPacket,
) size() int {
	return p._size
}

func (
	p *DelayPacket,
) ts() int32 {
	return p._ts
}

func (
	p *DelayPacket,
) setts(
	ts int32,
) {
	p._ts = ts
}

type (
	DelayTunnel struct {
		*list.List
	}
	LatencySimulator struct {
		current  int32
		lostrate int
		rttmin   int
		rttmax   int
		nmax     int
		p12      DelayTunnel
		p21      DelayTunnel
		r12      *rand.Rand
		r21      *rand.Rand
	}
)

func (
	p *LatencySimulator,
) Init(
	lostrate,
	rttmin,
	rttmax,
	nmax int,
) {
	p.r12 = rand.New(
		rand.NewSource(
			9,
		),
	)
	p.r21 = rand.New(
		rand.NewSource(
			99,
		),
	)
	p.p12 = DelayTunnel{
		list.New(),
	}
	p.p21 = DelayTunnel{
		list.New(),
	}
	p.current = iclock()
	p.lostrate = (lostrate / 2)
	p.rttmin = (rttmin / 2)
	p.rttmax = (rttmax / 2)
	p.nmax = nmax
}

func (
	p *LatencySimulator,
) send(
	peer int,
	data []byte,
	size int,
) int {
	rnd := 0
	if peer == 0 {
		rnd = p.r12.Intn(
			100,
		)
	} else {
		rnd = p.r21.Intn(
			100,
		)
	}
	if rnd < p.lostrate {
		return 0
	}
	pkt := &DelayPacket{}
	pkt.Init(
		size,
		data,
	)
	p.current = iclock()
	delay := p.rttmin
	if p.rttmax > p.rttmin {
		delay += rand.Int() % (p.rttmax - p.rttmin)
	}
	pkt.setts(
		p.current + int32(
			delay,
		),
	)
	if peer == 0 {
		p.p12.PushBack(
			pkt,
		)
	} else {
		p.p21.PushBack(
			pkt,
		)
	}
	return 1
}

func (
	p *LatencySimulator,
) recv(
	peer int,
	data []byte,
	maxsize int,
) int32 {
	var it *list.Element
	if peer == 0 {
		it = p.p21.Front()
		if p.p21.Len() == 0 {
			return -1
		}
	} else {
		it = p.p12.Front()
		if p.p12.Len() == 0 {
			return -1
		}
	}
	pkt := it.Value.(*DelayPacket)
	p.current = iclock()
	if p.current < pkt.ts() {
		return -2
	}
	if maxsize < pkt.size() {
		return -3
	}
	if peer == 0 {
		p.p21.Remove(
			it,
		)
	} else {
		p.p12.Remove(
			it,
		)
	}
	maxsize = pkt.size()
	copy(
		data,
		pkt.ptr()[:maxsize],
	)
	return int32(maxsize)
}

var vnet *LatencySimulator

func test(
	mode int,
	t *testing.T,
) {
	vnet = &LatencySimulator{}
	vnet.Init(
		10,
		60,
		125,
		1000,
	)

	output1 := func(
		buf []byte,
		size int,
	) {
		if vnet.send(
			0,
			buf,
			size,
		) != 1 {
			t.Log(
				fmt.Sprintf(
					"\noutput[1]: vnet.send: size=%v",
					size,
				),
			)
		}
	}
	output2 := func(
		buf []byte,
		size int,
	) {
		if vnet.send(
			1,
			buf,
			size,
		) != 1 {
			t.Log(
				fmt.Sprintf(
					"\noutput[2]: vnet.send: size=%v",
					size,
				),
			)
		}
	}
	gfcp1 := gfcp.NewGFCP(
		0x11223344,
		output1,
	)
	gfcp2 := gfcp.NewGFCP(
		0x11223344,
		output2,
	)

	current := uint32(
		iclock(),
	)
	slap := current + 20
	index := 0
	next := 0
	var sumrtt uint32
	count := 0
	maxrtt := 0

	gfcp1.WndSize(
		128,
		128,
	)
	gfcp2.WndSize(
		128,
		128,
	)

	if mode == 0 {
		gfcp1.NoDelay(
			0,
			10,
			0,
			0,
		)
		gfcp2.NoDelay(
			0,
			10,
			0,
			0,
		)
	} else if mode == 1 {
		gfcp1.NoDelay(
			0,
			10,
			0,
			1,
		)
		gfcp2.NoDelay(
			0,
			10,
			0,
			1,
		)
	} else {
		gfcp1.NoDelay(
			1,
			10,
			2,
			1,
		)
		gfcp2.NoDelay(
			1,
			10,
			2,
			1,
		)
	}

	buffer := make(
		[]byte,
		2000,
	)
	var hr int32

	ts1 := iclock()

	for {
		time.Sleep(
			(1 * time.Millisecond),
		)
		current = uint32(
			iclock(),
		)
		gfcp1.Update()
		gfcp2.Update()

		for ; current >= slap; slap += 20 {
			buf := new(
				bytes.Buffer,
			)
			binary.Write(
				buf,
				binary.LittleEndian,
				uint32(
					index,
				),
			)
			index++
			binary.Write(
				buf,
				binary.LittleEndian,
				current,
			)
			gfcp1.Send(
				buf.Bytes(),
			)
		}

		for {
			hr = vnet.recv(
				1,
				buffer,
				2000,
			)
			if hr < 0 {
				break
			}
			gfcp2.Input(
				buffer[:hr],
				true,
				false,
			)
		}

		for {
			hr = vnet.recv(
				0,
				buffer,
				2000,
			)
			if hr < 0 {
				break
			}
			gfcp1.Input(
				buffer[:hr],
				true,
				false,
			)
		}

		for {
			hr = int32(
				gfcp2.Recv(
					buffer[:10],
				),
			)
			if hr < 0 {
				break
			}
			buf := bytes.NewReader(
				buffer,
			)
			var sn uint32
			binary.Read(
				buf,
				binary.LittleEndian,
				&sn,
			)
			gfcp2.Send(
				buffer[:hr],
			)
		}

		for {
			hr = int32(
				gfcp1.Recv(
					buffer[:10],
				),
			)
			buf := bytes.NewReader(
				buffer,
			)
			if hr < 0 {
				break
			}
			var ts, sn, rtt uint32
			binary.Read(
				buf,
				binary.LittleEndian,
				&sn,
			)
			binary.Read(
				buf,
				binary.LittleEndian,
				&ts,
			)
			rtt = (current - ts)

			if sn != uint32(
				next,
			) {
				println(
					"ERROR sn ",
					count,
					"<->",
					next,
					sn,
				)
				return
			}

			next++
			sumrtt += rtt
			count++
			if rtt > uint32(
				maxrtt,
			) {
				maxrtt = int(
					rtt,
				)
			}

		}

		if next > 100 {
			break
		}
	}

	ts1 = iclock() - ts1

	names := []string{
		"=== Test 1/3:\tConfiguration: Default",
		"=== Test 2/3:\tConfiguration: Regular",
		"=== Test 3/3:\tConfiguration: Tweaked",
	}
	fmt.Printf(
		"\n%s\n\t\tElapsed Time:\t%d ms",
		names[mode],
		ts1,
	)
	fmt.Printf(
		"\n\t\tAverage RTT:\t%d ms\n\t\tMaximum RTT:\t%d ms\n",
		int(sumrtt/uint32(count)),
		maxrtt,
	)
}

func TestNetwork(
	t *testing.T,
) {
	test(
		0,
		t,
	)
	test(
		1,
		t,
	)
	test(
		2,
		t,
	)
}

func BenchmarkFlush(
	b *testing.B,
) {
	GFcp := gfcp.NewGFCP(
		1,
		func(
			buf []byte,
			size int,
		) {
		})
	GFcp.SndBuf = make(
		[]gfcp.Segment,
		2048,
	)
	for k := range GFcp.SndBuf {
		GFcp.SndBuf[k].Kxmit = 1
		GFcp.SndBuf[k].GFcpResendTs = gfcp.CurrentMs() + 1000
	}
	b.ResetTimer()
	b.ReportAllocs()
	var mu sync.Mutex
	for i := 0; i < b.N; i++ {
		mu.Lock()
		GFcp.Flush(
			false,
		)
		mu.Unlock()
	}
}
