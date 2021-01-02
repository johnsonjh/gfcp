// Package gfcp - A Fast and Reliable ARQ Protocol
//
// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.
// Copyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.
package gfcp // import "go.gridfinity.dev/gfcp"

import (
	"encoding/binary"
	"math"
	"runtime/debug"
	"sync/atomic"

	gfcpLegal "go4.org/legal"
)

// Gfcp protocol constants
const (
	GfcpRtoNdl     = 10  // GfcpRtoNdl:	NoDelay min RTO
	GfcpRtoMin     = 100 // GfcpRtoMin:	Regular min RTO
	GfcpRtoDef     = 250
	GfcpRtoMax     = 45000
	GfcpCmdPush    = 81 // GfcpCmdPush:	Push data
	GfcpCmdAck     = 82 // GfcpCmdAck:	Ack
	GfcpCmdWask    = 83 // GfcpCmdWask:	Get Window Size
	GfcpCmdWins    = 84 // GfcpCmdWins:	Set window Size
	GfcpAskSend    = 1  // GfcpAskSend:	Need to send GfcpCmdWask
	GfcpAskTell    = 2  // GfcpAskTell:	Need to send GfcpCmdWins
	GfcpWndSnd     = 64
	GfcpWndRcv     = 64
	GfcpMtuDef     = 1500
	GfcpAckFast    = 3
	GfcpInterval   = 70
	GfcpOverhead   = 24
	GfcpDeadLink   = 20
	GfcpThreshInit = 2
	GfcpThreshMin  = 1
	GfcpProbeInit  = 5000  // 5s initial probe window
	GfcpProbeLimit = 30000 // 30s hard probe timeout
)

type outputCallback func(
	buf []byte,
	size int,
)

func gfcpEncode8u(
	p []byte,
	c byte,
) []byte {
	p[0] = c
	return p[1:]
}

func gfcpDecode8u(
	p []byte,
	c *byte,
) []byte {
	*c = p[0]
	return p[1:]
}

func gfcpEncode16u(
	p []byte,
	w uint16,
) []byte {
	binary.LittleEndian.PutUint16(
		p,
		w,
	)
	return p[2:]
}

func gfcpDecode16u(
	p []byte,
	w *uint16,
) []byte {
	*w = binary.LittleEndian.Uint16(
		p,
	)
	return p[2:]
}

func gfcpEncode32u(
	p []byte,
	l uint32,
) []byte {
	binary.LittleEndian.PutUint32(
		p,
		l,
	)
	return p[4:]
}

func gfcpDecode32u(
	p []byte,
	l *uint32,
) []byte {
	*l = binary.LittleEndian.Uint32(
		p,
	)
	return p[4:]
}

func _imin(
	a,
	b uint32,
) uint32 {
	if a <= b {
		return a
	}
	return b
}

func _imax(
	a,
	b uint32,
) uint32 {
	if a >= b {
		return a
	}
	return b
}

func _ibound(
	lower,
	middle,
	upper uint32,
) uint32 {
	return _imin(
		_imax(
			lower,
			middle,
		),
		upper,
	)
}

func _itimediff(
	later,
	earlier uint32,
) int32 {
	return (int32)(later - earlier)
}

// GFcpSegment structure
type GFcpSegment struct {
	conv         uint32
	cmd          uint8
	frg          uint8
	wnd          uint16
	ts           uint32
	sn           uint32
	una          uint32
	rto          uint32
	Kxmit        uint32
	GFcpResendTs uint32
	fastack      uint32
	acked        uint32
	data         []byte
}

func (
	GFcpSeg *GFcpSegment,
) encode(
	ptr []byte,
) []byte {
	ptr = gfcpEncode32u(
		ptr,
		GFcpSeg.conv,
	)
	ptr = gfcpEncode8u(
		ptr,
		GFcpSeg.cmd,
	)
	ptr = gfcpEncode8u(
		ptr,
		GFcpSeg.frg,
	)
	ptr = gfcpEncode16u(
		ptr,
		GFcpSeg.wnd,
	)
	ptr = gfcpEncode32u(
		ptr,
		GFcpSeg.ts,
	)
	ptr = gfcpEncode32u(
		ptr,
		GFcpSeg.sn,
	)
	ptr = gfcpEncode32u(
		ptr,
		GFcpSeg.una,
	)
	ptr = gfcpEncode32u(
		ptr, uint32(len(
			GFcpSeg.data,
		)))
	atomic.AddUint64(
		&DefaultSnsi.GFcpOutputSegments,
		1,
	)
	return ptr
}

// GFCP primary structure
type GFCP struct {
	conv, mtu, mss, state               uint32
	sndUna, sndNxt, rcvNxt              uint32
	ssthresh                            uint32
	rxRttVar, rxSrtt                    int32
	rxRto, rxMinRto                     uint32
	sndWnd, rcvWnd, rmtWnd, cwnd, probe uint32
	interval, tsFlush                   uint32
	nodelay, updated                    uint32
	tsProbe, probeWait                  uint32
	deadLink, incr                      uint32
	fastresend                          int32
	nocwnd, stream                      int32
	sndQueue                            []GFcpSegment
	rcvQueue                            []GFcpSegment
	SndBuf                              []GFcpSegment
	rcvBuf                              []GFcpSegment
	acklist                             []ackItem
	buffer                              []byte
	reserved                            int
	output                              outputCallback
}

type ackItem struct {
	sn uint32
	ts uint32
}

// NewGFCP creates a new GFcp control object.
func NewGFCP(
	conv uint32,
	output outputCallback,
) *GFCP {
	GFcp := new(
		GFCP,
	)
	GFcp.conv = conv
	GFcp.sndWnd = GfcpWndSnd
	GFcp.rcvWnd = GfcpWndRcv
	GFcp.rmtWnd = GfcpWndRcv
	GFcp.mtu = GfcpMtuDef
	GFcp.mss = GFcp.mtu - GfcpOverhead
	GFcp.buffer = make(
		[]byte,
		GFcp.mtu,
	)
	GFcp.rxRto = GfcpRtoDef
	GFcp.rxMinRto = GfcpRtoMin
	GFcp.interval = GfcpInterval
	GFcp.tsFlush = GfcpInterval
	GFcp.ssthresh = GfcpThreshInit
	GFcp.deadLink = GfcpDeadLink
	GFcp.output = output
	return GFcp
}

func (
	GFcp *GFCP,
) newSegment(
	size int,
) (
	GFcpSeg GFcpSegment,
) {
	GFcpSeg.data = KxmitBuf.Get().([]byte)[:size]
	return
}

func (
	GFcp *GFCP,
) delSegment(
	GFcpSeg *GFcpSegment,
) {
	if GFcpSeg.data != nil {
		KxmitBuf.Put(
			// TODO(jhj): Switch to pointer to avoid allocation
			GFcpSeg.data,
		)
		GFcpSeg.data = nil
	}
}

// ReserveBytes keeps 'n' bytes from the beginning of buffering.
// Output callbacks use this to return 'false' if 'n' >= 'mss'.
func (
	GFcp *GFCP,
) ReserveBytes(
	n int,
) bool {
	if n >= int(
		GFcp.mtu-GfcpOverhead,
	) || n < 0 {
		return false
	}
	GFcp.reserved = n
	GFcp.mss = GFcp.mtu - GfcpOverhead - uint32(
		n,
	)
	return true
}

// PeekSize checks the size of next message in the receive queue.
func (
	GFcp *GFCP,
) PeekSize() (
	length int,
) {
	if len(
		GFcp.rcvQueue,
	) == 0 {
		return -1
	}
	GFcpSeg := &GFcp.rcvQueue[0]
	if GFcpSeg.frg == 0 {
		return len(
			GFcpSeg.data,
		)
	}
	if len(
		GFcp.rcvQueue,
	) < int(
		GFcpSeg.frg+1,
	) {
		return -1
	}
	for k := range GFcp.rcvQueue {
		GFcpSeg := &GFcp.rcvQueue[k]
		length += len(
			GFcpSeg.data,
		)
		if GFcpSeg.frg == 0 {
			break
		}
	}
	return
}

// Recv is upper level recviver; returns size or EAGAIN on error.
func (
	GFcp *GFCP,
) Recv(
	buffer []byte,
) (
	n int,
) {
	if len(
		GFcp.rcvQueue,
	) == 0 {
		return -1
	}
	peeksize := GFcp.PeekSize()
	if peeksize < 0 {
		return -2
	}
	if peeksize > len(
		buffer,
	) {
		return -3
	}
	var fastRecovery bool
	if len(
		GFcp.rcvQueue,
	) >= int(
		GFcp.rcvWnd,
	) {
		fastRecovery = true
	}
	count := 0
	for k := range GFcp.rcvQueue {
		GFcpSeg := &GFcp.rcvQueue[k]
		copy(
			buffer,
			GFcpSeg.data,
		)
		buffer = buffer[len(
			GFcpSeg.data,
		):]
		n += len(
			GFcpSeg.data,
		)
		count++
		GFcp.delSegment(
			GFcpSeg,
		)
		if GFcpSeg.frg == 0 {
			break
		}
	}
	if count > 0 {
		GFcp.rcvQueue = GFcp.removeFront(
			GFcp.rcvQueue,
			count,
		)
	}
	count = 0
	for k := range GFcp.rcvBuf {
		GFcpSeg := &GFcp.rcvBuf[k]
		if GFcpSeg.sn == GFcp.rcvNxt && len(
			GFcp.rcvQueue,
		) < int(
			GFcp.rcvWnd,
		) {
			GFcp.rcvNxt++
			count++
		} else {
			break
		}
	}
	if count > 0 {
		GFcp.rcvQueue = append(
			GFcp.rcvQueue,
			GFcp.rcvBuf[:count]...,
		)
		GFcp.rcvBuf = GFcp.removeFront(
			GFcp.rcvBuf,
			count,
		)
	}
	if len(
		GFcp.rcvQueue,
	) < int(
		GFcp.rcvWnd,
	) && fastRecovery {
		GFcp.probe |= GfcpAskTell
	}
	return
}

// Send is upper level sender, returns <0 on error.
func (
	GFcp *GFCP,
) Send(
	buffer []byte,
) int {
	var count int
	if len(
		buffer,
	) == 0 {
		return -1
	}
	if GFcp.stream != 0 {
		n := len(
			GFcp.sndQueue,
		)
		if n > 0 {
			GFcpSeg := &GFcp.sndQueue[n-1]
			if len(
				GFcpSeg.data,
			) < int(
				GFcp.mss,
			) {
				capacity := int(
					GFcp.mss,
				) - len(
					GFcpSeg.data,
				)
				extend := capacity
				if len(
					buffer,
				) < capacity {
					extend = len(
						buffer,
					)
				}
				oldlen := len(
					GFcpSeg.data,
				)
				GFcpSeg.data = GFcpSeg.data[:oldlen+extend]
				copy(
					GFcpSeg.data[oldlen:],
					buffer,
				)
				buffer = buffer[extend:]
			}
		}
		if len(
			buffer,
		) == 0 {
			return 0
		}
	}
	if len(
		buffer,
	) <= int(
		GFcp.mss,
	) {
		count = 1
	} else {
		count = (len(
			buffer,
		) + int(
			GFcp.mss,
		) - 1) / int(
			GFcp.mss,
		)
	}
	if count > 255 {
		return -2
	}
	if count == 0 {
		count = 1
	}
	for i := 0; i < count; i++ {
		var size int
		if len(
			buffer,
		) > int(
			GFcp.mss,
		) {
			size = int(
				GFcp.mss,
			)
		} else {
			size = len(
				buffer,
			)
		}
		GFcpSeg := GFcp.newSegment(
			size,
		)
		copy(
			GFcpSeg.data,
			buffer[:size],
		)
		if GFcp.stream == 0 {
			GFcpSeg.frg = uint8(
				count - i - 1,
			)
		} else {
			GFcpSeg.frg = 0
		}
		GFcp.sndQueue = append(
			GFcp.sndQueue,
			GFcpSeg,
		)
		buffer = buffer[size:]
	}
	return 0
}

func (
	GFcp *GFCP,
) updateAck(
	rtt int32,
) {
	var rto uint32
	if GFcp.rxSrtt == 0 {
		GFcp.rxSrtt = rtt
		GFcp.rxRttVar = rtt >> 1
	} else {
		delta := rtt - GFcp.rxSrtt
		GFcp.rxSrtt += delta >> 3
		if delta < 0 {
			delta = -delta
		}
		if rtt < GFcp.rxSrtt-GFcp.rxRttVar {
			GFcp.rxRttVar += (delta - GFcp.rxRttVar) >> 5
		} else {
			GFcp.rxRttVar += (delta - GFcp.rxRttVar) >> 2
		}
	}
	rto = uint32(
		GFcp.rxSrtt,
	) + _imax(
		GFcp.interval,
		uint32(
			GFcp.rxRttVar,
		)<<2)
	GFcp.rxRto = _ibound(
		GFcp.rxMinRto,
		rto,
		GfcpRtoMax,
	)
}

func (
	GFcp *GFCP,
) shrinkBuf() {
	if len(
		GFcp.SndBuf,
	) > 0 {
		GFcpSeg := &GFcp.SndBuf[0]
		GFcp.sndUna = GFcpSeg.sn
	} else {
		GFcp.sndUna = GFcp.sndNxt
	}
}

func (
	GFcp *GFCP,
) parseAck(
	sn uint32,
) {
	if _itimediff(
		sn,
		GFcp.sndUna,
	) < 0 || _itimediff(
		sn,
		GFcp.sndNxt,
	) >= 0 {
		return
	}

	for k := range GFcp.SndBuf {
		GFcpSeg := &GFcp.SndBuf[k]
		if sn == GFcpSeg.sn {
			GFcpSeg.acked = 1
			GFcp.delSegment(
				GFcpSeg,
			)
			break
		}
		if _itimediff(
			sn,
			GFcpSeg.sn,
		) < 0 {
			break
		}
	}
}

func (
	GFcp *GFCP,
) parseFastack(
	sn, ts uint32,
) {
	if _itimediff(
		sn,
		GFcp.sndUna,
	) < 0 || _itimediff(
		sn,
		GFcp.sndNxt,
	) >= 0 {
		return
	}
	for k := range GFcp.SndBuf {
		GFcpSeg := &GFcp.SndBuf[k]
		if _itimediff(
			sn,
			GFcpSeg.sn,
		) < 0 {
			break
		} else if sn != GFcpSeg.sn && _itimediff(
			GFcpSeg.ts,
			ts,
		) <= 0 {
			GFcpSeg.fastack++
		}
	}
}

func (
	GFcp *GFCP,
) parseUna(
	una uint32,
) {
	count := 0
	for k := range GFcp.SndBuf {
		GFcpSeg := &GFcp.SndBuf[k]
		if _itimediff(
			una,
			GFcpSeg.sn,
		) > 0 {
			GFcp.delSegment(
				GFcpSeg,
			)
			count++
		} else {
			break
		}
	}
	if count > 0 {
		GFcp.SndBuf = GFcp.removeFront(
			GFcp.SndBuf,
			count,
		)
	}
}

func (
	GFcp *GFCP,
) ackPush(
	sn,
	ts uint32,
) {
	GFcp.acklist = append(
		GFcp.acklist,
		ackItem{
			sn,
			ts,
		})
}

func (
	GFcp *GFCP,
) parseData(
	newGFcpSeg GFcpSegment,
) bool {
	sn := newGFcpSeg.sn
	if _itimediff(
		sn,
		GFcp.rcvNxt+GFcp.rcvWnd,
	) >= 0 ||
		_itimediff(
			sn,
			GFcp.rcvNxt,
		) < 0 {
		return true
	}

	n := len(
		GFcp.rcvBuf,
	) - 1
	insertIdx := 0
	repeat := false
	for i := n; i >= 0; i-- {
		GFcpSeg := &GFcp.rcvBuf[i]
		if GFcpSeg.sn == sn {
			repeat = true
			break
		}
		if _itimediff(
			sn,
			GFcpSeg.sn,
		) > 0 {
			insertIdx = i + 1
			break
		}
	}

	if !repeat {
		dataCopy := KxmitBuf.Get().([]byte)[:len(newGFcpSeg.data)]
		copy(
			dataCopy,
			newGFcpSeg.data,
		)
		newGFcpSeg.data = dataCopy

		if insertIdx == n+1 {
			GFcp.rcvBuf = append(
				GFcp.rcvBuf,
				newGFcpSeg,
			)
		} else {
			GFcp.rcvBuf = append(
				GFcp.rcvBuf,
				GFcpSegment{},
			)
			copy(
				GFcp.rcvBuf[insertIdx+1:],
				GFcp.rcvBuf[insertIdx:],
			)
			GFcp.rcvBuf[insertIdx] = newGFcpSeg
		}
	}
	count := 0
	for k := range GFcp.rcvBuf {
		GFcpSeg := &GFcp.rcvBuf[k]
		if GFcpSeg.sn == GFcp.rcvNxt && len(
			GFcp.rcvQueue,
		) < int(
			GFcp.rcvWnd,
		) {
			GFcp.rcvNxt++
			count++
		} else {
			break
		}
	}
	if count > 0 {
		GFcp.rcvQueue = append(
			GFcp.rcvQueue,
			GFcp.rcvBuf[:count]...,
		)
		GFcp.rcvBuf = GFcp.removeFront(
			GFcp.rcvBuf,
			count,
		)
	}
	return repeat
}

// Input receives a (low-level) UDP packet, and determinines if
// a complete packet has processsedd (not by the FEC algorithm.)
func (
	GFcp *GFCP,
) Input(
	data []byte,
	regular,
	ackNoDelay bool,
) int {
	sndUna := GFcp.sndUna
	if len(
		data,
	) < GfcpOverhead {
		return -1
	}
	var latest uint32
	var flag int
	var inSegs uint64
	for {
		var ts,
			sn,
			length,
			una,
			conv uint32
		var wnd uint16
		var cmd,
			frg uint8
		if len(
			data,
		) < int(
			GfcpOverhead,
		) {
			break
		}
		data = gfcpDecode32u(
			data,
			&conv,
		)
		if conv != GFcp.conv {
			return -1
		}
		data = gfcpDecode8u(
			data,
			&cmd,
		)
		data = gfcpDecode8u(
			data,
			&frg,
		)
		data = gfcpDecode16u(
			data,
			&wnd,
		)
		data = gfcpDecode32u(
			data,
			&ts,
		)
		data = gfcpDecode32u(
			data,
			&sn,
		)
		data = gfcpDecode32u(
			data,
			&una,
		)
		data = gfcpDecode32u(
			data,
			&length,
		)
		if len(
			data,
		) < int(
			length,
		) {
			return -2
		}
		if cmd != GfcpCmdPush && cmd != GfcpCmdAck &&
			cmd != GfcpCmdWask && cmd != GfcpCmdWins {
			return -3
		}
		if regular {
			GFcp.rmtWnd = uint32(
				wnd,
			)
		}
		GFcp.parseUna(
			una,
		)
		GFcp.shrinkBuf()
		if cmd == GfcpCmdAck {
			GFcp.parseAck(
				sn,
			)
			GFcp.parseFastack(
				sn,
				ts,
			)
			flag |= 1
			latest = ts
		} else if cmd == GfcpCmdPush {
			repeat := true
			if _itimediff(
				sn,
				GFcp.rcvNxt+GFcp.rcvWnd,
			) < 0 {
				GFcp.ackPush(
					sn,
					ts,
				)
				if _itimediff(
					sn,
					GFcp.rcvNxt,
				) >= 0 {
					var GFcpSeg GFcpSegment
					GFcpSeg.conv = conv
					GFcpSeg.cmd = cmd
					GFcpSeg.frg = frg
					GFcpSeg.wnd = wnd
					GFcpSeg.ts = ts
					GFcpSeg.sn = sn
					GFcpSeg.una = una
					GFcpSeg.data = data[:length]
					repeat = GFcp.parseData(
						GFcpSeg,
					)
				}
			}
			if regular && repeat {
				atomic.AddUint64(
					&DefaultSnsi.GFcpDupSegments,
					1,
				)
			}
		} else if cmd == GfcpCmdWask {
			GFcp.probe |= GfcpAskTell
			//} else if cmd == GfcpCmdWins {
			// XXX(jhj) ???
		} else {
			return -3
		}
		inSegs++
		data = data[length:]
	}
	atomic.AddUint64(
		&DefaultSnsi.GFcpInputSegments,
		inSegs,
	)
	if flag != 0 && regular {
		current := CurrentMs()
		if _itimediff(
			current,
			latest,
		) >= 0 {
			GFcp.updateAck(
				_itimediff(
					current,
					latest,
				),
			)
		}
	}
	if GFcp.nocwnd == 0 {
		if _itimediff(
			GFcp.sndUna,
			sndUna,
		) > 0 {
			if GFcp.cwnd < GFcp.rmtWnd {
				mss := GFcp.mss
				if GFcp.cwnd < GFcp.ssthresh {
					GFcp.cwnd++
					GFcp.incr += mss
				} else {
					if GFcp.incr < mss {
						GFcp.incr = mss
					}
					GFcp.incr += (mss*mss)/GFcp.incr + (mss / 16)
					if (GFcp.cwnd+1)*mss <= GFcp.incr {
						GFcp.cwnd++
					}
				}
				if GFcp.cwnd > GFcp.rmtWnd {
					GFcp.cwnd = GFcp.rmtWnd
					GFcp.incr = GFcp.rmtWnd * mss
				}
			}
		}
	}
	if ackNoDelay && len(
		GFcp.acklist,
	) > 0 {
		GFcp.Flush(
			true,
		)
	}
	return 0
}

func (
	GFcp *GFCP,
) wndUnused() uint16 {
	if len(
		GFcp.rcvQueue,
	) < int(GFcp.rcvWnd) {
		return uint16(
			int(
				GFcp.rcvWnd,
			) - len(
				GFcp.rcvQueue,
			),
		)
	}
	return 0
}

// Flush ...
func (
	GFcp *GFCP,
) Flush(
	ackOnly bool,
) uint32 {
	var GFcpSeg GFcpSegment
	GFcpSeg.conv = GFcp.conv
	GFcpSeg.cmd = GfcpCmdAck
	GFcpSeg.wnd = GFcp.wndUnused()
	GFcpSeg.una = GFcp.rcvNxt
	buffer := GFcp.buffer
	ptr := buffer[GFcp.reserved:]
	makeSpace := func(
		space int,
	) {
		size := len(
			buffer,
		) - len(
			ptr,
		)
		if size+space > int(
			GFcp.mtu,
		) {
			GFcp.output(
				buffer,
				size,
			)
			ptr = buffer[GFcp.reserved:]
		}
	}
	FlushBuffer := func() {
		size := len(
			buffer,
		) - len(
			ptr,
		)
		if size > GFcp.reserved {
			GFcp.output(
				buffer,
				size,
			)
		}
	}
	for i, ack := range GFcp.acklist {
		makeSpace(
			GfcpOverhead,
		)
		if ack.sn >= GFcp.rcvNxt || len(
			GFcp.acklist,
		)-1 == i {
			GFcpSeg.sn,
				GFcpSeg.ts = ack.sn,
				ack.ts
			ptr = GFcpSeg.encode(
				ptr,
			)
		}
	}
	GFcp.acklist = GFcp.acklist[0:0]
	if ackOnly {
		FlushBuffer()
		return GFcp.interval
	}
	if GFcp.rmtWnd == 0 {
		current := CurrentMs()
		if GFcp.probeWait == 0 {
			GFcp.probeWait = GfcpProbeInit
			GFcp.tsProbe = current + GFcp.probeWait
		} else if _itimediff(
			current,
			GFcp.tsProbe,
		) >= 0 {
			if GFcp.probeWait < GfcpProbeInit {
				GFcp.probeWait = GfcpProbeInit
			}
			GFcp.probeWait += GFcp.probeWait / 2
			if GFcp.probeWait > GfcpProbeLimit {
				GFcp.probeWait = GfcpProbeLimit
			}
			GFcp.tsProbe = current + GFcp.probeWait
			GFcp.probe |= GfcpAskSend
		}
	}
	GFcp.tsProbe = 0
	GFcp.probeWait = 0
	if (GFcp.probe & GfcpAskSend) != 0 {
		GFcpSeg.cmd = GfcpCmdWask
		makeSpace(
			GfcpOverhead,
		)
		ptr = GFcpSeg.encode(
			ptr,
		)
	}
	if (GFcp.probe & GfcpAskTell) != 0 {
		GFcpSeg.cmd = GfcpCmdWins
		makeSpace(
			GfcpOverhead,
		)
		ptr = GFcpSeg.encode(
			ptr,
		)
	}
	GFcp.probe = 0
	cwnd := _imin(
		GFcp.sndWnd,
		GFcp.rmtWnd,
	)
	if GFcp.nocwnd == 0 {
		cwnd = _imin(
			GFcp.cwnd,
			cwnd,
		)
	}
	newSegsCount := 0
	for k := range GFcp.sndQueue {
		if _itimediff(
			GFcp.sndNxt,
			GFcp.sndUna+cwnd,
		) >= 0 {
			break
		}
		newGFcpSeg := GFcp.sndQueue[k]
		newGFcpSeg.conv = GFcp.conv
		newGFcpSeg.cmd = GfcpCmdPush
		newGFcpSeg.sn = GFcp.sndNxt
		GFcp.SndBuf = append(
			GFcp.SndBuf,
			newGFcpSeg,
		)
		GFcp.sndNxt++
		newSegsCount++
	}
	if newSegsCount > 0 {
		GFcp.sndQueue = GFcp.removeFront(
			GFcp.sndQueue,
			newSegsCount,
		)
	}
	resent := uint32(
		GFcp.fastresend,
	)
	if GFcp.fastresend <= 0 {
		resent = 0xFFFFFFFF
	}
	current := CurrentMs()
	var change,
		lost,
		lostSegs,
		fastGFcpRestransmittedSegments,
		earlyGFcpRestransmittedSegments uint64
	minrto := int32(
		GFcp.interval,
	)
	ref := GFcp.SndBuf[:len(
		GFcp.SndBuf,
	)]
	for k := range ref {
		GFcpSegment := &ref[k]
		needsend := false
		if GFcpSegment.acked == 1 {
			continue
		}
		if GFcpSegment.Kxmit == 0 {
			needsend = true
			GFcpSegment.rto = GFcp.rxRto
			GFcpSegment.GFcpResendTs = current + GFcpSegment.rto
		} else if _itimediff(
			current,
			GFcpSegment.GFcpResendTs,
		) >= 0 {
			needsend = true
			if GFcp.nodelay == 0 {
				GFcpSegment.rto += GFcp.rxRto
			} else {
				GFcpSegment.rto += GFcp.rxRto / 2
			}
			GFcpSegment.GFcpResendTs = current + GFcpSegment.rto
			lost++
			lostSegs++
		} else if GFcpSegment.fastack >= resent {
			needsend = true
			GFcpSegment.fastack = 0
			GFcpSegment.rto = GFcp.rxRto
			GFcpSegment.GFcpResendTs = current + GFcpSegment.rto
			change++
			fastGFcpRestransmittedSegments++
		} else if GFcpSegment.fastack > 0 && newSegsCount == 0 {
			needsend = true
			GFcpSegment.fastack = 0
			GFcpSegment.rto = GFcp.rxRto
			GFcpSegment.GFcpResendTs = current + GFcpSegment.rto
			change++
			earlyGFcpRestransmittedSegments++
		}
		if needsend {
			current = CurrentMs()
			GFcpSegment.Kxmit++
			GFcpSegment.ts = current
			GFcpSegment.wnd = GFcpSeg.wnd
			GFcpSegment.una = GFcpSeg.una
			need := GfcpOverhead + len(
				GFcpSegment.data,
			)
			makeSpace(
				need,
			)
			ptr = GFcpSegment.encode(
				ptr,
			)
			copy(
				ptr,
				GFcpSegment.data,
			)
			ptr = ptr[len(
				GFcpSegment.data,
			):]
			if GFcpSegment.Kxmit >= GFcp.deadLink {
				GFcp.state = 0xFFFFFFFF
			}
		}
		if rto := _itimediff(
			GFcpSegment.GFcpResendTs,
			current,
		); rto > 0 && rto < minrto {
			minrto = rto
		}
	}
	FlushBuffer()
	sum := lostSegs
	if lostSegs > 0 {
		atomic.AddUint64(
			&DefaultSnsi.GFcpLostSegments,
			lostSegs,
		)
	}
	if fastGFcpRestransmittedSegments > 0 {
		atomic.AddUint64(
			&DefaultSnsi.FastGFcpRestransmittedSegments,
			fastGFcpRestransmittedSegments,
		)
		sum += fastGFcpRestransmittedSegments
	}
	if earlyGFcpRestransmittedSegments > 0 {
		atomic.AddUint64(
			&DefaultSnsi.EarlyGFcpRestransmittedSegments,
			earlyGFcpRestransmittedSegments,
		)
		sum += earlyGFcpRestransmittedSegments
	}
	if sum > 0 {
		atomic.AddUint64(
			&DefaultSnsi.GFcpRestransmittedSegments,
			sum,
		)
	}
	if GFcp.nocwnd == 0 {
		if change > 0 {
			inflight := GFcp.sndNxt - GFcp.sndUna
			GFcp.ssthresh = inflight / 2
			if GFcp.ssthresh < GfcpThreshMin {
				GFcp.ssthresh = GfcpThreshMin
			}
			GFcp.cwnd = GFcp.ssthresh + resent
			GFcp.incr = GFcp.cwnd * GFcp.mss
		}
		if lost > 0 {
			GFcp.ssthresh = cwnd / 2
			if GFcp.ssthresh < GfcpThreshMin {
				GFcp.ssthresh = GfcpThreshMin
			}
			GFcp.cwnd = 1
			GFcp.incr = GFcp.mss
		}

		if GFcp.cwnd < 1 {
			GFcp.cwnd = 1
			GFcp.incr = GFcp.mss
		}
	}
	return uint32(
		minrto,
	)
}

// Update is called repeatedly, 10ms to 100ms, queried via gfcp_check
// without gfcp_input or _send executing, returning timestamp in ms.
func (
	GFcp *GFCP,
) Update() {
	var slap int32
	current := CurrentMs()
	if GFcp.updated == 0 {
		GFcp.updated = 1
		GFcp.tsFlush = current
	}
	slap = _itimediff(
		current,
		GFcp.tsFlush,
	)
	if slap >= 10000 || slap < -10000 {
		GFcp.tsFlush = current
		slap = 0
	}
	if slap >= 0 {
		GFcp.tsFlush += GFcp.interval
		if _itimediff(
			current,
			GFcp.tsFlush,
		) >= 0 {
			GFcp.tsFlush = current + GFcp.interval
		}
		GFcp.Flush(
			false,
		)
	}
}

// Check function helps determine when to invoke an gfcp_update.
// It returns when you should invoke gfcp_update, in milliseconds,
// if there is no gfcp_input or _send calling. You may repeatdly
// call gfcp_update instead of update, to reduce most unnacessary
// gfcp_update invocations. This function may be used to schedule
// gfcp_updates, when implementing an epoll-like mechanism, or for
// optimizing an gfcp_update loop handling massive GFcp connections.
func (
	GFcp *GFCP,
) Check() uint32 {
	current := CurrentMs()
	tsFlush := GFcp.tsFlush
	tmFlush := int32(
		math.MaxInt32,
	)
	tmPacket := int32(
		math.MaxInt32,
	)
	minimal := uint32(
		0,
	)
	if GFcp.updated == 0 {
		return current
	}
	if _itimediff(
		current,
		tsFlush,
	) >= 10000 ||
		_itimediff(
			current,
			tsFlush,
		) < -10000 {
		tsFlush = current
	}
	if _itimediff(
		current,
		tsFlush,
	) >= 0 {
		return current
	}
	tmFlush = _itimediff(
		tsFlush,
		current,
	)
	for k := range GFcp.SndBuf {
		GFcpSeg := &GFcp.SndBuf[k]
		diff := _itimediff(
			GFcpSeg.GFcpResendTs,
			current,
		)
		if diff <= 0 {
			return current
		}
		if diff < tmPacket {
			tmPacket = diff
		}
	}
	minimal = uint32(
		tmPacket,
	)
	if tmPacket >= tmFlush {
		minimal = uint32(
			tmFlush,
		)
	}
	if minimal >= GFcp.interval {
		minimal = GFcp.interval
	}
	return current + minimal
}

// SetMtu changes MTU size.
// Defult MTU is 1400 byes.
func (
	GFcp *GFCP,
) SetMtu(
	mtu int,
) int {
	if mtu < 50 || mtu < GfcpOverhead {
		return -1
	}
	if GFcp.reserved >= int(
		GFcp.mtu-GfcpOverhead,
	) || GFcp.reserved < 0 {
		return -1
	}
	buffer := make(
		[]byte,
		mtu,
	)
	/*if buffer == nil {
		return -2
	}*/ // XXX(jhj): buffer can't be nil
	GFcp.mtu = uint32(
		mtu,
	)
	GFcp.mss = GFcp.mtu - GfcpOverhead - uint32(
		GFcp.reserved,
	)
	GFcp.buffer = buffer
	return 0
}

// NoDelay options:
// * fastest:	gfcp_nodelay(GFcp, 1, 20, 2, 1)
// * nodelay:	0: disable (default), 1: enable
// * interval:	internal update timer interval in milliseconds, defaults to 100ms
// * resend:	0: disable fast resends (default), 1: enable fast resends
// * nc:		0: normal congestion control (default), 1: disable congestion control
func (
	GFcp *GFCP,
) NoDelay(
	nodelay,
	interval,
	resend,
	nc int,
) int {
	if nodelay >= 0 {
		GFcp.nodelay = uint32(
			nodelay,
		)
		if nodelay != 0 {
			GFcp.rxMinRto = GfcpRtoNdl
		} else {
			GFcp.rxMinRto = GfcpRtoMin
		}
	}
	if interval >= 0 {
		if interval > 5000 {
			interval = 5000
		} else if interval < 10 {
			interval = 10
		}
		GFcp.interval = uint32(
			interval,
		)
	}
	if resend >= 0 {
		GFcp.fastresend = int32(
			resend,
		)
	}
	if nc >= 0 {
		GFcp.nocwnd = int32(
			nc,
		)
	}
	return 0
}

// WndSize sets maximum window size (efaults: sndwnd=32 and rcvwnd=32)
func (
	GFcp *GFCP,
) WndSize(
	sndwnd,
	rcvwnd int,
) int {
	if sndwnd > 0 {
		GFcp.sndWnd = uint32(
			sndwnd,
		)
	}
	if rcvwnd > 0 {
		GFcp.rcvWnd = uint32(
			rcvwnd,
		)
	}
	return 0
}

// WaitSnd shows how many packets are queued to be sent
func (
	GFcp *GFCP,
) WaitSnd() int {
	return len(
		GFcp.SndBuf,
	) + len(
		GFcp.sndQueue,
	)
}

func (
	GFcp *GFCP,
) removeFront(
	q []GFcpSegment,
	n int,
) []GFcpSegment {
	if n > cap(
		q,
	)/2 {
		newn := copy(
			q,
			q[n:],
		)
		return q[:newn]
	}
	return q[n:]
}

func init() {
	debug.SetGCPercent(
		180,
	)
	gfcpLegal.RegisterLicense(
		"\nThe MIT License (MIT)\n\nCopyright © 2015 Daniel Fu <daniel820313@gmail.com>.\nCopyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.\nCopyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.\nCopyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including, without limitation, the rights\nto use, copy, modify, merge, publish, distribute, sub-license, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice, and this permission notice, shall be\nincluded in all copies, or substantial portions, of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING, BUT NOT LIMITED TO, THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF, OR IN CONNECTION WITH THE SOFTWARE, OR THE USE OR OTHER DEALINGS IN\nTHE SOFTWARE.\n",
	)
}
