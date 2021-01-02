// Package lkcp9 - A Fast and Reliable ARQ Protocol
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
package lkcp9 // import "go.gridfinity.dev/lkcp9"

import (
	"encoding/binary"
	"math"
	"runtime"
	"sync/atomic"

	lkcp9Legal "go4.org/legal"
)

// IKcp9 protocol constants
const (
	IKcpRtoNdl     = 20 // IKcpRtoNdl:	NoDelay min RTO
	IKcpRtoMin     = 90 // IKcpRtoMin:	Regular min RTO
	IKcpRtoDef     = 150
	IKcpRtoMax     = 45000
	IKcpCmdPush    = 81 // IKcpCmdPush:	Push data
	IKcpCmdAck     = 82 // IKcpCmdAck:	Ack
	IKcpCmdWask    = 83 // IKcpCmdWask:	Get Window Size
	IKcpCmdWins    = 84 // IKcpCmdWins:	Set window Size
	IKcpAskSend    = 1  // IKcpAskSend:	Need to send IKcpCmdWask
	IKcpAskTell    = 2  // IKcpAskTell:	Need to send IKcpCmdWins
	IKcpWndSnd     = 32
	IKcpWndRcv     = 32
	IKcpMtuDef     = 9000
	IKcpAckFast    = 3
	IKcpInterval   = 100
	IKcpOverhead   = 24
	IKcpDeadLink   = 20
	IKcpThreshInit = 2
	IKcpThreshMin  = 2
	IKcpProbeInit  = 5000  // 5s initial probe window
	IKcpProbeLimit = 60000 // 60s hard probe timeout
)

type outputCallback func(
	buf []byte,
	size int,
)

func iKcpEncode8u(
	p []byte,
	c byte,
) []byte {
	p[0] = c
	return p[1:]
}

func iKcpDecode8u(
	p []byte,
	c *byte,
) []byte {
	*c = p[0]
	return p[1:]
}

func iKcpEncode16u(
	p []byte,
	w uint16,
) []byte {
	binary.LittleEndian.PutUint16(
		p,
		w,
	)
	return p[2:]
}

func iKcpDecode16u(
	p []byte,
	w *uint16,
) []byte {
	*w = binary.LittleEndian.Uint16(
		p,
	)
	return p[2:]
}

func iKcpEncode32u(
	p []byte,
	l uint32,
) []byte {
	binary.LittleEndian.PutUint32(
		p,
		l,
	)
	return p[4:]
}

func iKcpDecode32u(
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

// KcpSegment structure
type KcpSegment struct {
	conv        uint32
	cmd         uint8
	frg         uint8
	wnd         uint16
	ts          uint32
	sn          uint32
	una         uint32
	rto         uint32
	Kxmit       uint32
	KcpResendTs uint32
	fastack     uint32
	acked       uint32
	data        []byte
}

func (
	KcpSeg *KcpSegment,
) encode(
	ptr []byte,
) []byte {
	ptr = iKcpEncode32u(
		ptr,
		KcpSeg.conv,
	)
	ptr = iKcpEncode8u(
		ptr,
		KcpSeg.cmd,
	)
	ptr = iKcpEncode8u(
		ptr,
		KcpSeg.frg,
	)
	ptr = iKcpEncode16u(
		ptr,
		KcpSeg.wnd,
	)
	ptr = iKcpEncode32u(
		ptr,
		KcpSeg.ts,
	)
	ptr = iKcpEncode32u(
		ptr,
		KcpSeg.sn,
	)
	ptr = iKcpEncode32u(
		ptr,
		KcpSeg.una,
	)
	ptr = iKcpEncode32u(
		ptr, uint32(len(
			KcpSeg.data,
		)))
	atomic.AddUint64(
		&DefaultSnsi.KcpOutputSegments,
		1,
	)
	return ptr
}

// KCP primary structure
type KCP struct {
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
	sndQueue                            []KcpSegment
	rcvQueue                            []KcpSegment
	SndBuf                              []KcpSegment
	rcvBuf                              []KcpSegment
	acklist                             []ackItem
	buffer                              []byte
	reserved                            int
	output                              outputCallback
}

type ackItem struct {
	sn uint32
	ts uint32
}

// NewKCP creates a new Kcp control object.
func NewKCP(
	conv uint32,
	output outputCallback,
) *KCP {
	Kcp := new(
		KCP,
	)
	Kcp.conv = conv
	Kcp.sndWnd = IKcpWndSnd
	Kcp.rcvWnd = IKcpWndRcv
	Kcp.rmtWnd = IKcpWndRcv
	Kcp.mtu = IKcpMtuDef
	Kcp.mss = Kcp.mtu - IKcpOverhead
	Kcp.buffer = make(
		[]byte,
		Kcp.mtu,
	)
	Kcp.rxRto = IKcpRtoDef
	Kcp.rxMinRto = IKcpRtoMin
	Kcp.interval = IKcpInterval
	Kcp.tsFlush = IKcpInterval
	Kcp.ssthresh = IKcpThreshInit
	Kcp.deadLink = IKcpDeadLink
	Kcp.output = output
	return Kcp
}

func (
	Kcp *KCP,
) newSegment(
	size int,
) (
	KcpSeg KcpSegment,
) {
	KcpSeg.data = KxmitBuf.Get().([]byte)[:size]
	return
}

func (Kcp *KCP) delSegment(
	KcpSeg *KcpSegment,
) {
	if KcpSeg.data != nil {
		KxmitBuf.Put(
			// TODO(jhj): Switch to pointer to avoid allocation
			KcpSeg.data,
		)
		KcpSeg.data = nil
	}
}

// ReserveBytes keeps 'n' bytes from the beginning of buffering.
// Output callbacks use this to return 'false' if 'n' >= 'mss'.
func (
	Kcp *KCP,
) ReserveBytes(
	n int,
) bool {
	if n >= int(
		Kcp.mtu-IKcpOverhead,
	) || n < 0 {
		return false
	}
	Kcp.reserved = n
	Kcp.mss = Kcp.mtu - IKcpOverhead - uint32(
		n,
	)
	return true
}

// PeekSize checks the size of next message in the receive queue.
func (
	Kcp *KCP,
) PeekSize() (
	length int,
) {
	if len(
		Kcp.rcvQueue,
	) == 0 {
		return -1
	}
	KcpSeg := &Kcp.rcvQueue[0]
	if KcpSeg.frg == 0 {
		return len(
			KcpSeg.data,
		)
	}
	if len(
		Kcp.rcvQueue,
	) < int(KcpSeg.frg+1) {
		return -1
	}
	for k := range Kcp.rcvQueue {
		KcpSeg := &Kcp.rcvQueue[k]
		length += len(
			KcpSeg.data,
		)
		if KcpSeg.frg == 0 {
			break
		}
	}
	return
}

// Recv is upper level recviver; returns size or EAGAIN on error.
func (
	Kcp *KCP,
) Recv(
	buffer []byte,
) (
	n int,
) {
	if len(
		Kcp.rcvQueue,
	) == 0 {
		return -1
	}
	peeksize := Kcp.PeekSize()
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
		Kcp.rcvQueue,
	) >= int(
		Kcp.rcvWnd,
	) {
		fastRecovery = true
	}
	count := 0
	for k := range Kcp.rcvQueue {
		KcpSeg := &Kcp.rcvQueue[k]
		copy(
			buffer,
			KcpSeg.data,
		)
		buffer = buffer[len(KcpSeg.data):]
		n += len(
			KcpSeg.data,
		)
		count++
		Kcp.delSegment(
			KcpSeg,
		)
		if KcpSeg.frg == 0 {
			break
		}
	}
	if count > 0 {
		Kcp.rcvQueue = Kcp.removeFront(
			Kcp.rcvQueue,
			count,
		)
	}
	count = 0
	for k := range Kcp.rcvBuf {
		KcpSeg := &Kcp.rcvBuf[k]
		if KcpSeg.sn == Kcp.rcvNxt && len(
			Kcp.rcvQueue,
		) < int(Kcp.rcvWnd) {
			Kcp.rcvNxt++
			count++
		} else {
			break
		}
	}
	if count > 0 {
		Kcp.rcvQueue = append(
			Kcp.rcvQueue,
			Kcp.rcvBuf[:count]...,
		)
		Kcp.rcvBuf = Kcp.removeFront(
			Kcp.rcvBuf,
			count,
		)
	}
	if len(
		Kcp.rcvQueue,
	) < int(Kcp.rcvWnd) && fastRecovery {
		Kcp.probe |= IKcpAskTell
	}
	return
}

// Send is upper level sender, returns <0 on error.
func (
	Kcp *KCP,
) Send(
	buffer []byte,
) int {
	var count int
	if len(
		buffer,
	) == 0 {
		return -1
	}
	if Kcp.stream != 0 {
		n := len(
			Kcp.sndQueue,
		)
		if n > 0 {
			KcpSeg := &Kcp.sndQueue[n-1]
			if len(KcpSeg.data) < int(Kcp.mss) {
				capacity := int(Kcp.mss) - len(
					KcpSeg.data,
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
					KcpSeg.data,
				)
				KcpSeg.data = KcpSeg.data[:oldlen+extend]
				copy(KcpSeg.data[oldlen:], buffer)
				buffer = buffer[extend:]
			}
		}
		if len(buffer) == 0 {
			return 0
		}
	}
	if len(buffer) <= int(Kcp.mss) {
		count = 1
	} else {
		count = (len(
			buffer,
		) + int(Kcp.mss) - 1) / int(Kcp.mss)
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
			Kcp.mss,
		) {
			size = int(
				Kcp.mss,
			)
		} else {
			size = len(
				buffer,
			)
		}
		KcpSeg := Kcp.newSegment(
			size,
		)
		copy(
			KcpSeg.data,
			buffer[:size],
		)
		if Kcp.stream == 0 {
			KcpSeg.frg = uint8(
				count - i - 1,
			)
		} else {
			KcpSeg.frg = 0
		}
		Kcp.sndQueue = append(
			Kcp.sndQueue,
			KcpSeg,
		)
		buffer = buffer[size:]
	}
	return 0
}

func (
	Kcp *KCP,
) updateAck(
	rtt int32,
) {
	var rto uint32
	if Kcp.rxSrtt == 0 {
		Kcp.rxSrtt = rtt
		Kcp.rxRttVar = rtt >> 1
	} else {
		delta := rtt - Kcp.rxSrtt
		Kcp.rxSrtt += delta >> 3
		if delta < 0 {
			delta = -delta
		}
		if rtt < Kcp.rxSrtt-Kcp.rxRttVar {
			Kcp.rxRttVar += (delta - Kcp.rxRttVar) >> 5
		} else {
			Kcp.rxRttVar += (delta - Kcp.rxRttVar) >> 2
		}
	}
	rto = uint32(
		Kcp.rxSrtt,
	) + _imax(
		Kcp.interval,
		uint32(Kcp.rxRttVar)<<2)
	Kcp.rxRto = _ibound(
		Kcp.rxMinRto,
		rto,
		IKcpRtoMax,
	)
}

func (
	Kcp *KCP,
) shrinkBuf() {
	if len(
		Kcp.SndBuf,
	) > 0 {
		KcpSeg := &Kcp.SndBuf[0]
		Kcp.sndUna = KcpSeg.sn
	} else {
		Kcp.sndUna = Kcp.sndNxt
	}
}

func (
	Kcp *KCP,
) parseAck(
	sn uint32,
) {
	if _itimediff(
		sn,
		Kcp.sndUna,
	) < 0 || _itimediff(
		sn,
		Kcp.sndNxt,
	) >= 0 {
		return
	}

	for k := range Kcp.SndBuf {
		KcpSeg := &Kcp.SndBuf[k]
		if sn == KcpSeg.sn {
			KcpSeg.acked = 1
			Kcp.delSegment(
				KcpSeg,
			)
			break
		}
		if _itimediff(
			sn,
			KcpSeg.sn,
		) < 0 {
			break
		}
	}
}

func (
	Kcp *KCP,
) parseFastack(
	sn, ts uint32,
) {
	if _itimediff(
		sn,
		Kcp.sndUna,
	) < 0 || _itimediff(
		sn,
		Kcp.sndNxt,
	) >= 0 {
		return
	}
	for k := range Kcp.SndBuf {
		KcpSeg := &Kcp.SndBuf[k]
		if _itimediff(
			sn,
			KcpSeg.sn,
		) < 0 {
			break
		} else if sn != KcpSeg.sn && _itimediff(
			KcpSeg.ts,
			ts,
		) <= 0 {
			KcpSeg.fastack++
		}
	}
}

func (
	Kcp *KCP,
) parseUna(
	una uint32,
) {
	count := 0
	for k := range Kcp.SndBuf {
		KcpSeg := &Kcp.SndBuf[k]
		if _itimediff(
			una,
			KcpSeg.sn,
		) > 0 {
			Kcp.delSegment(
				KcpSeg,
			)
			count++
		} else {
			break
		}
	}
	if count > 0 {
		Kcp.SndBuf = Kcp.removeFront(
			Kcp.SndBuf,
			count,
		)
	}
}

func (
	Kcp *KCP,
) ackPush(
	sn,
	ts uint32,
) {
	Kcp.acklist = append(
		Kcp.acklist,
		ackItem{
			sn,
			ts,
		})
}

func (
	Kcp *KCP,
) parseData(
	newKcpSeg KcpSegment,
) bool {
	sn := newKcpSeg.sn
	if _itimediff(
		sn,
		Kcp.rcvNxt+Kcp.rcvWnd,
	) >= 0 ||
		_itimediff(
			sn,
			Kcp.rcvNxt,
		) < 0 {
		return true
	}

	n := len(
		Kcp.rcvBuf,
	) - 1
	insertIdx := 0
	repeat := false
	for i := n; i >= 0; i-- {
		KcpSeg := &Kcp.rcvBuf[i]
		if KcpSeg.sn == sn {
			repeat = true
			break
		}
		if _itimediff(
			sn,
			KcpSeg.sn,
		) > 0 {
			insertIdx = i + 1
			break
		}
	}

	if !repeat {
		dataCopy := KxmitBuf.Get().([]byte)[:len(
			newKcpSeg.data,
		)]
		copy(
			dataCopy,
			newKcpSeg.data,
		)
		newKcpSeg.data = dataCopy

		if insertIdx == n+1 {
			Kcp.rcvBuf = append(
				Kcp.rcvBuf,
				newKcpSeg,
			)
		} else {
			Kcp.rcvBuf = append(
				Kcp.rcvBuf,
				KcpSegment{},
			)
			copy(
				Kcp.rcvBuf[insertIdx+1:],
				Kcp.rcvBuf[insertIdx:],
			)
			Kcp.rcvBuf[insertIdx] = newKcpSeg
		}
	}
	count := 0
	for k := range Kcp.rcvBuf {
		KcpSeg := &Kcp.rcvBuf[k]
		if KcpSeg.sn == Kcp.rcvNxt && len(
			Kcp.rcvQueue,
		) < int(Kcp.rcvWnd) {
			Kcp.rcvNxt++
			count++
		} else {
			break
		}
	}
	if count > 0 {
		Kcp.rcvQueue = append(
			Kcp.rcvQueue,
			Kcp.rcvBuf[:count]...,
		)
		Kcp.rcvBuf = Kcp.removeFront(
			Kcp.rcvBuf,
			count,
		)
	}
	return repeat
}

// Input receives a (low-level) UDP packet, and determinines if
// a complete packet has processsedd (not by the FEC algorithm.)
func (
	Kcp *KCP,
) Input(
	data []byte,
	regular,
	ackNoDelay bool,
) int {
	sndUna := Kcp.sndUna
	if len(
		data,
	) < IKcpOverhead {
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
		) < int(IKcpOverhead) {
			break
		}
		data = iKcpDecode32u(
			data,
			&conv,
		)
		if conv != Kcp.conv {
			return -1
		}
		data = iKcpDecode8u(
			data,
			&cmd,
		)
		data = iKcpDecode8u(
			data,
			&frg,
		)
		data = iKcpDecode16u(
			data,
			&wnd,
		)
		data = iKcpDecode32u(
			data,
			&ts,
		)
		data = iKcpDecode32u(
			data,
			&sn,
		)
		data = iKcpDecode32u(
			data,
			&una,
		)
		data = iKcpDecode32u(
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
		if cmd != IKcpCmdPush && cmd != IKcpCmdAck &&
			cmd != IKcpCmdWask && cmd != IKcpCmdWins {
			return -3
		}
		if regular {
			Kcp.rmtWnd = uint32(wnd)
		}
		Kcp.parseUna(
			una,
		)
		Kcp.shrinkBuf()
		if cmd == IKcpCmdAck {
			Kcp.parseAck(
				sn,
			)
			Kcp.parseFastack(
				sn,
				ts,
			)
			flag |= 1
			latest = ts
		} else if cmd == IKcpCmdPush {
			repeat := true
			if _itimediff(
				sn,
				Kcp.rcvNxt+Kcp.rcvWnd,
			) < 0 {
				Kcp.ackPush(
					sn,
					ts,
				)
				if _itimediff(
					sn,
					Kcp.rcvNxt,
				) >= 0 {
					var KcpSeg KcpSegment
					KcpSeg.conv = conv
					KcpSeg.cmd = cmd
					KcpSeg.frg = frg
					KcpSeg.wnd = wnd
					KcpSeg.ts = ts
					KcpSeg.sn = sn
					KcpSeg.una = una
					KcpSeg.data = data[:length]
					repeat = Kcp.parseData(
						KcpSeg,
					)
				}
			}
			if regular && repeat {
				atomic.AddUint64(
					&DefaultSnsi.DuplicateSegments,
					1,
				)
			}
		} else if cmd == IKcpCmdWask {
			Kcp.probe |= IKcpAskTell
			//} else if cmd == IKcpCmdWins {
			// XXX(jhj) ???
		} else {
			return -3
		}
		inSegs++
		data = data[length:]
	}
	atomic.AddUint64(
		&DefaultSnsi.KcpInputSegments,
		inSegs,
	)
	if flag != 0 && regular {
		current := KcpCurrentMs()
		if _itimediff(
			current,
			latest,
		) >= 0 {
			Kcp.updateAck(
				_itimediff(
					current,
					latest,
				),
			)
		}
	}
	if Kcp.nocwnd == 0 {
		if _itimediff(
			Kcp.sndUna,
			sndUna,
		) > 0 {
			if Kcp.cwnd < Kcp.rmtWnd {
				mss := Kcp.mss
				if Kcp.cwnd < Kcp.ssthresh {
					Kcp.cwnd++
					Kcp.incr += mss
				} else {
					if Kcp.incr < mss {
						Kcp.incr = mss
					}
					Kcp.incr += (mss*mss)/Kcp.incr + (mss / 16)
					if (Kcp.cwnd+1)*mss <= Kcp.incr {
						Kcp.cwnd++
					}
				}
				if Kcp.cwnd > Kcp.rmtWnd {
					Kcp.cwnd = Kcp.rmtWnd
					Kcp.incr = Kcp.rmtWnd * mss
				}
			}
		}
	}
	if ackNoDelay && len(
		Kcp.acklist,
	) > 0 {
		Kcp.Flush(
			true,
		)
	}
	return 0
}

func (
	Kcp *KCP,
) wndUnused() uint16 {
	if len(
		Kcp.rcvQueue,
	) < int(Kcp.rcvWnd) {
		return uint16(int(Kcp.rcvWnd) - len(
			Kcp.rcvQueue,
		),
		)
	}
	return 0
}

// Flush ...
func (
	Kcp *KCP,
) Flush(
	ackOnly bool,
) uint32 {
	var KcpSeg KcpSegment
	KcpSeg.conv = Kcp.conv
	KcpSeg.cmd = IKcpCmdAck
	KcpSeg.wnd = Kcp.wndUnused()
	KcpSeg.una = Kcp.rcvNxt
	buffer := Kcp.buffer
	ptr := buffer[Kcp.reserved:]
	makeSpace := func(
		space int,
	) {
		size := len(
			buffer,
		) - len(
			ptr,
		)
		if size+space > int(Kcp.mtu) {
			Kcp.output(
				buffer,
				size,
			)
			ptr = buffer[Kcp.reserved:]
		}
	}
	FlushBuffer := func() {
		size := len(
			buffer,
		) - len(
			ptr,
		)
		if size > Kcp.reserved {
			Kcp.output(
				buffer,
				size,
			)
		}
	}
	for i, ack := range Kcp.acklist {
		makeSpace(
			IKcpOverhead,
		)
		if ack.sn >= Kcp.rcvNxt || len(
			Kcp.acklist,
		)-1 == i {
			KcpSeg.sn,
				KcpSeg.ts = ack.sn,
				ack.ts
			ptr = KcpSeg.encode(
				ptr,
			)
		}
	}
	Kcp.acklist = Kcp.acklist[0:0]
	if ackOnly {
		FlushBuffer()
		return Kcp.interval
	}
	if Kcp.rmtWnd == 0 {
		current := KcpCurrentMs()
		if Kcp.probeWait == 0 {
			Kcp.probeWait = IKcpProbeInit
			Kcp.tsProbe = current + Kcp.probeWait
		} else if _itimediff(current, Kcp.tsProbe) >= 0 {
			if Kcp.probeWait < IKcpProbeInit {
				Kcp.probeWait = IKcpProbeInit
			}
			Kcp.probeWait += Kcp.probeWait / 2
			if Kcp.probeWait > IKcpProbeLimit {
				Kcp.probeWait = IKcpProbeLimit
			}
			Kcp.tsProbe = current + Kcp.probeWait
			Kcp.probe |= IKcpAskSend
		}
	}
	Kcp.tsProbe = 0
	Kcp.probeWait = 0
	if (Kcp.probe & IKcpAskSend) != 0 {
		KcpSeg.cmd = IKcpCmdWask
		makeSpace(
			IKcpOverhead,
		)
		ptr = KcpSeg.encode(
			ptr,
		)
	}
	if (Kcp.probe & IKcpAskTell) != 0 {
		KcpSeg.cmd = IKcpCmdWins
		makeSpace(
			IKcpOverhead,
		)
		ptr = KcpSeg.encode(
			ptr,
		)
	}
	Kcp.probe = 0
	cwnd := _imin(
		Kcp.sndWnd,
		Kcp.rmtWnd,
	)
	if Kcp.nocwnd == 0 {
		cwnd = _imin(
			Kcp.cwnd,
			cwnd,
		)
	}
	newSegsCount := 0
	for k := range Kcp.sndQueue {
		if _itimediff(
			Kcp.sndNxt,
			Kcp.sndUna+cwnd,
		) >= 0 {
			break
		}
		newKcpSeg := Kcp.sndQueue[k]
		newKcpSeg.conv = Kcp.conv
		newKcpSeg.cmd = IKcpCmdPush
		newKcpSeg.sn = Kcp.sndNxt
		Kcp.SndBuf = append(
			Kcp.SndBuf,
			newKcpSeg,
		)
		Kcp.sndNxt++
		newSegsCount++
	}
	if newSegsCount > 0 {
		Kcp.sndQueue = Kcp.removeFront(
			Kcp.sndQueue,
			newSegsCount,
		)
	}
	resent := uint32(Kcp.fastresend)
	if Kcp.fastresend <= 0 {
		resent = 0xFFFFFFFF
	}
	current := KcpCurrentMs()
	var change,
		lost,
		lostSegs,
		fastKcpRestransmittedSegments,
		earlyKcpRestransmittedSegments uint64
	minrto := int32(Kcp.interval)
	ref := Kcp.SndBuf[:len(
		Kcp.SndBuf,
	)]
	for k := range ref {
		KcpSegment := &ref[k]
		needsend := false
		if KcpSegment.acked == 1 {
			continue
		}
		if KcpSegment.Kxmit == 0 {
			needsend = true
			KcpSegment.rto = Kcp.rxRto
			KcpSegment.KcpResendTs = current + KcpSegment.rto
		} else if _itimediff(
			current,
			KcpSegment.KcpResendTs,
		) >= 0 {
			needsend = true
			if Kcp.nodelay == 0 {
				KcpSegment.rto += Kcp.rxRto
			} else {
				KcpSegment.rto += Kcp.rxRto / 2
			}
			KcpSegment.KcpResendTs = current + KcpSegment.rto
			lost++
			lostSegs++
		} else if KcpSegment.fastack >= resent {
			needsend = true
			KcpSegment.fastack = 0
			KcpSegment.rto = Kcp.rxRto
			KcpSegment.KcpResendTs = current + KcpSegment.rto
			change++
			fastKcpRestransmittedSegments++
		} else if KcpSegment.fastack > 0 && newSegsCount == 0 {
			needsend = true
			KcpSegment.fastack = 0
			KcpSegment.rto = Kcp.rxRto
			KcpSegment.KcpResendTs = current + KcpSegment.rto
			change++
			earlyKcpRestransmittedSegments++
		}
		if needsend {
			current = KcpCurrentMs()
			KcpSegment.Kxmit++
			KcpSegment.ts = current
			KcpSegment.wnd = KcpSeg.wnd
			KcpSegment.una = KcpSeg.una
			need := IKcpOverhead + len(
				KcpSegment.data,
			)
			makeSpace(
				need,
			)
			ptr = KcpSegment.encode(
				ptr,
			)
			copy(
				ptr,
				KcpSegment.data,
			)
			ptr = ptr[len(
				KcpSegment.data,
			):]
			if KcpSegment.Kxmit >= Kcp.deadLink {
				Kcp.state = 0xFFFFFFFF
			}
		}
		if rto := _itimediff(
			KcpSegment.KcpResendTs,
			current,
		); rto > 0 && rto < minrto {
			minrto = rto
		}
	}
	FlushBuffer()
	sum := lostSegs
	if lostSegs > 0 {
		atomic.AddUint64(
			&DefaultSnsi.LostSegments,
			lostSegs,
		)
	}
	if fastKcpRestransmittedSegments > 0 {
		atomic.AddUint64(
			&DefaultSnsi.FastKcpRestransmittedSegments,
			fastKcpRestransmittedSegments,
		)
		sum += fastKcpRestransmittedSegments
	}
	if earlyKcpRestransmittedSegments > 0 {
		atomic.AddUint64(
			&DefaultSnsi.EarlyKcpRestransmittedSegments,
			earlyKcpRestransmittedSegments,
		)
		sum += earlyKcpRestransmittedSegments
	}
	if sum > 0 {
		atomic.AddUint64(
			&DefaultSnsi.KcpRestransmittedSegments,
			sum,
		)
	}
	if Kcp.nocwnd == 0 {
		if change > 0 {
			inflight := Kcp.sndNxt - Kcp.sndUna
			Kcp.ssthresh = inflight / 2
			if Kcp.ssthresh < IKcpThreshMin {
				Kcp.ssthresh = IKcpThreshMin
			}
			Kcp.cwnd = Kcp.ssthresh + resent
			Kcp.incr = Kcp.cwnd * Kcp.mss
		}
		if lost > 0 {
			Kcp.ssthresh = cwnd / 2
			if Kcp.ssthresh < IKcpThreshMin {
				Kcp.ssthresh = IKcpThreshMin
			}
			Kcp.cwnd = 1
			Kcp.incr = Kcp.mss
		}

		if Kcp.cwnd < 1 {
			Kcp.cwnd = 1
			Kcp.incr = Kcp.mss
		}
	}
	return uint32(
		minrto,
	)
}

// Update is called repeatedly, 10ms to 100ms, queried via iKcp_check
// without iKcp_input or _send executing, returning timestamp in ms.
func (
	Kcp *KCP,
) Update() {
	var slap int32
	current := KcpCurrentMs()
	if Kcp.updated == 0 {
		Kcp.updated = 1
		Kcp.tsFlush = current
	}
	slap = _itimediff(
		current,
		Kcp.tsFlush,
	)
	if slap >= 10000 || slap < -10000 {
		Kcp.tsFlush = current
		slap = 0
	}
	if slap >= 0 {
		Kcp.tsFlush += Kcp.interval
		if _itimediff(
			current,
			Kcp.tsFlush,
		) >= 0 {
			Kcp.tsFlush = current + Kcp.interval
		}
		Kcp.Flush(
			false,
		)
	}
}

// Check function helps determine when to invoke an iKcp_update.
// It returns when you should invoke iKcp_update, in milliseconds,
// if there is no iKcp_input or _send calling. You may repeatdly
// call iKcp_update instead of update, to reduce most unnacessary
// iKcp_update invocations. This function may be used to schedule
// iKcp_updates, when implementing an epoll-like mechanism, or for
// optimizing an iKcp_update loop handling massive Kcp connections.
func (
	Kcp *KCP,
) Check() uint32 {
	current := KcpCurrentMs()
	tsFlush := Kcp.tsFlush
	tmFlush := int32(math.MaxInt32)
	tmPacket := int32(math.MaxInt32)
	minimal := uint32(0)
	if Kcp.updated == 0 {
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
	for k := range Kcp.SndBuf {
		KcpSeg := &Kcp.SndBuf[k]
		diff := _itimediff(
			KcpSeg.KcpResendTs,
			current,
		)
		if diff <= 0 {
			return current
		}
		if diff < tmPacket {
			tmPacket = diff
		}
	}
	minimal = uint32(tmPacket)
	if tmPacket >= tmFlush {
		minimal = uint32(tmFlush)
	}
	if minimal >= Kcp.interval {
		minimal = Kcp.interval
	}
	return current + minimal
}

// SetMtu changes MTU size.
// Defult MTU is 1400 byes.
func (
	Kcp *KCP,
) SetMtu(
	mtu int,
) int {
	if mtu < 50 || mtu < IKcpOverhead {
		return -1
	}
	if Kcp.reserved >= int(Kcp.mtu-IKcpOverhead) || Kcp.reserved < 0 {
		return -1
	}
	buffer := make(
		[]byte,
		mtu,
	)
	if buffer == nil {
		return -2
	}
	Kcp.mtu = uint32(mtu)
	Kcp.mss = Kcp.mtu - IKcpOverhead - uint32(Kcp.reserved)
	Kcp.buffer = buffer
	return 0
}

// NoDelay options:
// * fastest:	iKcp_nodelay(Kcp, 1, 20, 2, 1)
// * nodelay:	0: disable (default), 1: enable
// * interval:	internal update timer interval in milliseconds, defaults to 100ms
// * resend:	0: disable fast resends (default), 1: enable fast resends
// * nc:		0: normal congestion control (default), 1: disable congestion control
func (
	Kcp *KCP,
) NoDelay(
	nodelay,
	interval,
	resend,
	nc int,
) int {
	if nodelay >= 0 {
		Kcp.nodelay = uint32(nodelay)
		if nodelay != 0 {
			Kcp.rxMinRto = IKcpRtoNdl
		} else {
			Kcp.rxMinRto = IKcpRtoMin
		}
	}
	if interval >= 0 {
		if interval > 5000 {
			interval = 5000
		} else if interval < 10 {
			interval = 10
		}
		Kcp.interval = uint32(interval)
	}
	if resend >= 0 {
		Kcp.fastresend = int32(resend)
	}
	if nc >= 0 {
		Kcp.nocwnd = int32(nc)
	}
	return 0
}

// WndSize sets maximum window size (efaults: sndwnd=32 and rcvwnd=32)
func (
	Kcp *KCP,
) WndSize(
	sndwnd,
	rcvwnd int,
) int {
	if sndwnd > 0 {
		Kcp.sndWnd = uint32(sndwnd)
	}
	if rcvwnd > 0 {
		Kcp.rcvWnd = uint32(rcvwnd)
	}
	return 0
}

// WaitSnd shows how many packets are queued to be sent
func (
	Kcp *KCP,
) WaitSnd() int {
	return len(
		Kcp.SndBuf,
	) + len(
		Kcp.sndQueue,
	)
}

func (
	Kcp *KCP,
) removeFront(
	q []KcpSegment,
	n int,
) []KcpSegment {
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
	// 8 Goroutines per CPU or hardware thread
	if (runtime.GOMAXPROCS(runtime.NumCPU() * 8)) < (runtime.NumCPU() * 8) {
		_ = runtime.GOMAXPROCS(runtime.NumCPU() * 8)
	}
	// Register the MIT License
	lkcp9Legal.RegisterLicense(
		"\nThe MIT License (MIT)\n\nCopyright © 2015 Daniel Fu <daniel820313@gmail.com>.\nCopyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.\nCopyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.\nCopyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including, without limitation, the rights\nto use, copy, modify, merge, publish, distribute, sub-license, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice, and this permission notice, shall be\nincluded in all copies, or substantial portions, of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING, BUT NOT LIMITED TO, THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF, OR IN CONNECTION WITH THE SOFTWARE, OR THE USE OR OTHER DEALINGS IN\nTHE SOFTWARE.\n",
	)
}
