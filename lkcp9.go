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
	"sync/atomic"

	lkcp9Legal "go4.org/legal"
)

const (
	IKCP_RTO_NDL     = 30  // no delay min rto
	IKCP_RTO_MIN     = 100 // normal min rto
	IKCP_RTO_DEF     = 200
	IKCP_RTO_MAX     = 60000
	IKCP_CMD_PUSH    = 81 // cmd: push data
	IKCP_CMD_ACK     = 82 // cmd: ack
	IKCP_CMD_WASK    = 83 // cmd: window probe (ask)
	IKCP_CMD_WINS    = 84 // cmd: window size (tell)
	IKCP_ASK_SEND    = 1  // need to send IKCP_CMD_WASK
	IKCP_ASK_TELL    = 2  // need to send IKCP_CMD_WINS
	IKCP_WND_SND     = 32
	IKCP_WND_RCV     = 32
	IKCP_MTU_DEF     = 1400
	IKCP_ACK_FAST    = 3
	IKCP_INTERVAL    = 100
	IKCP_OVERHEAD    = 24
	IKCP_DEADLINK    = 20
	IKCP_THRESH_INIT = 2
	IKCP_THRESH_MIN  = 2
	IKCP_PROBE_INIT  = 7000   // 7 secs to probe window size
	IKCP_PROBE_LIMIT = 120000 // up to 120 secs to probe window
)

type output_callback func(
	buf []byte,
	size int,
)

func iKcp_encode8u(
	p []byte,
	c byte,
) []byte {
	p[0] = c
	return p[1:]
}

func iKcp_decode8u(
	p []byte,
	c *byte,
) []byte {
	*c = p[0]
	return p[1:]
}

func iKcp_encode16u(
	p []byte,
	w uint16,
) []byte {
	binary.LittleEndian.PutUint16(
		p,
		w,
	)
	return p[2:]
}

func iKcp_decode16u(
	p []byte,
	w *uint16,
) []byte {
	*w = binary.LittleEndian.Uint16(
		p,
	)
	return p[2:]
}

func iKcp_encode32u(
	p []byte,
	l uint32,
) []byte {
	binary.LittleEndian.PutUint32(
		p,
		l,
	)
	return p[4:]
}

func iKcp_decode32u(
	p []byte,
	l *uint32,
) []byte {
	*l = binary.LittleEndian.Uint32(
		p,
	)
	return p[4:]
}

func _imin_(
	a,
	b uint32,
) uint32 {
	if a <= b {
		return a
	}
	return b
}

func _imax_(
	a,
	b uint32,
) uint32 {
	if a >= b {
		return a
	}
	return b
}

func _ibound_(
	lower,
	middle,
	upper uint32,
) uint32 {
	return _imin_(
		_imax_(
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
	ptr = iKcp_encode32u(
		ptr,
		KcpSeg.conv,
	)
	ptr = iKcp_encode8u(
		ptr,
		KcpSeg.cmd,
	)
	ptr = iKcp_encode8u(
		ptr,
		KcpSeg.frg,
	)
	ptr = iKcp_encode16u(
		ptr,
		KcpSeg.wnd,
	)
	ptr = iKcp_encode32u(
		ptr,
		KcpSeg.ts,
	)
	ptr = iKcp_encode32u(
		ptr,
		KcpSeg.sn,
	)
	ptr = iKcp_encode32u(
		ptr,
		KcpSeg.una,
	)
	ptr = iKcp_encode32u(
		ptr, uint32(len(
			KcpSeg.data,
		)))
	atomic.AddUint64(
		&DefaultSnsi.KcpOutputSegments,
		1,
	)
	return ptr
}

type KCP struct {
	conv, mtu, mss, state                  uint32
	snd_una, snd_nxt, rcv_nxt              uint32
	ssthresh                               uint32
	rx_rttvar, rx_srtt                     int32
	rx_rto, rx_minrto                      uint32
	snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe uint32
	interval, ts_Flush                     uint32
	nodelay, updated                       uint32
	ts_probe, probe_wait                   uint32
	dead_link, incr                        uint32
	fastresend                             int32
	nocwnd, stream                         int32
	snd_queue                              []KcpSegment
	rcv_queue                              []KcpSegment
	SndBuf                                 []KcpSegment
	rcv_buf                                []KcpSegment
	acklist                                []ackItem
	buffer                                 []byte
	reserved                               int
	output                                 output_callback
}

type ackItem struct {
	sn uint32
	ts uint32
}

// NewKCP creates a new Kcp control object.
func NewKCP(
	conv uint32,
	output output_callback,
) *KCP {
	Kcp := new(
		KCP,
	)
	Kcp.conv = conv
	Kcp.snd_wnd = IKCP_WND_SND
	Kcp.rcv_wnd = IKCP_WND_RCV
	Kcp.rmt_wnd = IKCP_WND_RCV
	Kcp.mtu = IKCP_MTU_DEF
	Kcp.mss = Kcp.mtu - IKCP_OVERHEAD
	Kcp.buffer = make(
		[]byte,
		Kcp.mtu,
	)
	Kcp.rx_rto = IKCP_RTO_DEF
	Kcp.rx_minrto = IKCP_RTO_MIN
	Kcp.interval = IKCP_INTERVAL
	Kcp.ts_Flush = IKCP_INTERVAL
	Kcp.ssthresh = IKCP_THRESH_INIT
	Kcp.dead_link = IKCP_DEADLINK
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
		Kcp.mtu-IKCP_OVERHEAD,
	) || n < 0 {
		return false
	}
	Kcp.reserved = n
	Kcp.mss = Kcp.mtu - IKCP_OVERHEAD - uint32(
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
		Kcp.rcv_queue,
	) == 0 {
		return -1
	}
	KcpSeg := &Kcp.rcv_queue[0]
	if KcpSeg.frg == 0 {
		return len(
			KcpSeg.data,
		)
	}
	if len(
		Kcp.rcv_queue,
	) < int(KcpSeg.frg+1) {
		return -1
	}
	for k := range Kcp.rcv_queue {
		KcpSeg := &Kcp.rcv_queue[k]
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
		Kcp.rcv_queue,
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
	var fast_recover bool
	if len(
		Kcp.rcv_queue,
	) >= int(
		Kcp.rcv_wnd,
	) {
		fast_recover = true
	}
	count := 0
	for k := range Kcp.rcv_queue {
		KcpSeg := &Kcp.rcv_queue[k]
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
		Kcp.rcv_queue = Kcp.remove_front(
			Kcp.rcv_queue,
			count,
		)
	}
	count = 0
	for k := range Kcp.rcv_buf {
		KcpSeg := &Kcp.rcv_buf[k]
		if KcpSeg.sn == Kcp.rcv_nxt && len(
			Kcp.rcv_queue,
		) < int(Kcp.rcv_wnd) {
			Kcp.rcv_nxt++
			count++
		} else {
			break
		}
	}
	if count > 0 {
		Kcp.rcv_queue = append(
			Kcp.rcv_queue,
			Kcp.rcv_buf[:count]...,
		)
		Kcp.rcv_buf = Kcp.remove_front(
			Kcp.rcv_buf,
			count,
		)
	}
	if len(
		Kcp.rcv_queue,
	) < int(Kcp.rcv_wnd) && fast_recover {
		Kcp.probe |= IKCP_ASK_TELL
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
			Kcp.snd_queue,
		)
		if n > 0 {
			KcpSeg := &Kcp.snd_queue[n-1]
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
		Kcp.snd_queue = append(
			Kcp.snd_queue,
			KcpSeg,
		)
		buffer = buffer[size:]
	}
	return 0
}

func (
	Kcp *KCP,
) update_ack(
	rtt int32,
) {
	var rto uint32
	if Kcp.rx_srtt == 0 {
		Kcp.rx_srtt = rtt
		Kcp.rx_rttvar = rtt >> 1
	} else {
		delta := rtt - Kcp.rx_srtt
		Kcp.rx_srtt += delta >> 3
		if delta < 0 {
			delta = -delta
		}
		if rtt < Kcp.rx_srtt-Kcp.rx_rttvar {
			Kcp.rx_rttvar += (delta - Kcp.rx_rttvar) >> 5
		} else {
			Kcp.rx_rttvar += (delta - Kcp.rx_rttvar) >> 2
		}
	}
	rto = uint32(
		Kcp.rx_srtt,
	) + _imax_(
		Kcp.interval,
		uint32(Kcp.rx_rttvar)<<2)
	Kcp.rx_rto = _ibound_(
		Kcp.rx_minrto,
		rto,
		IKCP_RTO_MAX,
	)
}

func (
	Kcp *KCP,
) shrink_buf() {
	if len(
		Kcp.SndBuf,
	) > 0 {
		KcpSeg := &Kcp.SndBuf[0]
		Kcp.snd_una = KcpSeg.sn
	} else {
		Kcp.snd_una = Kcp.snd_nxt
	}
}

func (
	Kcp *KCP,
) parse_ack(
	sn uint32,
) {
	if _itimediff(
		sn,
		Kcp.snd_una,
	) < 0 || _itimediff(
		sn,
		Kcp.snd_nxt,
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
) parse_fastack(
	sn, ts uint32,
) {
	if _itimediff(
		sn,
		Kcp.snd_una,
	) < 0 || _itimediff(
		sn,
		Kcp.snd_nxt,
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
) parse_una(
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
		Kcp.SndBuf = Kcp.remove_front(
			Kcp.SndBuf,
			count,
		)
	}
}

func (
	Kcp *KCP,
) ack_push(
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
) parse_data(
	newKcpSeg KcpSegment,
) bool {
	sn := newKcpSeg.sn
	if _itimediff(
		sn,
		Kcp.rcv_nxt+Kcp.rcv_wnd,
	) >= 0 ||
		_itimediff(
			sn,
			Kcp.rcv_nxt,
		) < 0 {
		return true
	}

	n := len(
		Kcp.rcv_buf,
	) - 1
	insert_idx := 0
	repeat := false
	for i := n; i >= 0; i-- {
		KcpSeg := &Kcp.rcv_buf[i]
		if KcpSeg.sn == sn {
			repeat = true
			break
		}
		if _itimediff(
			sn,
			KcpSeg.sn,
		) > 0 {
			insert_idx = i + 1
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

		if insert_idx == n+1 {
			Kcp.rcv_buf = append(
				Kcp.rcv_buf,
				newKcpSeg,
			)
		} else {
			Kcp.rcv_buf = append(
				Kcp.rcv_buf,
				KcpSegment{},
			)
			copy(
				Kcp.rcv_buf[insert_idx+1:],
				Kcp.rcv_buf[insert_idx:],
			)
			Kcp.rcv_buf[insert_idx] = newKcpSeg
		}
	}
	count := 0
	for k := range Kcp.rcv_buf {
		KcpSeg := &Kcp.rcv_buf[k]
		if KcpSeg.sn == Kcp.rcv_nxt && len(
			Kcp.rcv_queue,
		) < int(Kcp.rcv_wnd) {
			Kcp.rcv_nxt++
			count++
		} else {
			break
		}
	}
	if count > 0 {
		Kcp.rcv_queue = append(
			Kcp.rcv_queue,
			Kcp.rcv_buf[:count]...,
		)
		Kcp.rcv_buf = Kcp.remove_front(
			Kcp.rcv_buf,
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
	snd_una := Kcp.snd_una
	if len(
		data,
	) < IKCP_OVERHEAD {
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
		) < int(IKCP_OVERHEAD) {
			break
		}
		data = iKcp_decode32u(
			data,
			&conv,
		)
		if conv != Kcp.conv {
			return -1
		}
		data = iKcp_decode8u(
			data,
			&cmd,
		)
		data = iKcp_decode8u(
			data,
			&frg,
		)
		data = iKcp_decode16u(
			data,
			&wnd,
		)
		data = iKcp_decode32u(
			data,
			&ts,
		)
		data = iKcp_decode32u(
			data,
			&sn,
		)
		data = iKcp_decode32u(
			data,
			&una,
		)
		data = iKcp_decode32u(
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
		if cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS {
			return -3
		}
		if regular {
			Kcp.rmt_wnd = uint32(wnd)
		}
		Kcp.parse_una(
			una,
		)
		Kcp.shrink_buf()
		if cmd == IKCP_CMD_ACK {
			Kcp.parse_ack(
				sn,
			)
			Kcp.parse_fastack(
				sn,
				ts,
			)
			flag |= 1
			latest = ts
		} else if cmd == IKCP_CMD_PUSH {
			repeat := true
			if _itimediff(
				sn,
				Kcp.rcv_nxt+Kcp.rcv_wnd,
			) < 0 {
				Kcp.ack_push(
					sn,
					ts,
				)
				if _itimediff(
					sn,
					Kcp.rcv_nxt,
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
					repeat = Kcp.parse_data(
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
		} else if cmd == IKCP_CMD_WASK {
			Kcp.probe |= IKCP_ASK_TELL
		} else if cmd == IKCP_CMD_WINS {
		} else {
			return -3
		}
		inSegs++
		data = data[length:]
	}
	atomic.AddUint64(&DefaultSnsi.KcpInputSegments, inSegs)
	if flag != 0 && regular {
		current := KcpCurrentMs()
		if _itimediff(
			current,
			latest,
		) >= 0 {
			Kcp.update_ack(
				_itimediff(
					current,
					latest,
				),
			)
		}
	}
	if Kcp.nocwnd == 0 {
		if _itimediff(
			Kcp.snd_una,
			snd_una,
		) > 0 {
			if Kcp.cwnd < Kcp.rmt_wnd {
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
				if Kcp.cwnd > Kcp.rmt_wnd {
					Kcp.cwnd = Kcp.rmt_wnd
					Kcp.incr = Kcp.rmt_wnd * mss
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
) wnd_unused() uint16 {
	if len(
		Kcp.rcv_queue,
	) < int(Kcp.rcv_wnd) {
		return uint16(int(Kcp.rcv_wnd) - len(
			Kcp.rcv_queue,
		),
		)
	}
	return 0
}

func (
	Kcp *KCP,
) Flush(
	ackOnly bool,
) uint32 {
	var KcpSeg KcpSegment
	KcpSeg.conv = Kcp.conv
	KcpSeg.cmd = IKCP_CMD_ACK
	KcpSeg.wnd = Kcp.wnd_unused()
	KcpSeg.una = Kcp.rcv_nxt
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
			IKCP_OVERHEAD,
		)
		if ack.sn >= Kcp.rcv_nxt || len(
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
	if Kcp.rmt_wnd == 0 {
		current := KcpCurrentMs()
		if Kcp.probe_wait == 0 {
			Kcp.probe_wait = IKCP_PROBE_INIT
			Kcp.ts_probe = current + Kcp.probe_wait
		} else if _itimediff(current, Kcp.ts_probe) >= 0 {
			if Kcp.probe_wait < IKCP_PROBE_INIT {
				Kcp.probe_wait = IKCP_PROBE_INIT
			}
			Kcp.probe_wait += Kcp.probe_wait / 2
			if Kcp.probe_wait > IKCP_PROBE_LIMIT {
				Kcp.probe_wait = IKCP_PROBE_LIMIT
			}
			Kcp.ts_probe = current + Kcp.probe_wait
			Kcp.probe |= IKCP_ASK_SEND
		}
	}
	Kcp.ts_probe = 0
	Kcp.probe_wait = 0
	if (Kcp.probe & IKCP_ASK_SEND) != 0 {
		KcpSeg.cmd = IKCP_CMD_WASK
		makeSpace(
			IKCP_OVERHEAD,
		)
		ptr = KcpSeg.encode(
			ptr,
		)
	}
	if (Kcp.probe & IKCP_ASK_TELL) != 0 {
		KcpSeg.cmd = IKCP_CMD_WINS
		makeSpace(
			IKCP_OVERHEAD,
		)
		ptr = KcpSeg.encode(
			ptr,
		)
	}
	Kcp.probe = 0
	cwnd := _imin_(
		Kcp.snd_wnd,
		Kcp.rmt_wnd,
	)
	if Kcp.nocwnd == 0 {
		cwnd = _imin_(
			Kcp.cwnd,
			cwnd,
		)
	}
	newSegsCount := 0
	for k := range Kcp.snd_queue {
		if _itimediff(
			Kcp.snd_nxt,
			Kcp.snd_una+cwnd,
		) >= 0 {
			break
		}
		newKcpSeg := Kcp.snd_queue[k]
		newKcpSeg.conv = Kcp.conv
		newKcpSeg.cmd = IKCP_CMD_PUSH
		newKcpSeg.sn = Kcp.snd_nxt
		Kcp.SndBuf = append(
			Kcp.SndBuf,
			newKcpSeg,
		)
		Kcp.snd_nxt++
		newSegsCount++
	}
	if newSegsCount > 0 {
		Kcp.snd_queue = Kcp.remove_front(
			Kcp.snd_queue,
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
			KcpSegment.rto = Kcp.rx_rto
			KcpSegment.KcpResendTs = current + KcpSegment.rto
		} else if _itimediff(
			current,
			KcpSegment.KcpResendTs,
		) >= 0 {
			needsend = true
			if Kcp.nodelay == 0 {
				KcpSegment.rto += Kcp.rx_rto
			} else {
				KcpSegment.rto += Kcp.rx_rto / 2
			}
			KcpSegment.KcpResendTs = current + KcpSegment.rto
			lost++
			lostSegs++
		} else if KcpSegment.fastack >= resent {
			needsend = true
			KcpSegment.fastack = 0
			KcpSegment.rto = Kcp.rx_rto
			KcpSegment.KcpResendTs = current + KcpSegment.rto
			change++
			fastKcpRestransmittedSegments++
		} else if KcpSegment.fastack > 0 && newSegsCount == 0 {
			needsend = true
			KcpSegment.fastack = 0
			KcpSegment.rto = Kcp.rx_rto
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
			need := IKCP_OVERHEAD + len(
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
			if KcpSegment.Kxmit >= Kcp.dead_link {
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
			inflight := Kcp.snd_nxt - Kcp.snd_una
			Kcp.ssthresh = inflight / 2
			if Kcp.ssthresh < IKCP_THRESH_MIN {
				Kcp.ssthresh = IKCP_THRESH_MIN
			}
			Kcp.cwnd = Kcp.ssthresh + resent
			Kcp.incr = Kcp.cwnd * Kcp.mss
		}
		if lost > 0 {
			Kcp.ssthresh = cwnd / 2
			if Kcp.ssthresh < IKCP_THRESH_MIN {
				Kcp.ssthresh = IKCP_THRESH_MIN
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
		Kcp.ts_Flush = current
	}
	slap = _itimediff(
		current,
		Kcp.ts_Flush,
	)
	if slap >= 10000 || slap < -10000 {
		Kcp.ts_Flush = current
		slap = 0
	}
	if slap >= 0 {
		Kcp.ts_Flush += Kcp.interval
		if _itimediff(
			current,
			Kcp.ts_Flush,
		) >= 0 {
			Kcp.ts_Flush = current + Kcp.interval
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
	ts_Flush := Kcp.ts_Flush
	tm_Flush := int32(0x7FFFFFFF)
	tm_packet := int32(0x7FFFFFFF)
	minimal := uint32(0)
	if Kcp.updated == 0 {
		return current
	}
	if _itimediff(
		current,
		ts_Flush,
	) >= 10000 ||
		_itimediff(
			current,
			ts_Flush,
		) < -10000 {
		ts_Flush = current
	}
	if _itimediff(
		current,
		ts_Flush,
	) >= 0 {
		return current
	}
	tm_Flush = _itimediff(
		ts_Flush,
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
		if diff < tm_packet {
			tm_packet = diff
		}
	}
	minimal = uint32(tm_packet)
	if tm_packet >= tm_Flush {
		minimal = uint32(tm_Flush)
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
	if mtu < 50 || mtu < IKCP_OVERHEAD {
		return -1
	}
	if Kcp.reserved >= int(Kcp.mtu-IKCP_OVERHEAD) || Kcp.reserved < 0 {
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
	Kcp.mss = Kcp.mtu - IKCP_OVERHEAD - uint32(Kcp.reserved)
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
			Kcp.rx_minrto = IKCP_RTO_NDL
		} else {
			Kcp.rx_minrto = IKCP_RTO_MIN
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
		Kcp.snd_wnd = uint32(sndwnd)
	}
	if rcvwnd > 0 {
		Kcp.rcv_wnd = uint32(rcvwnd)
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
		Kcp.snd_queue,
	)
}

func (
	Kcp *KCP,
) remove_front(
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
	// Register the MIT License
	lkcp9Legal.RegisterLicense(
		"\nThe MIT License (MIT)\n\nCopyright © 2015 Daniel Fu <daniel820313@gmail.com>.\nCopyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.\nCopyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.\nCopyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including, without limitation, the rights\nto use, copy, modify, merge, publish, distribute, sub-license, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice, and this permission notice, shall be\nincluded in all copies, or substantial portions, of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING, BUT NOT LIMITED TO, THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF, OR IN CONNECTION WITH THE SOFTWARE, OR THE USE OR OTHER DEALINGS IN\nTHE SOFTWARE.\n",
	)
}
