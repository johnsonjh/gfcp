// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2021 Gridfinity, LLC. <admin@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

// +build linux

package gfcp // import "go.gridfinity.dev/gfcp"

import (
	"net"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	batchSize = 16
)

func (
	s *UDPSession,
) readLoop() {
	addr, _ := net.ResolveUDPAddr(
		"udp",
		s.conn.LocalAddr().String(),
	)
	if addr.IP.To4() != nil {
		s.readLoopIPv4()
	} else {
		s.readLoopIPv6()
	}
}

func (
	s *UDPSession,
) readLoopIPv6() {
	var src string
	msgs := make(
		[]ipv6.Message,
		batchSize,
	)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{
			make(
				[]byte,
				GFcpMtuLimit,
			),
		}
	}
	conn := ipv6.NewPacketConn(
		s.conn,
	)
	for {
		if count, err := conn.ReadBatch(
			msgs,
			0,
		); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				if src == "" {
					src = msg.Addr.String()
				} else if msg.Addr.String() != src {
					atomic.AddUint64(
						&DefaultSnsi.GFcpPreInputErrors,
						1,
					)
					continue
				}
				if msg.N < s.headerSize+GfcpOverhead {
					atomic.AddUint64(
						&DefaultSnsi.GFcpInputErrors,
						1,
					)
					continue
				}
				s.packetInput(
					msg.Buffers[0][:msg.N],
				)
			}
		} else {
			s.chReadError <- err
			return
		}
	}
}

func (
	s *UDPSession,
) readLoopIPv4() {
	var src string
	msgs := make(
		[]ipv4.Message,
		batchSize,
	)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{make(
			[]byte,
			GFcpMtuLimit,
		)}
	}
	conn := ipv4.NewPacketConn(
		s.conn,
	)
	for {
		if count, err := conn.ReadBatch(
			msgs,
			0,
		); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				if src == "" {
					src = msg.Addr.String()
				} else if msg.Addr.String() != src {
					atomic.AddUint64(
						&DefaultSnsi.GFcpInputErrors,
						1,
					)
					continue
				}
				if msg.N < s.headerSize+GfcpOverhead {
					atomic.AddUint64(
						&DefaultSnsi.GFcpInputErrors,
						1,
					)
					continue
				}
				s.packetInput(
					msg.Buffers[0][:msg.N],
				)
			}
		} else {
			s.chReadError <- err
			return
		}
	}
}

func (
	l *Listener,
) monitor() {
	addr, _ := net.ResolveUDPAddr(
		"udp",
		l.conn.LocalAddr().String(),
	)
	if addr.IP.To4() != nil {
		l.monitorIPv4()
	} else {
		l.monitorIPv6()
	}
}

func (
	l *Listener,
) monitorIPv4() {
	msgs := make(
		[]ipv4.Message,
		batchSize,
	)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{make(
			[]byte,
			GFcpMtuLimit,
		)}
	}
	conn := ipv4.NewPacketConn(
		l.conn,
	)
	for {
		if count, err := conn.ReadBatch(
			msgs,
			0,
		); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				if msg.N >= l.headerSize+GfcpOverhead {
					l.packetInput(
						msg.Buffers[0][:msg.N],
						msg.Addr,
					)
				} else {
					atomic.AddUint64(
						&DefaultSnsi.GFcpInputErrors,
						1,
					)
				}
			}
		} else {
			return
		}
	}
}

func (
	l *Listener,
) monitorIPv6() {
	msgs := make(
		[]ipv6.Message,
		batchSize,
	)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{make(
			[]byte,
			GFcpMtuLimit,
		)}
	}
	conn := ipv4.NewPacketConn(
		l.conn,
	)
	for {
		if count, err := conn.ReadBatch(
			msgs,
			0,
		); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				if msg.N >= l.headerSize+GfcpOverhead {
					l.packetInput(
						msg.Buffers[0][:msg.N],
						msg.Addr,
					)
				} else {
					atomic.AddUint64(
						&DefaultSnsi.GFcpInputErrors,
						1,
					)
				}
			}
		} else {
			return
		}
	}
}
