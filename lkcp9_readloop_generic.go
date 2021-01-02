// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.
// Copyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

// +build !linux

package lkcp9 // import "go.gridfinity.dev/lkcp9"

import (
	"sync/atomic"
)

func (
	s *UDPSession,
) readLoop() {
	buf := make(
		[]byte,
		KcpMtuLimit,
	)
	var src string
	for {
		if n, addr, err := s.conn.ReadFrom(
			buf,
		); err == nil {
			if src == "" {
				src = addr.String()
			} else if addr.String() != src {
				atomic.AddUint64(
					&DefaultSnsi.KcpInputErrors,
					1,
				)
				continue
			}
			if n >= s.headerSize+IKcpOverhead {
				s.packetInput(
					buf[:n],
				)
			} else {
				atomic.AddUint64(
					&DefaultSnsi.KcpInputErrors,
					1,
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
	buf := make(
		[]byte,
		KcpMtuLimit,
	)
	for {
		if n, from, err := l.conn.ReadFrom(
			buf,
		); err == nil {
			if n >= l.headerSize+IKcpOverhead {
				l.packetInput(
					buf[:n],
					from,
				)
			} else {
				atomic.AddUint64(
					&DefaultSnsi.KcpInputErrors,
					1,
				)
			}
		} else {
			return
		}
	}
}
