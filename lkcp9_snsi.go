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
	"fmt"
	"sync/atomic"
)

// Snsi: Simple Network Statistics Indicators
type Snsi struct {
	KcpBytesSent                   uint64 // Bytes sent from upper level
	KcpBytesReceived               uint64 // Bytes received to upper level
	MaxConn                        uint64 // Max number of connections ever reached
	KcpActiveOpen                  uint64 // Accumulated active open connections
	KcpPassiveOpen                 uint64 // Accumulated passive open connections
	KcpNowEstablished              uint64 // Current number of established connections
	KcpPreInputErrors              uint64 // UDP read errors reported from net.PacketConn
	KcpChecksumFailures            uint64 // Checksum errors from CRC32
	KcpInputErrors                 uint64 // Packet input errors reported from KCP
	KcpInputPackets                uint64 // Incoming packets count
	KcpOutputPackets               uint64 // Outgoing packets count
	KcpInputSegments               uint64 // Incoming KCP KSegments
	KcpOutputSegments              uint64 // Outgoing KCP KSegments
	KcpInputBytes                  uint64 // UDP bytes received
	KcpOutputBytes                 uint64 // UDP bytes sent
	KcpRestransmittedSegments      uint64 // Accmulated retransmited KSegments
	FastKcpRestransmittedSegments  uint64 // Accmulated fast retransmitted KSegments
	EarlyKcpRestransmittedSegments uint64 // Accmulated early retransmitted KSegments
	LostSegments                   uint64 // Number of segs infered as lost
	DuplicateSegments              uint64 // Number of segs duplicated
	KcpFECRecovered                uint64 // Correct packets recovered from FEC
	KcpFailures                    uint64 // Incorrect packets recovered from FEC
	KcpFECParityShards             uint64 // FEC KSegments received
	KcpFECRuntShards               uint64 // Number of data shards insufficient for recovery
}

func newSnsi() *Snsi {
	return new(
		Snsi,
	)
}

// Header returns all field names
func (
	s *Snsi,
) Header() []string {
	return []string{
		"KcpBytesSent",
		"KcpBytesReceived",
		"MaxConn",
		"KcpActiveOpen",
		"KcpPassiveOpen",
		"KcpNowEstablished",
		"KcpInputErrors",
		"KcpChecksumFailures",
		"KcpInputErrors",
		"KcpInputPackets",
		"KcpOutputPackets",
		"KcpInputSegments",
		"KcpOutputSegments",
		"KcpInputBytes",
		"KcpOutputBytes",
		"KcpRestransmittedSegments",
		"FastKcpRestransmittedSegments",
		"EarlyKcpRestransmittedSegments",
		"LostSegments",
		"DuplicateSegments",
		"KcpFECParityShards",
		"KcpFailures",
		"KcpFECRecovered",
		"KcpFECRuntShards",
	}
}

// ToSlice returns current Snsi info as a slice
func (
	s *Snsi,
) ToSlice() []string {
	snsi := s.Copy()
	return []string{
		fmt.Sprint(
			snsi.KcpBytesSent,
		),
		fmt.Sprint(
			snsi.KcpBytesReceived,
		),
		fmt.Sprint(
			snsi.MaxConn,
		),
		fmt.Sprint(
			snsi.KcpActiveOpen,
		),
		fmt.Sprint(
			snsi.KcpPassiveOpen,
		),
		fmt.Sprint(
			snsi.KcpNowEstablished,
		),
		fmt.Sprint(
			snsi.KcpInputErrors,
		),
		fmt.Sprint(
			snsi.KcpChecksumFailures,
		),
		fmt.Sprint(
			snsi.KcpInputErrors,
		),
		fmt.Sprint(
			snsi.KcpInputPackets,
		),
		fmt.Sprint(
			snsi.KcpOutputPackets,
		),
		fmt.Sprint(
			snsi.KcpInputSegments,
		),
		fmt.Sprint(
			snsi.KcpOutputSegments,
		),
		fmt.Sprint(
			snsi.KcpInputBytes,
		),
		fmt.Sprint(
			snsi.KcpOutputBytes,
		),
		fmt.Sprint(
			snsi.KcpRestransmittedSegments,
		),
		fmt.Sprint(
			snsi.FastKcpRestransmittedSegments,
		),
		fmt.Sprint(
			snsi.EarlyKcpRestransmittedSegments,
		),
		fmt.Sprint(
			snsi.LostSegments,
		),
		fmt.Sprint(
			snsi.DuplicateSegments,
		),
		fmt.Sprint(
			snsi.KcpFECParityShards,
		),
		fmt.Sprint(
			snsi.KcpFailures,
		),
		fmt.Sprint(
			snsi.KcpFECRecovered,
		),
		fmt.Sprint(
			snsi.KcpFECRuntShards,
		),
	}
}

// Copy makes a copy of current Snsi snapshot
func (
	s *Snsi,
) Copy() *Snsi {
	d := newSnsi()
	d.KcpBytesSent = atomic.LoadUint64(
		&s.KcpBytesSent,
	)
	d.KcpBytesReceived = atomic.LoadUint64(
		&s.KcpBytesReceived,
	)
	d.MaxConn = atomic.LoadUint64(
		&s.MaxConn,
	)
	d.KcpActiveOpen = atomic.LoadUint64(
		&s.KcpActiveOpen,
	)
	d.KcpPassiveOpen = atomic.LoadUint64(
		&s.KcpPassiveOpen,
	)
	d.KcpNowEstablished = atomic.LoadUint64(
		&s.KcpNowEstablished,
	)
	d.KcpInputErrors = atomic.LoadUint64(
		&s.KcpInputErrors,
	)
	d.KcpChecksumFailures = atomic.LoadUint64(
		&s.KcpChecksumFailures,
	)
	d.KcpInputErrors = atomic.LoadUint64(
		&s.KcpInputErrors,
	)
	d.KcpInputPackets = atomic.LoadUint64(
		&s.KcpInputPackets,
	)
	d.KcpOutputPackets = atomic.LoadUint64(
		&s.KcpOutputPackets,
	)
	d.KcpInputSegments = atomic.LoadUint64(
		&s.KcpInputSegments,
	)
	d.KcpOutputSegments = atomic.LoadUint64(
		&s.KcpOutputSegments,
	)
	d.KcpInputBytes = atomic.LoadUint64(
		&s.KcpInputBytes,
	)
	d.KcpOutputBytes = atomic.LoadUint64(
		&s.KcpOutputBytes,
	)
	d.KcpRestransmittedSegments = atomic.LoadUint64(
		&s.KcpRestransmittedSegments,
	)
	d.FastKcpRestransmittedSegments = atomic.LoadUint64(
		&s.FastKcpRestransmittedSegments,
	)
	d.EarlyKcpRestransmittedSegments = atomic.LoadUint64(
		&s.EarlyKcpRestransmittedSegments,
	)
	d.LostSegments = atomic.LoadUint64(
		&s.LostSegments,
	)
	d.DuplicateSegments = atomic.LoadUint64(
		&s.DuplicateSegments,
	)
	d.KcpFECParityShards = atomic.LoadUint64(
		&s.KcpFECParityShards,
	)
	d.KcpFailures = atomic.LoadUint64(
		&s.KcpFailures,
	)
	d.KcpFECRecovered = atomic.LoadUint64(
		&s.KcpFECRecovered,
	)
	d.KcpFECRuntShards = atomic.LoadUint64(
		&s.KcpFECRuntShards,
	)
	return d
}

// Reset sets all Snsi values to zero
func (s *Snsi) Reset() {
	atomic.StoreUint64(
		&s.KcpBytesSent,
		0,
	)
	atomic.StoreUint64(
		&s.KcpBytesReceived,
		0,
	)
	atomic.StoreUint64(
		&s.MaxConn,
		0,
	)
	atomic.StoreUint64(
		&s.KcpActiveOpen,
		0,
	)
	atomic.StoreUint64(
		&s.KcpPassiveOpen,
		0,
	)
	atomic.StoreUint64(
		&s.KcpNowEstablished,
		0,
	)
	atomic.StoreUint64(
		&s.KcpInputErrors,
		0,
	)
	atomic.StoreUint64(
		&s.KcpChecksumFailures,
		0,
	)
	atomic.StoreUint64(
		&s.KcpInputErrors,
		0,
	)
	atomic.StoreUint64(
		&s.KcpInputPackets,
		0,
	)
	atomic.StoreUint64(
		&s.KcpOutputPackets,
		0,
	)
	atomic.StoreUint64(
		&s.KcpInputSegments,
		0,
	)
	atomic.StoreUint64(
		&s.KcpOutputSegments,
		0,
	)
	atomic.StoreUint64(
		&s.KcpInputBytes,
		0,
	)
	atomic.StoreUint64(
		&s.KcpOutputBytes,
		0,
	)
	atomic.StoreUint64(
		&s.KcpRestransmittedSegments,
		0,
	)
	atomic.StoreUint64(
		&s.FastKcpRestransmittedSegments,
		0,
	)
	atomic.StoreUint64(
		&s.EarlyKcpRestransmittedSegments,
		0,
	)
	atomic.StoreUint64(
		&s.LostSegments,
		0,
	)
	atomic.StoreUint64(
		&s.DuplicateSegments,
		0,
	)
	atomic.StoreUint64(
		&s.KcpFECParityShards,
		0,
	)
	atomic.StoreUint64(
		&s.KcpFailures,
		0,
	)
	atomic.StoreUint64(
		&s.KcpFECRecovered,
		0,
	)
	atomic.StoreUint64(
		&s.KcpFECRuntShards,
		0,
	)
}

// DefaultSnsi is the LKCP9 default statistics collector
var (
	DefaultSnsi *Snsi
)

func init() {
	DefaultSnsi = newSnsi()
}
