// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2021 Gridfinity, LLC. <admin@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

package gfcp // import "go.gridfinity.dev/gfcp"

import (
	"fmt"
	"sync/atomic"
)

// Snsi == Simple Network Statistics Indicators
type Snsi struct {
	GFcpBytesSent                   uint64 // Bytes sent from upper level
	GFcpBytesReceived               uint64 // Bytes received to upper level
	GFcpMaxConn                     uint64 // Max number of connections ever reached
	GFcpActiveOpen                  uint64 // Accumulated active open connections
	GFcpPassiveOpen                 uint64 // Accumulated passive open connections
	GFcpNowEstablished              uint64 // Current number of established connections
	GFcpPreInputErrors              uint64 // UDP read errors reported from net.PacketConn
	GFcpChecksumFailures            uint64 // Checksum errors from CRC32
	GFcpInputErrors                 uint64 // Packet input errors reported from GFCP
	GFcpInputPackets                uint64 // Incoming packets count
	GFcpOutputPackets               uint64 // Outgoing packets count
	GFcpInputSegments               uint64 // Incoming GFCP KSegments
	GFcpOutputSegments              uint64 // Outgoing GFCP KSegments
	GFcpInputBytes                  uint64 // UDP bytes received
	GFcpOutputBytes                 uint64 // UDP bytes sent
	GFcpRestransmittedSegments      uint64 // Accmulated retransmited KSegments
	FastGFcpRestransmittedSegments  uint64 // Accmulated fast retransmitted KSegments
	EarlyGFcpRestransmittedSegments uint64 // Accmulated early retransmitted KSegments
	GFcpLostSegments                uint64 // Number of segs inferred as lost
	GFcpDupSegments                 uint64 // Number of segs duplicated
	GFcpFECRecovered                uint64 // Correct packets recovered from FEC
	GFcpFailures                    uint64 // Incorrect packets recovered from FEC
	GFcpFECParityShards             uint64 // FEC KSegments received
	GFcpFECRuntShards               uint64 // Number of data shards insufficient for recovery
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
		"GFcpBytesSent",
		"GFcpBytesReceived",
		"GFcpMaxConn",
		"GFcpActiveOpen",
		"GFcpPassiveOpen",
		"GFcpNowEstablished",
		"GFcpInputErrors",
		"GFcpChecksumFailures",
		"GFcpInputErrors",
		"GFcpInputPackets",
		"GFcpOutputPackets",
		"GFcpInputSegments",
		"GFcpOutputSegments",
		"GFcpInputBytes",
		"GFcpOutputBytes",
		"GFcpRestransmittedSegments",
		"FastGFcpRestransmittedSegments",
		"EarlyGFcpRestransmittedSegments",
		"GFcpLostSegments",
		"GFcpDupSegments",
		"GFcpFECParityShards",
		"GFcpFailures",
		"GFcpFECRecovered",
		"GFcpFECRuntShards",
	}
}

// ToSlice returns current Snsi info as a slice
func (
	s *Snsi,
) ToSlice() []string {
	snsi := s.Copy()
	return []string{
		fmt.Sprint(
			snsi.GFcpBytesSent,
		),
		fmt.Sprint(
			snsi.GFcpBytesReceived,
		),
		fmt.Sprint(
			snsi.GFcpMaxConn,
		),
		fmt.Sprint(
			snsi.GFcpActiveOpen,
		),
		fmt.Sprint(
			snsi.GFcpPassiveOpen,
		),
		fmt.Sprint(
			snsi.GFcpNowEstablished,
		),
		fmt.Sprint(
			snsi.GFcpInputErrors,
		),
		fmt.Sprint(
			snsi.GFcpChecksumFailures,
		),
		fmt.Sprint(
			snsi.GFcpInputErrors,
		),
		fmt.Sprint(
			snsi.GFcpInputPackets,
		),
		fmt.Sprint(
			snsi.GFcpOutputPackets,
		),
		fmt.Sprint(
			snsi.GFcpInputSegments,
		),
		fmt.Sprint(
			snsi.GFcpOutputSegments,
		),
		fmt.Sprint(
			snsi.GFcpInputBytes,
		),
		fmt.Sprint(
			snsi.GFcpOutputBytes,
		),
		fmt.Sprint(
			snsi.GFcpRestransmittedSegments,
		),
		fmt.Sprint(
			snsi.FastGFcpRestransmittedSegments,
		),
		fmt.Sprint(
			snsi.EarlyGFcpRestransmittedSegments,
		),
		fmt.Sprint(
			snsi.GFcpLostSegments,
		),
		fmt.Sprint(
			snsi.GFcpDupSegments,
		),
		fmt.Sprint(
			snsi.GFcpFECParityShards,
		),
		fmt.Sprint(
			snsi.GFcpFailures,
		),
		fmt.Sprint(
			snsi.GFcpFECRecovered,
		),
		fmt.Sprint(
			snsi.GFcpFECRuntShards,
		),
	}
}

// Copy makes a copy of current Snsi snapshot
func (
	s *Snsi,
) Copy() *Snsi {
	d := newSnsi()
	d.GFcpBytesSent = atomic.LoadUint64(
		&s.GFcpBytesSent,
	)
	d.GFcpBytesReceived = atomic.LoadUint64(
		&s.GFcpBytesReceived,
	)
	d.GFcpMaxConn = atomic.LoadUint64(
		&s.GFcpMaxConn,
	)
	d.GFcpActiveOpen = atomic.LoadUint64(
		&s.GFcpActiveOpen,
	)
	d.GFcpPassiveOpen = atomic.LoadUint64(
		&s.GFcpPassiveOpen,
	)
	d.GFcpNowEstablished = atomic.LoadUint64(
		&s.GFcpNowEstablished,
	)
	d.GFcpInputErrors = atomic.LoadUint64(
		&s.GFcpInputErrors,
	)
	d.GFcpChecksumFailures = atomic.LoadUint64(
		&s.GFcpChecksumFailures,
	)
	d.GFcpInputErrors = atomic.LoadUint64(
		&s.GFcpInputErrors,
	)
	d.GFcpInputPackets = atomic.LoadUint64(
		&s.GFcpInputPackets,
	)
	d.GFcpOutputPackets = atomic.LoadUint64(
		&s.GFcpOutputPackets,
	)
	d.GFcpInputSegments = atomic.LoadUint64(
		&s.GFcpInputSegments,
	)
	d.GFcpOutputSegments = atomic.LoadUint64(
		&s.GFcpOutputSegments,
	)
	d.GFcpInputBytes = atomic.LoadUint64(
		&s.GFcpInputBytes,
	)
	d.GFcpOutputBytes = atomic.LoadUint64(
		&s.GFcpOutputBytes,
	)
	d.GFcpRestransmittedSegments = atomic.LoadUint64(
		&s.GFcpRestransmittedSegments,
	)
	d.FastGFcpRestransmittedSegments = atomic.LoadUint64(
		&s.FastGFcpRestransmittedSegments,
	)
	d.EarlyGFcpRestransmittedSegments = atomic.LoadUint64(
		&s.EarlyGFcpRestransmittedSegments,
	)
	d.GFcpLostSegments = atomic.LoadUint64(
		&s.GFcpLostSegments,
	)
	d.GFcpDupSegments = atomic.LoadUint64(
		&s.GFcpDupSegments,
	)
	d.GFcpFECParityShards = atomic.LoadUint64(
		&s.GFcpFECParityShards,
	)
	d.GFcpFailures = atomic.LoadUint64(
		&s.GFcpFailures,
	)
	d.GFcpFECRecovered = atomic.LoadUint64(
		&s.GFcpFECRecovered,
	)
	d.GFcpFECRuntShards = atomic.LoadUint64(
		&s.GFcpFECRuntShards,
	)
	return d
}

// Reset sets all Snsi values to zero
func (s *Snsi) Reset() {
	atomic.StoreUint64(
		&s.GFcpBytesSent,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpBytesReceived,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpMaxConn,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpActiveOpen,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpPassiveOpen,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpNowEstablished,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpInputErrors,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpChecksumFailures,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpInputErrors,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpInputPackets,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpOutputPackets,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpInputSegments,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpOutputSegments,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpInputBytes,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpOutputBytes,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpRestransmittedSegments,
		0,
	)
	atomic.StoreUint64(
		&s.FastGFcpRestransmittedSegments,
		0,
	)
	atomic.StoreUint64(
		&s.EarlyGFcpRestransmittedSegments,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpLostSegments,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpDupSegments,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpFECParityShards,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpFailures,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpFECRecovered,
		0,
	)
	atomic.StoreUint64(
		&s.GFcpFECRuntShards,
		0,
	)
}

// DefaultSnsi is the GFCP default statistics collector
var (
	DefaultSnsi *Snsi
)

func init() {
	DefaultSnsi = newSnsi()
}
