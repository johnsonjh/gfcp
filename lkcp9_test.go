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
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"

	u "go.gridfinity.dev/leaktestfe"
	licn "go4.org/legal"
)

func TestGoEnvironment(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	debug.FreeOSMemory()
	t.Log(
		fmt.Sprintf(
			"\nGo ROOT=%v\nGo version=%v\nGo GOMAXPROCS=%v\nGo NumCPU=%v",
			runtime.GOROOT(),
			runtime.Version(),
			runtime.GOMAXPROCS(-1),
			runtime.NumCPU(),
		),
	)
}

func Testlkcp9License(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	licenses := licn.Licenses()
	if len(
		licenses,
	) == 0 {
		t.Fatal(
			"\nlkcp9_license_test.TestLicense.licenses FAILURE:",
		)
	} else {
		t.Log(
			fmt.Sprintf(
				"\nEmbedded Licesnse data:\n%v\n",
				licenses,
			),
		)
	}
}
