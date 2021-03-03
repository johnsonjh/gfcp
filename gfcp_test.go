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
	"fmt"
	"runtime"
	"testing"

	u "go.gridfinity.dev/leaktestfe"
	licn "go4.org/legal"
)

func TestArchitecture(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	is64bit := uint64(^uintptr(0)) == ^uint64(0)
	if !is64bit {
		t.Fatal(
			"\n\t*** Platform is not 64-bit, unsupported architecture",
		)
	}
}

func TestGoEnvironment(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	t.Log(
		fmt.Sprintf(
			"\n\tCompiler:\t%v (%v)\n\tSystem:\t\t%v/%v\n\tCPU(s):\t\t%v logical processor(s)\n\tGOMAXPROCS:\t%v\n",
			runtime.Compiler,
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH,
			runtime.NumCPU(),
			runtime.GOMAXPROCS(
				-1,
			),
		),
	)
}

func TestGFcpLicense(
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
			"\n\ngfcp_license_test.TestGFcpLicense FAILURE",
		)
	} else {
		t.Log(
			fmt.Sprintf(
				"\n\n%v\n",
				licenses,
			),
		)
	}
}
