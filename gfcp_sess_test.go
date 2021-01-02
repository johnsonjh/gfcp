// Copyright © 2015 Daniel Fu <daniel820313@gmail.com>.
// Copyright © 2019 Loki 'l0k18' Verloren <stalker.loki@protonmail.ch>.
// Copyright © 2020 Gridfinity, LLC. <admin@gridfinity.com>.
// Copyright © 2020 Jeffrey H. Johnson <jeff@gridfinity.com>.
//
// All rights reserved.
//
// All use of this code is governed by the MIT license.
// The complete license is available in the LICENSE file.

package gfcp_test

import (
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sync"
	"testing"
	"time"

	"go.gridfinity.dev/gfcp"
	u "go.gridfinity.dev/leaktestfe"
	"golang.org/x/crypto/pbkdf2"
)

const (
	portEcho           = "127.0.0.1:9079"
	portSink           = "127.0.0.1:19609"
	portTinyBufferEcho = "127.0.0.1:29609"
	portListerner      = "127.0.0.1:9078"
)

var (
	key = []byte(
		"testkey",
	)
	pass = pbkdf2.Key(
		key,
		[]byte(portSink),
		4096,
		32,
		fnv.New128a,
	)
)

func init() {
	go func() {
		log.Println(
			http.ListenAndServe(
				"127.0.0.1:8881",
				nil,
			),
		)
	}()
	go echoServer()
	go sinkServer()
	go tinyBufferEchoServer()
}

func dialEcho() (
	*gfcp.UDPSession,
	error,
) {
	sess, err := gfcp.DialWithOptions(
		portEcho,
		10,
		3,
	)
	if err != nil {
		panic(
			err,
		)
	}
	sess.SetStreamMode(
		true,
	)
	sess.SetStreamMode(
		false,
	)
	sess.SetStreamMode(
		true,
	)
	sess.SetWindowSize(
		1024,
		1024,
	)
	sess.SetReadBuffer(
		16 * 1024 * 1024,
	)
	sess.SetWriteBuffer(
		16 * 1024 * 1024,
	)
	sess.SetStreamMode(
		true,
	)
	sess.SetNoDelay(
		1,
		10,
		2,
		1,
	)
	sess.SetMtu(
		1400,
	)
	sess.SetMtu(
		1600,
	)
	sess.SetMtu(
		1400,
	)
	sess.SetACKNoDelay(
		true,
	)
	sess.SetACKNoDelay(
		false,
	)
	sess.SetDeadline(
		time.Now().Add(
			time.Minute,
		),
	)

	return sess, err
}

func dialSink() (
	*gfcp.UDPSession,
	error,
) {
	sess, err := gfcp.DialWithOptions(
		portSink,
		0,
		0,
	)
	if err != nil {
		panic(
			err,
		)
	}
	sess.SetStreamMode(
		true,
	)
	sess.SetWindowSize(
		1024, 1024,
	)
	sess.SetReadBuffer(
		16 * 1024 * 1024,
	)
	sess.SetWriteBuffer(
		16 * 1024 * 1024,
	)
	sess.SetStreamMode(
		true,
	)
	sess.SetNoDelay(
		1,
		10,
		2,
		1,
	)
	sess.SetMtu(
		1400,
	)
	sess.SetACKNoDelay(
		false,
	)
	sess.SetDeadline(
		time.Now().Add(
			time.Minute,
		),
	)
	return sess, err
}

func dialTinyBufferEcho() (
	*gfcp.UDPSession,
	error,
) {
	sess, err := gfcp.DialWithOptions(
		portTinyBufferEcho,
		10,
		3,
	)
	if err != nil {
		panic(
			err,
		)
	}

	return sess, err
}

func listenEcho() (
	net.Listener,
	error,
) {
	return gfcp.ListenWithOptions(
		portEcho,
		10,
		3,
	)
}

func listenTinyBufferEcho() (
	net.Listener,
	error,
) {
	return gfcp.ListenWithOptions(
		portTinyBufferEcho,
		10,
		3,
	)
}

func listenSink() (
	net.Listener,
	error,
) {
	return gfcp.ListenWithOptions(
		portSink,
		0,
		0,
	)
}

func echoServer() {
	l, err := listenEcho()
	if err != nil {
		panic(
			err,
		)
	}
	go func() {
		GFcplistener := l.(*gfcp.Listener)
		GFcplistener.SetReadBuffer(
			4 * 1024 * 1024,
		)
		GFcplistener.SetWriteBuffer(
			4 * 1024 * 1024,
		)
		GFcplistener.SetDSCP(
			46,
		)
		for {
			s, err := l.Accept()
			if err != nil {
				return
			}
			s.(*gfcp.UDPSession).SetReadBuffer(
				4 * 1024 * 1024,
			)
			s.(*gfcp.UDPSession).SetWriteBuffer(
				4 * 1024 * 1024,
			)
			go handleEcho(s.(*gfcp.UDPSession))
		}
	}()
}

func sinkServer() {
	l, err := listenSink()
	if err != nil {
		panic(
			err,
		)
	}
	go func() {
		GFcplistener := l.(*gfcp.Listener)
		GFcplistener.SetReadBuffer(
			4 * 1024 * 1024,
		)
		GFcplistener.SetWriteBuffer(
			4 * 1024 * 1024,
		)
		GFcplistener.SetDSCP(
			46,
		)
		for {
			s, err := l.Accept()
			if err != nil {
				return
			}
			go handleSink(s.(*gfcp.UDPSession))
		}
	}()
}

func tinyBufferEchoServer() {
	l, err := listenTinyBufferEcho()
	if err != nil {
		panic(
			err,
		)
	}
	go func() {
		for {
			s, err := l.Accept()
			if err != nil {
				return
			}
			go handleTinyBufferEcho(s.(*gfcp.UDPSession))
		}
	}()
}

func handleEcho(
	conn *gfcp.UDPSession,
) {
	conn.SetStreamMode(
		true,
	)
	conn.SetWindowSize(
		4096,
		4096,
	)
	conn.SetNoDelay(
		1,
		10,
		2,
		1,
	)
	conn.SetDSCP(
		46,
	)
	conn.SetMtu(
		1400,
	)
	conn.SetACKNoDelay(
		false,
	)
	conn.SetReadDeadline(
		time.Now().Add(
			time.Minute,
		),
	)
	conn.SetWriteDeadline(
		time.Now().Add(
			time.Minute,
		),
	)
	buf := make(
		[]byte,
		65536,
	)
	for {
		n, err := conn.Read(
			buf,
		)
		if err != nil {
			panic(
				err,
			)
		}
		conn.Write(
			buf[:n],
		)

	}
}

func handleSink(
	conn *gfcp.UDPSession,
) {
	conn.SetStreamMode(
		true,
	)
	conn.SetWindowSize(
		4096,
		4096,
	)
	conn.SetNoDelay(
		1,
		10,
		2,
		1,
	)
	conn.SetDSCP(
		46,
	)
	conn.SetMtu(
		1400,
	)
	conn.SetACKNoDelay(
		false,
	)
	conn.SetReadDeadline(
		time.Now().Add(
			time.Minute,
		),
	)
	conn.SetWriteDeadline(
		time.Now().Add(
			time.Minute,
		),
	)
	buf := make(
		[]byte,
		65536,
	)
	for {
		_, err := conn.Read(
			buf,
		)
		if err != nil {
			panic(
				err,
			)
		}

	}
}

func handleTinyBufferEcho(
	conn *gfcp.UDPSession,
) {
	conn.SetStreamMode(
		true,
	)
	buf := make(
		[]byte,
		2,
	)
	for {
		n, err := conn.Read(
			buf,
		)
		if err != nil {
			panic(
				err,
			)
		}
		conn.Write(
			buf[:n],
		)

	}
}

func TestTimeout(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	cli, err := dialEcho()
	if err != nil {
		panic(
			err,
		)
	}
	buf := make(
		[]byte,
		10,
	)
	cli.SetDeadline(
		time.Now().Add(
			time.Second,
		),
	)
	<-time.After(
		2 * time.Second,
	)
	n, err := cli.Read(
		buf,
	)
	if n != 0 || err == nil {
		t.Fail()
	}
	cli.Close()
}

func TestSendRecv(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	cli, err := dialEcho()
	if err != nil {
		panic(
			err,
		)
	}
	cli.SetWriteDelay(
		true,
	)
	cli.SetDUP(
		1,
	)
	const (
		N = 100
	)
	buf := make(
		[]byte,
		10,
	)
	for i := 0; i < N; i++ {
		msg := fmt.Sprintf(
			"hello%v",
			i,
		)
		cli.Write(
			[]byte(
				msg,
			),
		)
		if n, err := cli.Read(
			buf,
		); err == nil {
			if string(
				buf[:n],
			) != msg {
				t.Fail()
			}
		} else {
			panic(
				err,
			)
		}
	}
	cli.Close()
}

func TestSendVector(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	cli, err := dialEcho()
	if err != nil {
		panic(
			err,
		)
	}
	cli.SetWriteDelay(
		false,
	)
	const N = 100
	buf := make(
		[]byte,
		20,
	)
	v := make(
		[][]byte,
		2,
	)
	for i := 0; i < N; i++ {
		v[0] = []byte(
			fmt.Sprintf(
				"holas%v",
				i,
			))
		v[1] = []byte(
			fmt.Sprintf(
				"amigo%v",
				i,
			))
		msg :=
			fmt.Sprintf(
				"holas%vamigo%v",
				i,
				i,
			)
		cli.WriteBuffers(
			v,
		)
		if n, err := cli.Read(
			buf,
		); err == nil {
			if string(
				buf[:n],
			) != msg {
				t.Error(
					string(
						buf[:n],
					),
					msg,
				)
			}
		} else {
			panic(
				err,
			)
		}
	}
	cli.Close()
}

func TestTinyBufferReceiver(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	cli, err := dialTinyBufferEcho()
	if err != nil {
		panic(
			err,
		)
	}
	const (
		N = 100
	)
	snd := byte(
		0,
	)
	fillBuffer := func(
		buf []byte,
	) {
		for i := 0; i < len(
			buf,
		); i++ {
			buf[i] = snd
			snd++
		}
	}
	rcv := byte(
		0,
	)
	check := func(
		buf []byte,
	) bool {
		for i := 0; i < len(
			buf,
		); i++ {
			if buf[i] != rcv {
				return false
			}
			rcv++
		}
		return true
	}
	sndbuf := make(
		[]byte,
		7,
	)
	rcvbuf := make(
		[]byte,
		7,
	)
	for i := 0; i < N; i++ {
		fillBuffer(
			sndbuf,
		)
		cli.Write(
			sndbuf,
		)
		if n, err := io.ReadFull(
			cli,
			rcvbuf,
		); err == nil {
			if !check(
				rcvbuf[:n],
			) {
				t.Fail()
			}
		} else {
			panic(
				err,
			)
		}
	}
	cli.Close()
}

func TestClose(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	cli, err := dialEcho()
	if err != nil {
		panic(
			err,
		)
	}
	buf := make(
		[]byte,
		10,
	)
	cli.Close()
	if cli.Close() == nil {
		t.Fail()
	}
	n, err := cli.Write(
		buf,
	)
	if n != 0 || err == nil {
		t.Fail()
	}
	n, err = cli.Read(
		buf,
	)
	if n != 0 || err == nil {
		t.Fail()
	}
	cli.Close()
}

func TestParallel(
	t *testing.T,
) {
	concurrent := 1024
	if runtime.GOOS == "darwin" {
		t.Log(
			"\n--- WARN: Running on macOS: Retargetting concurrency:\t128",
		)
		concurrent = 128
	}
	t.Log(
		fmt.Sprintf(
			"\n--- INFO: Target concurrency:\t%v",
			concurrent,
		),
	)
	t.Parallel()
	t.Log(
		fmt.Sprintf(
			"\tStage 1/2:\tGoroutines:\t%v",
			runtime.NumGoroutine(),
		),
	)
	defer u.Leakplug(
		t,
	)
	var wg sync.WaitGroup
	wg.Add(
		concurrent,
	)
	for i := 0; i < concurrent; i++ {
		go parallel_client(
			&wg,
		)
	}
	t.Log(
		fmt.Sprintf(
			"\tStage 2/2:\tGoroutines:\t%v",
			runtime.NumGoroutine(),
		),
	)
	wg.Wait()
	t.Log(
		fmt.Sprintf(
			"\tStage 2/3:\tGoroutines:\t%v",
			runtime.NumGoroutine(),
		),
	)
}

func parallel_client(
	wg *sync.WaitGroup,
) (
	err error,
) {
	cli, err := dialEcho()
	if err != nil {
		panic(
			err,
		)
	}

	err = echo_tester(
		cli,
		64,
		64,
	)
	wg.Done()

	return
}

func BenchmarkEchoSpeed1K(
	b *testing.B,
) {
	speedclient(
		b,
		1*1000,
	)
}

func BenchmarkEchoSpeed4K(
	b *testing.B,
) {
	speedclient(
		b,
		4*1000,
	)
}

func BenchmarkEchoSpeed64K(
	b *testing.B,
) {
	speedclient(
		b,
		64*1000,
	)
}

func BenchmarkEchoSpeed256K(
	b *testing.B,
) {
	speedclient(
		b,
		256*1000,
	)
}

func BenchmarkEchoSpeed512K(
	b *testing.B,
) {
	speedclient(
		b,
		512*1000,
	)
}

func BenchmarkEchoSpeed1M(
	b *testing.B,
) {
	speedclient(
		b,
		1*1000*1000,
	)
}

func BenchmarkEchoSpeed4M(
	b *testing.B,
) {
	speedclient(
		b,
		4*1000*1000,
	)
}

func BenchmarkEchoSpeed8M(
	b *testing.B,
) {
	speedclient(
		b,
		8*1000*1000,
	)
}

func speedclient(
	b *testing.B,
	nbytes int,
) {
	b.ReportAllocs()
	cli, err := dialEcho()
	if err != nil {
		panic(
			err,
		)
	}

	if err := echo_tester(
		cli,
		nbytes,
		b.N,
	); err != nil {
		b.Fail()
	}
	b.SetBytes(
		int64(
			nbytes,
		),
	)
}

func BenchmarkSinkSpeed1K(
	b *testing.B,
) {
	sinkclient(
		b,
		1*1000,
	)
}

func BenchmarkSinkSpeed4K(
	b *testing.B,
) {
	sinkclient(
		b,
		4*1000,
	)
}

func BenchmarkSinkSpeed64K(
	b *testing.B,
) {
	sinkclient(
		b,
		64*1000,
	)
}

func BenchmarkSinkSpeed256K(
	b *testing.B,
) {
	sinkclient(
		b,
		256*1000,
	)
}

func BenchmarkSinkSpeed512K(
	b *testing.B,
) {
	sinkclient(
		b,
		512*1000,
	)
}

func BenchmarkSinkSpeed1M(
	b *testing.B,
) {
	sinkclient(
		b,
		1*1000*1000,
	)
}

func BenchmarkSinkSpeed4M(
	b *testing.B,
) {
	sinkclient(
		b,
		4*1000*1000,
	)
}

func BenchmarkSinkSpeed8M(
	b *testing.B,
) {
	sinkclient(
		b,
		8*1000*1000,
	)
}

func sinkclient(
	b *testing.B,
	nbytes int,
) {
	b.ReportAllocs()
	cli, err := dialSink()
	if err != nil {
		panic(
			err,
		)
	}
	sink_tester(
		cli,
		nbytes,
		b.N,
	)
	b.SetBytes(
		int64(
			nbytes,
		),
	)
}

func echo_tester(
	cli net.Conn,
	msglen,
	msgcount int,
) error {
	buf := make(
		[]byte,
		msglen,
	)
	for i := 0; i < msgcount; i++ {
		if _, err := cli.Write(
			buf,
		); err != nil {
			return err
		}
		nrecv := 0
		for {
			n, err := cli.Read(
				buf,
			)
			if err != nil {
				return err
			} else {
				nrecv += n
				if nrecv == msglen {
					break
				}
			}
		}
	}
	return nil
}

func sink_tester(
	cli *gfcp.UDPSession,
	msglen,
	msgcount int,
) error {
	buf := make(
		[]byte,
		msglen,
	)
	for i := 0; i < msgcount; i++ {
		if _, err := cli.Write(
			buf,
		); err != nil {
			return err
		}
	}
	return nil
}

func TestSnsi(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	t.Log(
		*gfcp.DefaultSnsi.Copy(),
	)
	t.Log(
		gfcp.DefaultSnsi.Header(),
	)
	t.Log(
		gfcp.DefaultSnsi.ToSlice(),
	)
	gfcp.DefaultSnsi.Reset()
	t.Log(
		gfcp.DefaultSnsi.ToSlice(),
	)
}

func TestListenerClose(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	l, err := gfcp.ListenWithOptions(
		portListerner,
		10,
		3,
	)
	if err != nil {
		t.Fail()
	}
	l.SetReadDeadline(
		time.Now().Add(
			time.Second,
		),
	)
	l.SetWriteDeadline(
		time.Now().Add(
			time.Second,
		),
	)
	l.SetDeadline(
		time.Now().Add(
			time.Second,
		),
	)
	time.Sleep(
		1 * time.Millisecond,
	)
	if _, err := l.Accept(); err == nil {
		t.Fail()
	}
	l.Close()
	fakeaddr, _ := net.ResolveUDPAddr(
		"udp6",
		"127.0.0.1:7162",
	)
	if l.CloseSession(
		fakeaddr,
	) {
		t.Fail()
	}
}
