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

	u "go.gridfinity.dev/leaktestfe"
	"go.gridfinity.dev/lkcp9"
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
	*lkcp9.UDPSession,
	error,
) {
	block, _ := lkcp9.NewNoneBlockCrypt(
		pass,
	)
	sess, err := lkcp9.DialWithOptions(
		portEcho,
		block,
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
		1, 10, 2, 1,
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
	sess.SetDeadline(time.Now().Add(
		time.Minute,
	))

	return sess, err
}

func dialSink() (
	*lkcp9.UDPSession,
	error,
) {
	sess, err := lkcp9.DialWithOptions(
		portSink,
		nil,
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
		16 * 1024 * 1024)
	sess.SetStreamMode(
		true,
	)
	sess.SetNoDelay(
		1, 10, 2, 1,
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
	*lkcp9.UDPSession,
	error,
) {
	block, _ := lkcp9.NewNoneBlockCrypt(
		pass,
	)
	sess, err := lkcp9.DialWithOptions(
		portTinyBufferEcho,
		block,
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
	block, _ := lkcp9.NewNoneBlockCrypt(
		pass,
	)

	return lkcp9.ListenWithOptions(
		portEcho,
		block,
		10,
		3,
	)
}

func listenTinyBufferEcho() (
	net.Listener,
	error,
) {
	block, _ := lkcp9.NewNoneBlockCrypt(
		pass,
	)

	return lkcp9.ListenWithOptions(
		portTinyBufferEcho,
		block,
		10,
		3,
	)
}

func listenSink() (
	net.Listener,
	error,
) {
	return lkcp9.ListenWithOptions(
		portSink,
		nil,
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
		Kcplistener := l.(*lkcp9.Listener)
		Kcplistener.SetReadBuffer(4 * 1024 * 1024)
		Kcplistener.SetWriteBuffer(4 * 1024 * 1024)
		Kcplistener.SetDSCP(46)
		for {
			s, err := l.Accept()
			if err != nil {
				return
			}
			s.(*lkcp9.UDPSession).SetReadBuffer(4 * 1024 * 1024)
			s.(*lkcp9.UDPSession).SetWriteBuffer(4 * 1024 * 1024)
			go handleEcho(s.(*lkcp9.UDPSession))
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
		Kcplistener := l.(*lkcp9.Listener)
		Kcplistener.SetReadBuffer(
			4 * 1024 * 1024,
		)
		Kcplistener.SetWriteBuffer(
			4 * 1024 * 1024,
		)
		Kcplistener.SetDSCP(
			46,
		)
		for {
			s, err := l.Accept()
			if err != nil {
				return
			}
			go handleSink(s.(*lkcp9.UDPSession))
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
			go handleTinyBufferEcho(s.(*lkcp9.UDPSession))
		}
	}()
}

func handleEcho(
	conn *lkcp9.UDPSession,
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
		time.Now().Add(time.Hour),
	)
	conn.SetWriteDeadline(
		time.Now().Add(time.Hour),
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
	conn *lkcp9.UDPSession,
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
		time.Now().Add(time.Hour),
	)
	conn.SetWriteDeadline(
		time.Now().Add(time.Hour),
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
	conn *lkcp9.UDPSession,
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
		time.Now().Add(time.Second),
	)
	<-time.After(
		2 * time.Second,
	)
	n, err := cli.Read(buf)
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
			[]byte(msg),
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
					string(buf[:n]),
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
		t.Log("--- WARN: Detected macOS: Lowering concurrency to 128")
		concurrent = 128
		return
	}
	t.Log(
		fmt.Sprintf(
			"--- INFO: Target concurrency: %v",
			concurrent,
		),
	)
	t.Parallel()
	t.Log(
		fmt.Sprintf(
			"Stage 1/2: Goroutines: %v",
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
			"Stage 2/2: Goroutines: %v",
			runtime.NumGoroutine(),
		),
	)
	wg.Wait()
	t.Log(
		fmt.Sprintf(
			"Stage 2/3: Goroutines: %v",
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

func BenchmarkEchoSpeed4K(
	b *testing.B,
) {
	speedclient(
		b,
		4096,
	)
}

func BenchmarkEchoSpeed64K(
	b *testing.B,
) {
	speedclient(
		b,
		65536,
	)
}

func BenchmarkEchoSpeed512K(
	b *testing.B,
) {
	speedclient(b,
		524288,
	)
}

func BenchmarkEchoSpeed1M(
	b *testing.B,
) {
	speedclient(
		b,
		1048576,
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
		int64(nbytes),
	)
}

func BenchmarkSinkSpeed4K(
	b *testing.B,
) {
	sinkclient(
		b,
		4*1024,
	)
}

func BenchmarkSinkSpeed64K(
	b *testing.B,
) {
	sinkclient(
		b,
		64*1024,
	)
}

func BenchmarkSinkSpeed256K(
	b *testing.B,
) {
	sinkclient(
		b,
		256*1024,
	)
}

func BenchmarkSinkSpeed1M(
	b *testing.B,
) {
	sinkclient(
		b,
		1*1024*1024,
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
		int64(nbytes),
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
	cli *lkcp9.UDPSession,
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
		*lkcp9.DefaultSnsi.Copy(),
	)
	t.Log(
		lkcp9.DefaultSnsi.Header(),
	)
	t.Log(
		lkcp9.DefaultSnsi.ToSlice(),
	)
	lkcp9.DefaultSnsi.Reset()
	t.Log(
		lkcp9.DefaultSnsi.ToSlice(),
	)
}

func TestListenerClose(
	t *testing.T,
) {
	defer u.Leakplug(
		t,
	)
	l, err := lkcp9.ListenWithOptions(
		portListerner,
		nil,
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
		1 * time.Second,
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
