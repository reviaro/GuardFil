package workspacefs

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMountedFIFOUsesOnlyTheViewsPipe(t *testing.T) {
	source, view, service := mounted(t)
	name := "pipe"
	if err := unix.Mkfifo(filepath.Join(view, name), 0600); err != nil {
		t.Fatal(err)
	}
	open := func(root string) int {
		t.Helper()
		fd, err := unix.Open(filepath.Join(root, name), unix.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	inside, host := open(view), open(source)
	if _, err := unix.Write(inside, []byte("inside")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	if n, _ := unix.Read(host, buf); n > 0 {
		t.Fatal("view pipe reached the host pipe")
	}
	if n, err := unix.Read(inside, buf); err != nil || string(buf[:n]) != "inside" {
		t.Fatalf("view pipe: %q %v", buf, err)
	}
	if _, err := unix.Write(host, []byte("host")); err != nil {
		t.Fatal(err)
	}
	if n, _ := unix.Read(inside, buf); n > 0 {
		t.Fatal("host pipe reached the view pipe")
	}
	policy := testPolicy + `  - id: pipe-write
    effect: deny
    match: {principals: [codex-agent], operations: [filesystem.write], resources: [{kind: path, value: /workspace/pipe}]}
`
	if _, err := service.SetPolicy([]byte(policy)); err != nil {
		t.Fatal(err)
	}
	if fd, err := unix.Open(filepath.Join(view, name), unix.O_RDWR|unix.O_NONBLOCK, 0); err == nil {
		unix.Close(fd)
		t.Fatal("new IPC access bypassed a write restriction")
	}
}

func TestMountedUnixSocketsDoNotConnectToHostEndpoints(t *testing.T) {
	source, view, _ := mounted(t)
	host, err := net.Listen("unix", filepath.Join(source, "host.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if conn, err := net.DialTimeout("unix", filepath.Join(view, "host.sock"), time.Second); err == nil {
		conn.Close()
		t.Fatal("agent connected to host socket")
	}
	listener, err := net.Listen("unix", filepath.Join(view, "local.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if conn, err := net.DialTimeout("unix", filepath.Join(source, "local.sock"), time.Second); err == nil {
		conn.Close()
		t.Fatal("view exposed its endpoint on the host backing inode")
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_, err = io.CopyN(conn, conn, 5)
		done <- err
	}()
	client, err := net.DialTimeout("unix", filepath.Join(view, "local.sock"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("view socket exchange: %q %v", buf, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := unix.Mknod(filepath.Join(view, "device"), unix.S_IFCHR|0600, 0); err == nil {
		os.Remove(filepath.Join(view, "device"))
		t.Fatal("device node created")
	}
}

func TestMountedIPCIsIsolatedBetweenViews(t *testing.T) {
	source, first, _ := mounted(t)
	other, err := New(source, "/workspace", SocketAuthorizer(filepath.Join(filepath.Dir(source), "approval.sock")))
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(filepath.Dir(source), "second")
	if err := os.Mkdir(second, 0700); err != nil {
		other.Close()
		t.Fatal(err)
	}
	server, err := other.Mount(second, false)
	if err != nil {
		other.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Unmount(); server.Wait(); other.Close() })
	if err := unix.Mkfifo(filepath.Join(first, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	var pipes []int
	for _, view := range []string{first, second} {
		fd, err := unix.Open(filepath.Join(view, "pipe"), unix.O_RDWR|unix.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		pipes = append(pipes, fd)
		t.Cleanup(func() { unix.Close(fd) })
	}
	buf := make([]byte, 16)
	for sender := range pipes {
		if _, err := unix.Write(pipes[sender], []byte("private")); err != nil {
			t.Fatal(err)
		}
		if n, _ := unix.Read(pipes[1-sender], buf); n > 0 {
			t.Fatal("pipe crossed workspace views")
		}
		if n, err := unix.Read(pipes[sender], buf); err != nil || string(buf[:n]) != "private" {
			t.Fatalf("own pipe: %q %v", buf, err)
		}
	}
	listener, err := net.Listen("unix", filepath.Join(first, "local.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if conn, err := net.DialTimeout("unix", filepath.Join(second, "local.sock"), time.Second); err == nil {
		conn.Close()
		t.Fatal("Unix socket connected across workspace views")
	}
}
