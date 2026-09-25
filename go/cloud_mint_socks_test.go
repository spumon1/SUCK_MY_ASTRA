package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

type cloudSOCKSObservation struct {
	host, user, password string
	port                 uint16
	err                  error
}

func receiveCloudSOCKSAuth(conn net.Conn) (string, string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", "", err
	}
	if head[0] != 5 {
		return "", "", fmt.Errorf("not SOCKS5")
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", "", err
	}
	if bytes.IndexByte(methods, 2) < 0 {
		return "", "", fmt.Errorf("no password auth offered")
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return "", "", err
	}
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", "", err
	}
	if head[0] != 1 {
		return "", "", fmt.Errorf("wrong auth version")
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return "", "", err
	}
	if _, err := io.ReadFull(conn, head[:1]); err != nil {
		return "", "", err
	}
	password := make([]byte, int(head[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return "", "", err
	}
	_, err := conn.Write([]byte{1, 0})
	return string(user), string(password), err
}

func serveCloudSOCKS(conn net.Conn) cloudSOCKSObservation {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	result := cloudSOCKSObservation{}
	result.user, result.password, result.err = receiveCloudSOCKSAuth(conn)
	if result.err != nil {
		return result
	}
	head := make([]byte, 5)
	if _, result.err = io.ReadFull(conn, head); result.err != nil {
		return result
	}
	if head[0] != 5 || head[1] != 1 || head[3] != 3 {
		result.err = fmt.Errorf("target DNS was not delegated to proxy")
		return result
	}
	host := make([]byte, int(head[4])+2)
	if _, result.err = io.ReadFull(conn, host); result.err != nil {
		return result
	}
	result.host = string(host[:len(host)-2])
	result.port = binary.BigEndian.Uint16(host[len(host)-2:])
	if _, result.err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}); result.err != nil {
		return result
	}
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		result.err = err
		return result
	}
	req.Body.Close()
	if req.Header.Get("Proxy-Authorization") != "" {
		result.err = fmt.Errorf("SOCKS auth leaked into HTTP")
		return result
	}
	_, result.err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfc-ok")
	return result
}

func TestCloudMintSOCKS5AndSOCKS5HUseProxyDNSAndAuthentication(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			observed := make(chan cloudSOCKSObservation, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					observed <- cloudSOCKSObservation{err: err}
					return
				}
				observed <- serveCloudSOCKS(conn)
			}()
			proxy := &url.URL{Scheme: scheme, Host: listener.Addr().String(), User: url.UserPassword("proxy-user", "proxy-password")}
			transport, err := newCloudMintTransport(proxy.String())
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			res, err := client.Get("http://fc-does-not-exist.invalid:9000/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if string(body) != "fc-ok" {
				t.Fatal("bad proxied response")
			}
			result := <-observed
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.host != "fc-does-not-exist.invalid" || result.port != 9000 || result.user != "proxy-user" || result.password != "proxy-password" {
				t.Fatal("wrong proxy destination or authentication")
			}
		})
	}
}
