package phantom

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSOCKS5CredentialsUseNegotiationAndStayOutOfOrigin(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer := make(chan error, 1)
	go func() {
		peer <- func() error {
			connection, err := listener.Accept()
			if err != nil {
				return err
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
			greeting := make([]byte, 2)
			if _, err := io.ReadFull(connection, greeting); err != nil {
				return err
			}
			methods := make([]byte, int(greeting[1]))
			if _, err := io.ReadFull(connection, methods); err != nil {
				return err
			}
			found := false
			for _, method := range methods {
				found = found || method == 2
			}
			if greeting[0] != 5 || !found {
				return fmt.Errorf("SOCKS5 did not offer username/password")
			}
			if _, err := connection.Write([]byte{5, 2}); err != nil {
				return err
			}
			if _, err := io.ReadFull(connection, greeting); err != nil {
				return err
			}
			username := make([]byte, int(greeting[1]))
			if _, err := io.ReadFull(connection, username); err != nil {
				return err
			}
			length := make([]byte, 1)
			if _, err := io.ReadFull(connection, length); err != nil {
				return err
			}
			password := make([]byte, int(length[0]))
			if _, err := io.ReadFull(connection, password); err != nil {
				return err
			}
			if greeting[0] != 1 || string(username) != "user" || string(password) != "secret" {
				return fmt.Errorf("incorrect SOCKS5 authentication")
			}
			if _, err := connection.Write([]byte{1, 0}); err != nil {
				return err
			}
			target := make([]byte, 5)
			if _, err := io.ReadFull(connection, target); err != nil {
				return err
			}
			if target[0] != 5 || target[1] != 1 || target[2] != 0 || target[3] != 3 {
				return fmt.Errorf("unexpected SOCKS5 connect address")
			}
			hostAndPort := make([]byte, int(target[4])+2)
			if _, err := io.ReadFull(connection, hostAndPort); err != nil {
				return err
			}
			if string(hostAndPort[:len(hostAndPort)-2]) != "origin.invalid" || hostAndPort[len(hostAndPort)-2] != 0 || hostAndPort[len(hostAndPort)-1] != 80 {
				return fmt.Errorf("SOCKS5 target changed")
			}
			if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
				return err
			}
			request, err := http.ReadRequest(bufio.NewReader(connection))
			if err != nil {
				return err
			}
			defer request.Body.Close()
			if request.RequestURI != "/path" || request.Header.Get("Authorization") != "" || request.Header.Get("Proxy-Authorization") != "" {
				return fmt.Errorf("origin request target or credentials changed")
			}
			_, err = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			return err
		}()
	}()
	client, err := New(Config{Profile: profile, Protocol: "h1", Proxy: "socks5h://" + listener.Addr().String(),
		ProxyCredentials: &ProxyCredentials{Username: "user", Password: "secret"}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Do(context.Background(), Request{Method: "GET", URL: "http://origin.invalid/path"})
	if err != nil {
		t.Fatal(err)
	}
	if data, err := response.Body.ReadAll(2); err != nil || string(data) != "ok" {
		t.Fatalf("SOCKS response %q: %v", data, err)
	}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
}
