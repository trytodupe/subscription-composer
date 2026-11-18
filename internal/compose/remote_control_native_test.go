package compose

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ttd/subscription-composer/internal/model"
)

// An explicit dual-stack service must bind on both families and enforce authentication.
// Native schema checks alone establish neither behavior.
func TestNativeRemoteControl(t *testing.T) {
	validator := os.Getenv("SUBCOMPOSE_SING_BOX")
	if validator == "" {
		t.Skip("set SUBCOMPOSE_SING_BOX to a sing-box 1.14 executable")
	}
	for _, platform := range []string{"macos", "linux"} {
		t.Run(platform, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "[::]:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			device := model.Device{
				ID: "api-test", Platform: platform, Base: json.RawMessage(`{}`),
				RemoteControl: model.RemoteControl{Listen: "::", ListenPort: uint16(port), Secret: strings.Repeat("a", 32)},
			}
			_, _, nodes := fixture()
			content, err := Build(device, model.Policy{}, nodes)
			if err != nil {
				t.Fatal(err)
			}
			if err := Check(context.Background(), validator, content); err != nil {
				t.Fatal(err)
			}
			if platform == "macos" && runtime.GOOS != "darwin" {
				t.Skip("macOS dual wildcard and loopback API listeners require Darwin socket semantics")
			}
			profile := decode(t, content)
			// Keep this runtime test independent of the host's proxy ports and TUN.
			delete(profile, "inbounds")
			content, err = json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, validator, "run", "-D", dir, "-c", path)
			if err := cmd.Start(); err != nil {
				t.Fatal("could not start native API test instance")
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() { cancel(); <-done }()
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			for _, host := range []string{"127.0.0.1", "::1"} {
				t.Run(host, func(t *testing.T) {
					address := net.JoinHostPort(host, strconv.Itoa(port))
					deadline := time.Now().Add(5 * time.Second)
					for {
						conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
						if err == nil {
							conn.Close()
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("generated API did not become reachable on %s: %v", host, err)
						}
						time.Sleep(10 * time.Millisecond)
					}
					for _, credential := range []struct{ secret, status string }{
						{"", "16"}, {"incorrect", "16"}, {device.RemoteControl.Secret, "0"},
					} {
						request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/daemon.StartedService/GetVersion", bytes.NewReader(make([]byte, 5)))
						if err != nil {
							t.Fatal(err)
						}
						request.Header.Set("Content-Type", "application/grpc-web+proto")
						request.Header.Set("X-Grpc-Web", "1")
						if credential.secret != "" {
							request.Header.Set("Authorization", "Bearer "+credential.secret)
						}
						response, err := client.Do(request)
						if err != nil {
							t.Fatal("native API request failed")
						}
						body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
						response.Body.Close()
						if err != nil || response.StatusCode != http.StatusOK {
							t.Fatal("native API returned an invalid HTTP response")
						}
						status := response.Header.Get("Grpc-Status")
						for len(body) >= 5 {
							size := uint64(binary.BigEndian.Uint32(body[1:5]))
							if size > uint64(len(body)-5) {
								t.Fatal("invalid gRPC-Web response frame")
							}
							if body[0]&0x80 != 0 {
								for _, line := range strings.Split(string(body[5:5+int(size)]), "\r\n") {
									key, value, _ := strings.Cut(line, ":")
									if strings.EqualFold(key, "grpc-status") {
										status = strings.TrimSpace(value)
									}
								}
							}
							body = body[5+int(size):]
						}
						if status != credential.status {
							t.Fatalf("expected gRPC status %s, got %q", credential.status, status)
						}
					}
				})
			}
		})
	}
}
