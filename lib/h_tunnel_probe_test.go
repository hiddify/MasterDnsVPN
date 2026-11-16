package lib

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func exchangeUDP(address string, query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// The tunnel probes pass when sent straight to the server, before Run, and an answer to another
// probe or to an ordinary name does not pass.
func TestTunnelProbes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const domain = "t.example"
	port, key := startTestServer(t, ctx, domain, "")
	server := fmt.Sprintf("127.0.0.1:%d", port)

	c, err := New(Options{
		Domains:          []string{domain},
		Resolvers:        []string{"127.0.0.1:9"},
		EncryptionMethod: EncryptionXOR,
		EncryptionKey:    key,
	})
	if err != nil {
		t.Fatal(err)
	}
	probes, err := c.TunnelProbes()
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 2 {
		t.Fatalf("%d probes, want upload and download", len(probes))
	}
	var answers [][]byte
	for _, probe := range probes {
		var answer []byte
		for try := 0; try < 5; try++ { // the server starts in the background
			if answer, err = exchangeUDP(server, probe.Query); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("%s probe: %v", probe.Name, err)
		}
		if err := probe.Check(answer); err != nil {
			t.Fatalf("%s probe: %v", probe.Name, err)
		}
		answers = append(answers, answer)
	}

	// a resolver that answers with something else: a cached answer to an older probe
	again, err := c.TunnelProbes()
	if err != nil {
		t.Fatal(err)
	}
	for i, probe := range again {
		if err := probe.Check(answers[i]); err == nil {
			t.Fatalf("%s probe accepted the answer to an older probe", probe.Name)
		}
		if err := probe.Check(nil); err == nil {
			t.Fatalf("%s probe accepted an empty answer", probe.Name)
		}
	}
}
