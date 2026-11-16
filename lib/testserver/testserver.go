// ==============================================================================
// MasterDnsVPN (Hiddify fork)
// Package testserver runs a MasterDnsVPN server on the loopback, for the tests of programs that
// embed the client through package lib. It is not meant for production use.
// ==============================================================================
package testserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/udpserver"
)

// Start runs a server for domain on 127.0.0.1 with XOR encryption until ctx is done. It returns
// the server's address and key. keyDir holds the key file.
func Start(ctx context.Context, domain string, keyDir string) (address string, key string, err error) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()

	keyPath := filepath.Join(keyDir, "masterdns-key.txt")
	raw := fmt.Sprintf(`{"DOMAIN":[%q],"UDP_HOST":"127.0.0.1","UDP_PORT":%d,"ENCRYPTION_KEY_FILE":%q,"DATA_ENCRYPTION_METHOD":1,"LOG_LEVEL":"ERROR","UDP_READERS":1}`, domain, port, keyPath)
	cfg, err := config.LoadServerConfigFromJSONBase64(base64.StdEncoding.EncodeToString([]byte(raw)))
	if err != nil {
		return "", "", err
	}
	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		return "", "", err
	}
	codec, err := security.NewCodecFromConfig(cfg, keyInfo.Key)
	if err != nil {
		return "", "", err
	}
	srv := udpserver.New(cfg, logger.New("server", "ERROR"), codec)
	go func() {
		if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "masterdns test server:", err)
		}
	}()
	return fmt.Sprintf("127.0.0.1:%d", port), keyInfo.Key, nil
}
