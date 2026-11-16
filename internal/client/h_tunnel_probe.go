// ==============================================================================
// MasterDnsVPN (Hiddify fork)
// This file (h_tunnel_probe.go) builds the MTU test queries as plain DNS messages, so a program
// that embeds the client can test a resolver through its own DNS transports (UDP, TCP, DoT, DoH)
// before handing it to the client.
// ==============================================================================
package client

import (
	"encoding/binary"
	"errors"
	"fmt"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

// TunnelProbe is one MTU test: a DNS query for the tunnel domain and the check of its answer.
type TunnelProbe struct {
	// Name says what is tested, for messages: "upload" or "download".
	Name string
	// Query is the DNS query, ready to send to a resolver.
	Query []byte
	// Check returns nil when response is the server's correct answer to Query.
	Check func(response []byte) error
}

// TunnelProbes builds the upload and download MTU tests at the smallest MTUs the client accepts,
// for the first tunnel domain. A resolver that passes both forwards the tunnel's queries to the
// server and brings its answers back, which a plain query for another name does not show. Each
// call builds new queries with new probe codes.
func (c *Client) TunnelProbes() ([]TunnelProbe, error) {
	if c == nil || len(c.cfg.Domains) == 0 {
		return nil, errors.New("no tunnel domain")
	}
	domain := c.cfg.Domains[0]

	uploadSize := max(minUploadMTUFloor, c.cfg.MinUploadMTU)
	if limit := c.maxUploadMTUPayload(domain); uploadSize > limit {
		return nil, fmt.Errorf("domain %s leaves %d bytes for a query, less than the minimum upload MTU %d", domain, limit, uploadSize)
	}
	uploadPayload, uploadCode, uploadBase64, err := c.buildMTUProbePayload(uploadSize)
	if err != nil {
		return nil, err
	}
	uploadQuery, err := c.buildMTUProbeQuery(domain, Enums.PACKET_MTU_UP_REQ, uploadPayload)
	if err != nil {
		return nil, err
	}

	downloadSize := effectiveDownloadMTUProbeSize(max(minDownloadMTUFloor, c.cfg.MinDownloadMTU))
	downloadPayload, downloadCode, downloadBase64, err := c.buildMTUProbePayload(max(1+mtuProbeCodeLength+2, uploadSize))
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(downloadPayload[1+mtuProbeCodeLength:1+mtuProbeCodeLength+2], uint16(downloadSize))
	downloadQuery, err := c.buildMTUProbeQuery(domain, Enums.PACKET_MTU_DOWN_REQ, downloadPayload)
	if err != nil {
		return nil, err
	}

	return []TunnelProbe{
		{
			Name:  "upload",
			Query: uploadQuery,
			Check: func(response []byte) error {
				return checkMTUProbeAnswer(response, uploadBase64, Enums.PACKET_MTU_UP_RES, uploadCode, uploadSize, 6)
			},
		},
		{
			Name:  "download",
			Query: downloadQuery,
			Check: func(response []byte) error {
				return checkMTUProbeAnswer(response, downloadBase64, Enums.PACKET_MTU_DOWN_RES, downloadCode, downloadSize, downloadSize)
			},
		},
	}, nil
}

// checkMTUProbeAnswer applies the checks of sendUploadMTUProbe and sendDownloadMTUProbe.
func checkMTUProbeAnswer(response []byte, base64Reply bool, packetType uint8, code uint32, size int, payloadLen int) error {
	packet, err := DnsParser.ExtractVPNResponse(response, base64Reply)
	if err != nil {
		return fmt.Errorf("no tunnel answer: %w", err)
	}
	if packet.PacketType != packetType {
		return fmt.Errorf("answer is packet type %d, not %d", packet.PacketType, packetType)
	}
	if len(packet.Payload) != payloadLen || len(packet.Payload) < mtuProbeCodeLength+2 {
		return fmt.Errorf("answer carries %d bytes, not %d", len(packet.Payload), payloadLen)
	}
	if binary.BigEndian.Uint32(packet.Payload[:mtuProbeCodeLength]) != code {
		return errors.New("answer is for another probe")
	}
	if got := int(binary.BigEndian.Uint16(packet.Payload[mtuProbeCodeLength : mtuProbeCodeLength+2])); got != size {
		return fmt.Errorf("server saw %d bytes, not %d", got, size)
	}
	return nil
}
