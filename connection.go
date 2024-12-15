// Copyright (C) 2024  Naomi Kirby
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/oskirby/tls-router/tlsproto"
)

type TlsConnection struct {
	conn   *net.TCPConn
	config *Configuration

	// Values to parse out of the handshake.
	ClientHello   tlsproto.ClientHello
	Versions      []tlsproto.ProtocolVersion
	ServerNames   []string
	AlpnProtocols []string

	// Data read from the connnection.
	recordVersion tlsproto.ProtocolVersion
	helloData     []byte
}

func (client *TlsConnection) handleRequest(ctx context.Context) error {
	// Read the TLS record and handshake header from the connection.
	headers := [9]byte{}
	rxLen, err := client.conn.Read(headers[:])
	if rxLen < len(headers) {
		return fmt.Errorf("read truncated")
	}
	recordType := tlsproto.ContentType(headers[0])
	client.recordVersion = tlsproto.ProtocolVersion(binary.BigEndian.Uint16(headers[1:3]))
	recordLength := int(binary.BigEndian.Uint16(headers[3:5]))
	if recordType != tlsproto.ContentTypeHandshake {
		return fmt.Errorf("invalid record type")
	}
	if recordLength > tlsproto.RecordMaxLength {
		return fmt.Errorf("tls record length exceeded")
	}
	if recordLength < 4 {
		return fmt.Errorf("tls handshake truncated")
	}

	// The handshake should start with a client hello. Anything else is an error.
	hsHeader := binary.BigEndian.Uint32(headers[5:9])
	hsType := tlsproto.HandshakeType((hsHeader >> 24) & 0xff)
	hsLength := int(hsHeader & 0xffffff)
	if (hsLength + 4) > recordLength {
		return fmt.Errorf("tls handshake truncated")
	}
	if hsType != tlsproto.HandshakeTypeClientHello {
		return fmt.Errorf("unexpected handshake type")
	}

	// Receive the client hello data
	client.helloData = make([]byte, hsLength)
	var helloRecv int = 0
	for helloRecv < int(hsLength) {
		rxLen, err := client.conn.Read(client.helloData[helloRecv:])
		if err != nil {
			return fmt.Errorf("read error: %v", err)
		}
		helloRecv += rxLen
	}

	// Parse the ClientHello
	err = client.ClientHello.Unmarshal(client.helloData)
	if err != nil {
		return err
	}

	// Step 3: Process the handshake record.
	err = client.processClientHello()
	if err != nil {
		return fmt.Errorf("handshake error: %v", err)
	}

	// Handshake processing is done, it's now up to the router to decide what
	// to do with this connection.
	return nil
}

func (client *TlsConnection) processClientHello() error {
	// Check for encrypted client hellos
	for _, ext := range client.ClientHello.Extensions {
		if ext.ExtType != tlsproto.ExtTypeEncryptedClientHello {
			continue
		}
		err := client.processEncryptedHello(&ext)
		if err != nil {
			return err
		}
	}

	client.Versions = make([]tlsproto.ProtocolVersion, 1)
	client.Versions[0] = client.ClientHello.Version

	// Parse for useful extensions
	for _, ext := range client.ClientHello.Extensions {
		switch ext.ExtType {
		case tlsproto.ExtTypeServerName:
			sni, err := ext.ParseServerName()
			if err != nil {
				return err
			}
			client.ServerNames = sni.ServerNames
		case tlsproto.ExtTypeAlpn:
			alpn, err := ext.ParseAlpnProtocols()
			if err != nil {
				return err
			}
			client.AlpnProtocols = alpn.AlpnProtocols
		case tlsproto.ExtTypeSupportedVersions:
			versions, err := ext.ParseSupportedVersions()
			if err != nil {
				return err
			}
			client.Versions = versions.Versions
		}
	}

	// DEBUG!
	log.Printf("TLS ClientHello Received")
	log.Printf("  Version: %s", client.ClientHello.Version.String())
	log.Printf("  Random: %s", base64.StdEncoding.EncodeToString(client.ClientHello.Random[:]))
	log.Printf("  Session ID: %s", base64.StdEncoding.EncodeToString(client.ClientHello.SessionId))
	log.Printf("  Ciphers:")
	for _, suite := range client.ClientHello.CipherSuites {
		log.Printf("    %s", suite.String())
	}
	log.Printf("  Compression:")
	for _, method := range client.ClientHello.CompressionMethods {
		log.Printf("    0x%02x", method)
	}
	log.Printf("  Extensions:")
	for _, ext := range client.ClientHello.Extensions {
		log.Printf("    0x%04x", ext.ExtType)
	}
	log.Printf("  Server Names:")
	for _, name := range client.ServerNames {
		log.Printf("    %s", name)
	}
	log.Printf("  Application Protocols:")
	for _, protocol := range client.AlpnProtocols {
		log.Printf("    %s", protocol)
	}
	log.Printf("  Supported Versions:")
	for _, version := range client.Versions {
		log.Printf("    %s", version.String())
	}

	// TODO:
	return nil
}

func (client *TlsConnection) resendHandshake(dest io.Writer) error {
	recLength := len(client.helloData) + 4
	if recLength > tlsproto.RecordMaxLength {
		return fmt.Errorf("record protocol overflow")
	}

	// Rebuild the record and handshake header in case they changed.
	headers := [9]byte{}
	headers[0] = uint8(tlsproto.ContentTypeHandshake)
	binary.BigEndian.PutUint16(headers[1:3], uint16(client.recordVersion))
	binary.BigEndian.PutUint16(headers[3:5], uint16(recLength))
	hsHeader := uint32(tlsproto.HandshakeTypeClientHello) << 24
	hsHeader += uint32(len(client.helloData))
	binary.BigEndian.PutUint32(headers[5:9], hsHeader)

	// Send the record header.
	n, err := dest.Write(headers[:])
	if err != nil {
		return err
	}
	if n != len(headers) {
		return fmt.Errorf("backend record truncated")
	}

	// Resend the ClientHello message
	txLen := 0
	for txLen < len(client.helloData) {
		n, err := dest.Write(client.helloData[txLen:])
		if err != nil {
			return err
		}
		txLen += n
	}

	return nil
}
