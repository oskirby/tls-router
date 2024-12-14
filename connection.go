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
	"encoding/binary"
	"encoding/hex"
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
	Versions      []tlsproto.ProtocolVersion
	ServerNames   []string
	AlpnProtocols []string
	CipherSuites  []tlsproto.CipherSuite

	// Data read from the connnection.
	recordHeader [5]byte
	recordData   []byte
}

func (client *TlsConnection) handleRequest(ctx context.Context) error {
	// Step 1: Read the TLS record header from the connection.
	rxLen, err := client.conn.Read(client.recordHeader[:])
	if rxLen < len(client.recordHeader) {
		return fmt.Errorf("read truncated")
	}
	recordType := tlsproto.ContentType(client.recordHeader[0])
	//recordVersion := TlsVersion(binary.BigEndian.Uint16(client.recordHeader[1:2]))
	recordLength := binary.BigEndian.Uint16(client.recordHeader[3:5])
	if recordLength > tlsproto.RecordMaxLength {
		return fmt.Errorf("tls record length exceeded")
	}
	if recordType != tlsproto.ContentTypeHandshake {
		return fmt.Errorf("invalid record type")
	}

	// Step 2: Receive the record data
	client.recordData = make([]byte, recordLength)
	var recordRecv int = 0
	for recordRecv < int(recordLength) {
		rxLen, err := client.conn.Read(client.recordData[recordRecv:recordLength])
		if err != nil {
			return fmt.Errorf("read error: %v", err)
		}
		recordRecv += rxLen
	}

	// Step 3: Process the handshake record.
	err = client.processHandshake()
	if err != nil {
		return fmt.Errorf("handshake error: %v", err)
	}

	// Handshake processing is done, it's now up to the router to decide what
	// to do with this connection.
	return nil
}

func (client *TlsConnection) processHandshake() error {
	// Parse the handshake type and length.
	if len(client.recordData) < 4 {
		return fmt.Errorf("malformed handshake")
	}
	x := binary.BigEndian.Uint32(client.recordData[0:4])
	hsType := tlsproto.HandshakeType((x & 0xff000000) >> 24)
	hsLength := int(x & 0x00ffffff)
	if len(client.recordData) < (hsLength + 4) {
		return fmt.Errorf("truncated handshake")
	}
	if hsType != tlsproto.HandshakeTypeClientHello {
		return fmt.Errorf("unexpected handshake type")
	}

	// Parse the ClientHello
	var hello tlsproto.ClientHello
	err := hello.Unmarshal(client.recordData[4:])
	if err != nil {
		return err
	}

	client.Versions = make([]tlsproto.ProtocolVersion, 1)
	client.Versions[0] = hello.Version
	client.CipherSuites = hello.CipherSuites
	var echExtension *tlsproto.Extension = nil

	// First pass: Parse for useful extensions
	for index, ext := range hello.Extensions {
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
		case tlsproto.ExtTypeEncryptedClientHello:
			// Handle ECH decryption last.
			echExtension = &hello.Extensions[index]
			break
		}
	}

	// If an ECH extension was found - process it.
	if echExtension != nil {
		err := client.processEncryptedHello(echExtension)
		if err != nil {
			return err
		}
	}

	// DEBUG!
	log.Printf("TLS ClientHello Received")
	log.Printf("  Version: %s", hello.Version.String())
	log.Printf("  Random: %s", hex.EncodeToString(hello.Random[:]))
	log.Printf("  Session ID: %s", hex.EncodeToString(hello.SessionId))
	log.Printf("  Ciphers:")
	for _, suite := range hello.CipherSuites {
		log.Printf("    %s", suite.String())
	}
	log.Printf("  Compression:")
	for _, method := range hello.CompressionMethods {
		log.Printf("    0x%02x", method)
	}
	log.Printf("  Extensions:")
	for _, ext := range hello.Extensions {
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
	// Re-send the record header.
	n, err := dest.Write(client.recordHeader[:])
	if err != nil {
		return err
	}
	if n != len(client.recordHeader) {
		return fmt.Errorf("backend record truncated")
	}

	// Resend the ClientHello message
	txLen := 0
	for txLen < len(client.recordData) {
		n, err := dest.Write(client.recordData[txLen:])
		if err != nil {
			return err
		}
		txLen += n
	}

	return nil
}
