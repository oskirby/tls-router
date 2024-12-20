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
	client  *net.TCPConn
	backend *net.TCPConn
	config  *Configuration

	// Values to parse out of the handshake.
	ClientHello   tlsproto.ClientHello
	Versions      []tlsproto.ProtocolVersion
	ServerNames   []string
	AlpnProtocols []string

	// Data read from the connnection.
	recordVersion   tlsproto.ProtocolVersion
	helloData       []byte
	serverHelloDone bool

	// The ECH context needs to be saved across messages in case we encounter a
	// HelloRetryRequest and we need to decrypt a subsequent ClientHello.
	echContext []byte
}

// readRecord reads exactly one record from the TCP connection and returns it.
func readRecord(conn *net.TCPConn) (*tlsproto.Record, error) {
	headers := [5]byte{}
	rxLen, err := conn.Read(headers[:])
	if err != nil {
		return nil, err
	}
	if rxLen < len(headers) {
		return nil, fmt.Errorf("read truncated")
	}

	// Parse the record header to determine how big the fragment is.
	record := tlsproto.Record{
		Type:    tlsproto.ContentType(headers[0]),
		Version: tlsproto.ProtocolVersion(binary.BigEndian.Uint16(headers[1:3])),
	}
	recLength := int(binary.BigEndian.Uint16(headers[3:5]))
	if recLength > tlsproto.RecordMaxLength {
		return nil, fmt.Errorf("tls record length exceeded")
	}

	// Read the record fragment.
	record.Fragment = make([]byte, recLength)
	recReceived := 0
	for recReceived < int(recLength) {
		rxLen, err := conn.Read(record.Fragment[recReceived:])
		if err != nil {
			return nil, fmt.Errorf("read error: %v", err)
		}
		recReceived += rxLen
	}

	return &record, nil
}

func sendRecord(conn *net.TCPConn, rec *tlsproto.Record) error {
	if len(rec.Fragment) > tlsproto.RecordMaxLength {
		return fmt.Errorf("tls record length exceeded")
	}

	// reconstruct and send the record header.
	header := [5]byte{}
	header[0] = uint8(rec.Type)
	binary.BigEndian.PutUint16(header[1:3], uint16(rec.Version))
	binary.BigEndian.PutUint16(header[3:5], uint16(len(rec.Fragment)))
	txLen, err := conn.Write(header[:])
	if err != nil {
		return err
	}
	if txLen < len(header) {
		return fmt.Errorf("write truncated")
	}

	// send the record fragment.
	offset := 0
	for offset < len(rec.Fragment) {
		txLen, err := conn.Write(rec.Fragment[offset:])
		if err != nil {
			return err
		}
		offset += txLen
	}

	return nil
}

func sendClientHello(conn *net.TCPConn, data []byte) error {
	recLength := len(data) + 4
	if recLength > tlsproto.RecordMaxLength {
		return fmt.Errorf("record protocol overflow")
	}

	// Rebuild the record and handshake header in case they changed.
	headers := [9]byte{}
	headers[0] = uint8(tlsproto.ContentTypeHandshake)
	binary.BigEndian.PutUint16(headers[1:3], uint16(tlsproto.VersionTls10))
	binary.BigEndian.PutUint16(headers[3:5], uint16(recLength))
	hsHeader := uint32(tlsproto.HandshakeTypeClientHello) << 24
	hsHeader += uint32(len(data))
	binary.BigEndian.PutUint32(headers[5:9], hsHeader)

	// Send the record header.
	n, err := conn.Write(headers[:])
	if err != nil {
		return err
	}
	if n != len(headers) {
		return fmt.Errorf("client hello truncated")
	}

	// Resend the ClientHello message
	txLen := 0
	for txLen < len(data) {
		n, err := conn.Write(data[txLen:])
		if err != nil {
			return err
		}
		txLen += n
	}

	return nil
}

func (tcon *TlsConnection) handleRequest(ctx context.Context) error {
	record, err := readRecord(tcon.client)
	if err != nil {
		return err
	}
	if record.Type != tlsproto.ContentTypeHandshake {
		return fmt.Errorf("invalid record type")
	}
	if len(record.Fragment) < 4 {
		return fmt.Errorf("tls handshake truncated")
	}
	tcon.recordVersion = record.Version

	// The handshake should start with a client hello. Anything else is an error.
	hsHeader := binary.BigEndian.Uint32(record.Fragment[0:4])
	hsType := tlsproto.HandshakeType((hsHeader >> 24) & 0xff)
	hsLength := int(hsHeader & 0xffffff)
	if hsType != tlsproto.HandshakeTypeClientHello {
		return fmt.Errorf("unexpected handshake type")
	}
	hsEnd := int(4 + hsLength)
	if hsEnd > len(record.Fragment) {
		return fmt.Errorf("tls handshake truncated")
	}
	tcon.helloData = record.Fragment[4:hsEnd]

	// Parse the ClientHello
	err = tcon.ClientHello.Unmarshal(tcon.helloData)
	if err != nil {
		return err
	}

	// Step 3: Process the handshake record.
	err = tcon.processClientHello()
	if err != nil {
		return fmt.Errorf("handshake error: %v", err)
	}

	// Handshake processing is done, it's now up to the router to decide what
	// to do with this connection.
	return nil
}

// handleInbound continues to process records from the client in case we need
// to decrypt any retried client hellos.
func (tcon *TlsConnection) handleInbound() error {
	for !tcon.serverHelloDone {
		// Read the next record
		record, err := readRecord(tcon.client)
		if err != nil {
			return err
		}

		// HACK: Drop inbound ChangeCipherSpecs before getting a ServerHello I
		// am not sure if this is a Firefox bug or an OpenSSL bug but it seems
		// that:
		//  - Firefox sends ECH
		//  - OpenSSL responds with: HRR | ChangeCipherSpec
		//  - OpenSSL drops all state for this connection
		//  - Firefox responds with: ChangeCipherSpec | ECH
		//  - OpenSSL encounters a ChangeCipherSpec before CH and throws an error.
		//
		// To workaround this, if we find an inbound ChangeCipherSpec while
		// waiting for a hello retry, just drop it.
		if record.Type == tlsproto.ContentTypeChangeCipherSpec &&
			len(record.Fragment) == 1 && record.Fragment[0] == 0x01 {
			continue
		}

		// If it's anything other than a client hello, send it to the backend.
		if record.Type != tlsproto.ContentTypeHandshake {
			err = sendRecord(tcon.backend, record)
			if err != nil {
				return err
			}
			continue
		}
		if len(record.Fragment) < 4 {
			return fmt.Errorf("tls handshake truncated")
		}
		hsHeader := binary.BigEndian.Uint32(record.Fragment[0:4])
		hsType := tlsproto.HandshakeType((hsHeader >> 24) & 0xff)
		hsLength := int(hsHeader & 0xffffff)
		hsEnd := int(4 + hsLength)
		if hsEnd > len(record.Fragment) {
			return fmt.Errorf("tls handshake truncated")
		}
		if hsType != tlsproto.HandshakeTypeClientHello {
			err = sendRecord(tcon.backend, record)
			if err != nil {
				return err
			}
			continue
		}
		hsData := record.Fragment[4:hsEnd]

		// Parse the client hello
		hello := tlsproto.ClientHello{}
		err = hello.Unmarshal(hsData)
		if err != nil {
			return err
		}

		// Handle the encrypted client hello extension, if any.
		for _, ext := range hello.Extensions {
			if ext.ExtType != tlsproto.ExtTypeEncryptedClientHello {
				continue
			}
			err := tcon.processEncryptedHello(&ext, &hello, hsData)
			if err != nil {
				return err
			}
			// Reconstruct the ClientHelloInner
			blob, err := hello.Marshal()
			if err != nil {
				return err
			}
			hsData = blob
		}

		// Resend the ClientHello
		err = sendClientHello(tcon.backend, hsData)
		if err != nil {
			return err
		}
	}

	// Once the server hello has been received, we can begin proxying records
	// without needing to do any parsing.
	_, err := io.Copy(tcon.backend, tcon.client)
	return err
}

// handleOutbound intercepts records from the backend and forwards them to the
// client until we happen upon a ServerHello after which we just connect the
// pipes and let the data flow between client and server.
func (tcon *TlsConnection) handleOutbound() error {
	for {
		// Read the next record and resend it to the client.
		record, err := readRecord(tcon.backend)
		if err != nil {
			return err
		}
		err = sendRecord(tcon.client, record)
		if err != nil {
			return err
		}

		// If it's anything other than a server hello, send it to the client.
		if record.Type != tlsproto.ContentTypeHandshake {
			continue
		}
		if len(record.Fragment) < 4 {
			return fmt.Errorf("tls handshake truncated")
		}
		hsHeader := binary.BigEndian.Uint32(record.Fragment[0:4])
		hsType := tlsproto.HandshakeType((hsHeader >> 24) & 0xff)
		hsLength := int(hsHeader & 0xffffff)
		hsEnd := int(4 + hsLength)
		if hsEnd > len(record.Fragment) {
			return fmt.Errorf("tls handshake truncated")
		}
		if hsType != tlsproto.HandshakeTypeServerHello {
			continue
		}

		// Parse the server hello and check for downgrades or retry requests
		hello := tlsproto.ServerHello{}
		err = hello.Unmarshal(record.Fragment[4:hsEnd])
		if err != nil {
			return err
		}

		// TODO: At this point, we can check to see if the backend really does
		// support ECH by calculating the ECH acceptance confirmation. If we
		// find that the server doesn't support it, we should probably complain
		// loudly - since we already know this connection is going to fail.

		// Log the connection, if verbose logging is enabled.
		if tcon.config.verbose {
			log.Printf("TLS Server Hello Received")
			log.Printf("  Version: %s", hello.GetVersion().String())
			log.Printf("  Random: %s", base64.StdEncoding.EncodeToString(hello.Random[:]))
			log.Printf("  Session ID: %s", base64.StdEncoding.EncodeToString(hello.SessionId))
			log.Printf("  Cipher: %s", hello.CipherSuite.String())
			log.Printf("  Compression: 0x%02x", hello.CompressionMethod)
			log.Printf("  Extensions:")
			for _, ext := range hello.Extensions {
				log.Printf("    0x%04x", ext.ExtType)
			}
		}

		// Check for a TLS1.3 Hello Retry Request, otherwise the connection can
		// begin proxying data.
		if hello.GetVersion() < tlsproto.VersionTls13 {
			tcon.serverHelloDone = true
			break
		}
		if !hello.IsRetryRequest() {
			tcon.serverHelloDone = true
			break
		}
	}

	// Once the server hello has been received, we can begin proxying records
	// without needing to do any parsing.
	_, err := io.Copy(tcon.client, tcon.backend)
	return err
}

func (tcon *TlsConnection) processClientHello() error {
	// Check for encrypted client hellos
	for _, ext := range tcon.ClientHello.Extensions {
		if ext.ExtType != tlsproto.ExtTypeEncryptedClientHello {
			continue
		}
		err := tcon.processEncryptedHello(&ext, &tcon.ClientHello, tcon.helloData)
		if err != nil {
			return err
		}
		// Reconstruct the ClientHelloInner
		blob, err := tcon.ClientHello.Marshal()
		if err != nil {
			return err
		}
		tcon.helloData = blob
	}

	tcon.Versions = make([]tlsproto.ProtocolVersion, 1)
	tcon.Versions[0] = tcon.ClientHello.Version

	// Parse for useful extensions
	for _, ext := range tcon.ClientHello.Extensions {
		switch ext.ExtType {
		case tlsproto.ExtTypeServerName:
			sni, err := ext.ParseServerName()
			if err != nil {
				return err
			}
			tcon.ServerNames = sni.ServerNames
		case tlsproto.ExtTypeAlpn:
			alpn, err := ext.ParseAlpnProtocols()
			if err != nil {
				return err
			}
			tcon.AlpnProtocols = alpn.AlpnProtocols
		case tlsproto.ExtTypeSupportedVersions:
			versions, err := ext.ParseSupportedVersions()
			if err != nil {
				return err
			}
			tcon.Versions = versions.Versions
		}
	}

	// DEBUG!
	if tcon.config.verbose {
		log.Printf("TLS ClientHello Received")
		log.Printf("  Version: %s", tcon.ClientHello.Version.String())
		log.Printf("  Random: %s", base64.StdEncoding.EncodeToString(tcon.ClientHello.Random[:]))
		log.Printf("  Session ID: %s", base64.StdEncoding.EncodeToString(tcon.ClientHello.SessionId))
		log.Printf("  Ciphers:")
		for _, suite := range tcon.ClientHello.CipherSuites {
			log.Printf("    %s", suite.String())
		}
		log.Printf("  Compression:")
		for _, method := range tcon.ClientHello.CompressionMethods {
			log.Printf("    0x%02x", method)
		}
		log.Printf("  Extensions:")
		for _, ext := range tcon.ClientHello.Extensions {
			log.Printf("    0x%04x", ext.ExtType)
		}
		log.Printf("  Server Names:")
		for _, name := range tcon.ServerNames {
			log.Printf("    %s", name)
		}
		log.Printf("  Application Protocols:")
		for _, protocol := range tcon.AlpnProtocols {
			log.Printf("    %s", protocol)
		}
		log.Printf("  Supported Versions:")
		for _, version := range tcon.Versions {
			log.Printf("    %s", version.String())
		}
	}

	// Success - it's now up to the router to handle this message.
	return nil
}

func (tcon *TlsConnection) Close() (err error) {
	if tcon.backend != nil {
		backendErr := tcon.backend.Close()
		if err != nil {
			err = backendErr
		}
	}
	if tcon.client != nil {
		clientErr := tcon.client.Close()
		if err != nil {
			err = clientErr
		}
	}
	return err
}
