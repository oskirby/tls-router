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
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cloudflare/circl/hpke"
	"github.com/oskirby/tls-router/tlsproto"
)

const ECHVersion uint16 = 0xfe0d

func (ech *ECHConfigContents) SetupPrivate() error {
	// Load and validate the HPKE keys
	kem := hpke.KEM(ech.KemId)
	if !kem.IsValid() {
		return fmt.Errorf("unsupported hpke kem: %s", HpkeKemString(kem))
	}
	if len(ech.PrivateKey) == 0 {
		// Load the private key from a file, if provided.
		if len(ech.PrivateKeyFile) == 0 {
			return fmt.Errorf("no private key provided")
		}
		data, err := os.ReadFile(ech.PrivateKeyFile)
		if err != nil {
			return err
		}
		keyblob, err := HpkeKeyParse(string(data))
		if err != nil {
			return err
		}
		ech.PrivateKey = keyblob
	}
	privkey, err := kem.Scheme().UnmarshalBinaryPrivateKey(ech.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid hpke private key: %v", err)
	}
	ech.hpkePrivateKey = privkey

	// Recover the public key.
	pubkey, err := ech.hpkePrivateKey.Public().MarshalBinary()
	if err != nil {
		return fmt.Errorf("hpke public key error: %v", err)
	}
	ech.PublicKey = pubkey

	// Validate the cipher suites
	for _, cipher := range ech.CipherSuites {
		if !cipher.KdfId.IsValid() {
			return fmt.Errorf("unsupported cipher kdf: %s", HpkeKdfString(cipher.KdfId))
		}
		if !cipher.AeadId.IsValid() {
			return fmt.Errorf("unsupported cipher aead: %s", HpkeAeadString(cipher.AeadId))
		}
	}

	// Prepare the echInfoString = "tls ech" || 0x00 || ECHConfig
	blob, err := ech.MarshalBinary()
	if err != nil {
		return err
	}
	ech.echInfoString = make([]byte, 12+len(blob))
	copy(ech.echInfoString[0:7], []byte("tls ech"))
	ech.echInfoString[7] = 0x00
	binary.BigEndian.PutUint16(ech.echInfoString[8:10], ECHVersion)
	binary.BigEndian.PutUint16(ech.echInfoString[10:12], uint16(len(blob)))
	copy(ech.echInfoString[12:], blob)

	return nil
}

func (client *TlsConnection) processEncryptedHello(ext *tlsproto.Extension) error {
	ech, err := ext.ParseEncryptedClientHello()
	if err != nil {
		return err
	}
	if ech.Type != tlsproto.ECHClientHelloOuter {
		return fmt.Errorf("malformed ech outer extension")
	}

	// Lookup the corresponding ECH configuration
	var echConfig *ECHConfigContents = nil
	for index, config := range client.config.ECHConfigs {
		if config.ConfigId == ech.ConfigId {
			echConfig = &client.config.ECHConfigs[index]
			break
		}
	}
	if echConfig == nil {
		return fmt.Errorf("ech config %d not found", ech.ConfigId)
	}

	// Setup the HPKE opener.
	kdf := hpke.KDF(ech.CipherKdf)
	if !kdf.IsValid() {
		return fmt.Errorf("ech invalid kdf")
	}
	aead := hpke.AEAD(ech.CipherAead)
	if !aead.IsValid() {
		return fmt.Errorf("ech invalid aead")
	}
	suite := hpke.NewSuite(hpke.KEM(echConfig.KemId), kdf, aead)
	receiver, err := suite.NewReceiver(echConfig.hpkePrivateKey, echConfig.echInfoString)
	if err != nil {
		return fmt.Errorf("ech receiver failed: %v", err)
	}
	opener, err := receiver.Setup(ech.Enc)
	if err != nil {
		return fmt.Errorf("ech setup failed: %v", err)
	}

	// Make a copy of the payload and then zero the original to produce the
	// ClientHelloOuterAAD. Note that this only works because the extension
	// parsing is zero-copy.
	payload := make([]byte, len(ech.Payload))
	copy(payload, ech.Payload)
	for i := 0; i < len(ech.Payload); i++ {
		ech.Payload[i] = 0
	}

	outerSessionId := client.ClientHello.SessionId

	// Make a copy of the outer extensions, as we will need them to expand
	// the any compressed extensions in the inner client hello.
	outerExts := make([]tlsproto.Extension, len(client.ClientHello.Extensions))
	for index, oex := range client.ClientHello.Extensions {
		outerExts[index] = oex
	}

	// Decrypt the encrypted EncodedClientHelloInner
	decrypt, err := opener.Open(payload, client.helloData)
	if err != nil {
		return fmt.Errorf("ech decrypt failed: %v", err)
	}

	log.Printf("DEBUG: decrypt=%s", base64.StdEncoding.EncodeToString(decrypt))

	// Parse the inner ClientHello
	err = client.ClientHello.Unmarshal(decrypt)
	if err != nil {
		return fmt.Errorf("ech parse error: %v", err)
	}

	// Restore the session ID from the outer client hello.
	client.ClientHello.SessionId = outerSessionId

	// Expand compressed extensions by copying them from the echOuter
	for i := 0; i < len(client.ClientHello.Extensions); i++ {
		ext := client.ClientHello.Extensions[i]
		switch ext.ExtType {
		case tlsproto.ExtTypeEchOuterExtensions:
			value, err := ext.ParseEchOuterExtensions()
			if err != nil {
				return err
			}
			// Expand the outer extensions and splice the extensions back together.
			expanded, err := expandEchOuterExt(value.OuterExtensions, outerExts)
			if err != nil {
				return err
			}
			remainder := client.ClientHello.Extensions[i+1:]
			client.ClientHello.Extensions = append(client.ClientHello.Extensions[:i], expanded...)
			client.ClientHello.Extensions = append(client.ClientHello.Extensions, remainder...)
			i += len(expanded) - 1

		case tlsproto.ExtTypeEncryptedClientHello:
			value, err := ext.ParseEncryptedClientHello()
			if err != nil {
				return err
			}
			if value.Type != tlsproto.ECHClientHelloInner {
				return fmt.Errorf("malformed ech inner extension")
			}
		default:
			break
		}
	}

	// Reconstruct the ClientHelloInner
	blob, err := client.ClientHello.Marshal()
	if err != nil {
		return err
	}
	client.helloData = blob

	return nil
}

func expandEchOuterExt(extTypes []tlsproto.ExtensionType, outer []tlsproto.Extension) ([]tlsproto.Extension, error) {
	oidx := 0
	results := []tlsproto.Extension{}
	for _, etype := range extTypes {
		found := false
		for oidx < len(outer) {
			if outer[oidx].ExtType != etype {
				oidx++
				continue
			}
			results = append(results, outer[oidx])
			found = true
			oidx++
			break
		}
		if !found {
			return nil, fmt.Errorf("ech extension expansion failed")
		}
	}

	return results, nil
}

func RunEchGenerateSvcb(list ECHConfigList) error {
	result, err := list.MarshalBinary()
	if err != nil {
		return err
	}

	// Encode to base64 and output
	encode := base64.StdEncoding.EncodeToString(result)
	fmt.Fprintf(os.Stdout, "ech=%s\n", encode)
	return nil
}
