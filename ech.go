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
	"fmt"
	"os"

	"github.com/cloudflare/circl/hpke"
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

	return nil
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
