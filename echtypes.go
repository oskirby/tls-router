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
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

type HpkeCipherSuite struct {
	KdfId  hpke.KDF
	AeadId hpke.AEAD
}

func (cipher *HpkeCipherSuite) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var cipherString string
	err := unmarshal(&cipherString)
	if err != nil {
		return err
	}
	kdfString, aeadString, found := strings.Cut(cipherString, ",")
	if !found {
		return fmt.Errorf("invalid cipher sute: %s", cipherString)
	}

	kdfVal, err := HpkeKdfParse(kdfString)
	if err != nil {
		return err
	}
	aeadVal, err := HpkeAeadParse(aeadString)
	if err != nil {
		return err
	}
	cipher.KdfId = kdfVal
	cipher.AeadId = aeadVal
	return nil
}

type HpkeKem hpke.KEM

func (kem *HpkeKem) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var kstring string
	err := unmarshal(&kstring)
	if err != nil {
		return err
	}

	kval, err := HpkeKemParse(kstring)
	if err != nil {
		return err
	}
	*kem = HpkeKem(kval)
	return nil
}

type ECHConfigContents struct {
	ConfigId       uint8             `yaml:"config_id"`
	KemId          HpkeKem           `yaml:"kem_id"`
	PublicKey      HpkeKey           `yaml:"public_key,omitempty"`
	CipherSuites   []HpkeCipherSuite `yaml:"cipher_suites"`
	MaxNameLength  uint8             `yaml:"maximum_name_length,omitempty"`
	PublicName     string            `yaml:"public_name"`

	// For the server implementation
	PrivateKey     HpkeKey           `yaml:"private_key,omitempty"`
	PrivateKeyFile string            `yaml:"private_key_file,omitempty"`
	hpkePrivateKey kem.PrivateKey
}

func (ech *ECHConfigContents) MarshalBinary() ([]byte, error) {
	// Start with the HpkeKeyConfig
	blob := make([]byte, 11 + len(ech.PublicKey) + 4 * len(ech.CipherSuites) + len(ech.PublicName))
	blob[0] = ech.ConfigId
	binary.BigEndian.PutUint16(blob[1:3], uint16(ech.KemId))

	// Public key
	binary.BigEndian.PutUint16(blob[3:5], uint16(len(ech.PublicKey)))
	copy(blob[5:5+len(ech.PublicKey)], ech.PublicKey)
	offset := 5 + len(ech.PublicKey)

	// Cipher Suites
	binary.BigEndian.PutUint16(blob[offset:offset+2], uint16(4 * len(ech.CipherSuites)))
	offset += 2	
	for _, cipher := range ech.CipherSuites {
		binary.BigEndian.PutUint16(blob[offset:offset+2], uint16(cipher.KdfId))
		binary.BigEndian.PutUint16(blob[offset+2:offset+4], uint16(cipher.AeadId))
		offset += 4
	}

	blob[offset] = ech.MaxNameLength
	offset++
	blob[offset] = uint8(len(ech.PublicName))
	offset++
	copy(blob[offset:offset+len(ech.PublicName)], []byte(ech.PublicName))
	offset += len(ech.PublicName)

	// TODO: Extensions...
	binary.BigEndian.PutUint16(blob[offset:offset+2], 0)

	return blob, nil
}

func (contents *ECHConfigContents) UnmarshalBinary(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf("ech config contents truncated")
	}
	contents.ConfigId = data[0]
	contents.KemId = HpkeKem(binary.BigEndian.Uint16(data[1:3]))
	pubkeyLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5 + pubkeyLen {
		return fmt.Errorf("ech config pubkey truncated")
	}
	contents.PublicKey = HpkeKey(data[5:5+pubkeyLen])

	// Parse the cipher_suites list
	offset := 5 + pubkeyLen
	if len(data) < (offset + 2) {
		return fmt.Errorf("ech config ciphers truncated")
	}
	ciphersLen := int(binary.BigEndian.Uint16(data[offset:offset+2]))
	offset += 2

	ciphersEnd := offset + ciphersLen
	if len(data) < ciphersEnd {
		return fmt.Errorf("ech ciphers truncated")
	}
	for offset < ciphersEnd {
		if offset + 4 > ciphersEnd {
			return fmt.Errorf("ech cipher truncated")
		}
		kdf := binary.BigEndian.Uint16(data[offset:offset+2])
		aead := binary.BigEndian.Uint16(data[offset+2:offset+4])
		contents.CipherSuites = append(contents.CipherSuites, HpkeCipherSuite{
			KdfId: hpke.KDF(kdf),
			AeadId: hpke.AEAD(aead),
		})
		offset += 4
	}

	// Parse the maximum name length.
	if len(data) <= offset {
		return fmt.Errorf("ech max name length truncated")
	}
	contents.MaxNameLength = data[offset]
	offset++

	// Parse the public name
	if len(data) <= offset {
		return fmt.Errorf("ech max name length truncated")
	}
	pubNameLength := int(data[offset])
	offset++
	if len(data) < offset + pubNameLength {
		return fmt.Errorf("ech public name truncated")
	}
	contents.PublicName = string(data[offset:offset+pubNameLength])

	// TODO: Extensions
	return nil
}

type ECHConfigList []ECHConfigContents

func (list ECHConfigList) MarshalBinary() ([]byte, error) {
	result := make([]byte, 2)
	for _, ech := range list {
		blob, err := ech.MarshalBinary()
		if err != nil {
			return nil, err
		}
		header := [4]byte{0, 0, 0, 0}
		binary.BigEndian.PutUint16(header[0:2], ECHVersion)
		binary.BigEndian.PutUint16(header[2:4], uint16(len(blob)))
		result = append(result, header[:]...)
		result = append(result, blob...)
	}

	echLength := len(result) - 2
	if echLength > 0xffff {
		return nil, fmt.Errorf("ech length overflow")
	}
	binary.BigEndian.PutUint16(result[0:2], uint16(echLength))
	return result, nil
}

func (list *ECHConfigList) UnmarshalBinary(data []byte) error {
	// Parse the overall size of the ECHConfig
	if len(data) < 2 {
		return fmt.Errorf("ech config list truncated")
	}
	totalLength := int(binary.BigEndian.Uint16(data[0:2]))
	if (totalLength+2) > len(data) {
		return fmt.Errorf("ech config list overflow")
	}

	// Parse the ECHConfigs from the list
	offset := 2
	echEnd := offset + totalLength
	for offset < echEnd {
		if offset + 4 > echEnd {
			return fmt.Errorf("ech config truncated")
		}
		echVersion := binary.BigEndian.Uint16(data[offset:offset+2])
		if echVersion != ECHVersion {
			return fmt.Errorf("ech version 0x%04x not supported", echVersion)
		}
		echLength := int(binary.BigEndian.Uint16(data[offset+2:offset+4]))
		echNext := offset + 4 + echLength
		if echNext > echEnd  {
			return fmt.Errorf("ech config truncated")
		}

		cfg := ECHConfigContents{}
		err := cfg.UnmarshalBinary(data[offset+4:echNext])
		if err != nil {
			return err
		}
		*list = append(*list, cfg)
		offset = echEnd
	}

	return nil
}
