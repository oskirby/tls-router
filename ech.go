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

	"github.com/cloudflare/circl/hpke"
)

type HpkeCipherSuite struct {
	KdfId  hpke.KDF
	AeadId hpke.AEAD
}

type HpkeKey []byte

func (key *HpkeKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var b64string string
	err := unmarshal(&b64string)
	if err != nil {
		return err
	}

	decode, err := base64.StdEncoding.DecodeString(b64string)
	if err != nil {
		return fmt.Errorf("base64 error: %v", err)
	}

	*key = decode
	return nil
}

type ECHConfig struct {
	ConfigId       uint8             `yaml:"config_id"`
	KemId          hpke.KEM          `yaml:"kem_id"`
	PrivateKey     HpkeKey           `yaml:"private_key,omitempty"`
	PrivateKeyFile string            `yaml:"private_key_file,omitempty"`
	CipherSuites   []HpkeCipherSuite `yaml:"cipher_suites"`
	PublicName     string            `yaml:"public_name"`
}
