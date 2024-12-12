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

import ()

type HpkeSymmetricCipherSuite struct {
	KdfId  HpkeKdf
	AeadId HpkeAead
}

type ECHConfig struct {
	ConfigId     uint8                      `yaml:"config_id"`
	KemId        uint16                     `yaml:"kem_id"`
	PrivateKey   HpkeKey                    `yaml:"private_key"`
	CipherSuites []HpkeSymmetricCipherSuite `yaml:"cipher_suites"`
	PublicName   string                     `yaml:"public_name"`
}
