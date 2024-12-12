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
)

// HPKE RFC9180 Section 7.1: Key Encapsulation Mechanisms (KEMs)
type HpkeKem uint16

const (
	DhkemP256HkdfSha256   HpkeKem = 0x0010
	DhkemP384HkdfSha384   HpkeKem = 0x0011
	DhkemP512HkdfSha512   HpkeKem = 0x0012
	DhkemX25519HkdfSha256 HpkeKem = 0x0020
	DhkemX448HkdfSha512   HpkeKem = 0x0021
)

func (kem *HpkeKem) String() string {
	switch *kem {
	case DhkemP256HkdfSha256:
		return "DHKEM(P-256,HKDF-SHA256)"
	case DhkemP384HkdfSha384:
		return "DHKEM(P-384,HKDF-SHA384)"
	case DhkemP512HkdfSha512:
		return "DHKEM(P-521,HKDF-SHA512)"
	case DhkemX25519HkdfSha256:
		return "DHKEM(X25519,HKDF-SHA256)"
	case DhkemX448HkdfSha512:
		return "DHKEM(X448,HKDF-SHA512)"
	default:
		return fmt.Sprintf("Unknown-%04x", kem)
	}
}

// HPKE RFC9180 Section 7.2: Key Derivation Functions (KDFs)
type HpkeKdf uint16

const (
	HkdfSha256 HpkeKdf = 0x0001
	HkdfSha384 HpkeKdf = 0x0002
	HkdfSha512 HpkeKdf = 0x0003
)

func (kdf *HpkeKdf) String() string {
	switch *kdf {
	case HkdfSha256:
		return "HKDF-SHA256"
	case HkdfSha384:
		return "HKDF-SHA384"
	case HkdfSha512:
		return "HKDF-512"
	default:
		return fmt.Sprintf("Unknown-%04x", kdf)
	}
}

// HPKE RFC9180 Section 7.3: Authenticated Encryption with Associated Data (AEAD) Functions
type HpkeAead uint16

const (
	AeadAes128Gcm        HpkeAead = 0x0001
	AeadAes256Gcm        HpkeAead = 0x0002
	AeadChaCha20Poly1035 HpkeAead = 0x0003
	AeadExportOnly       HpkeAead = 0xffff
)

func (aead *HpkeAead) String() string {
	switch *aead {
	case AeadAes128Gcm:
		return "AES-128-GCM"
	case AeadAes256Gcm:
		return "AES-256-GCM"
	case AeadChaCha20Poly1035:
		return "ChaCha20Poly1305"
	case AeadExportOnly:
		return "Export-only"
	default:
		return fmt.Sprintf("Unknown-%04x", aead)
	}
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
