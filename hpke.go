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
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"golang.org/x/exp/constraints"
)

func hpkeIdString[T constraints.Integer](id T, dict map[T]string) string {
	s, ok := dict[id]
	if ok {
		return s
	} else {
		return fmt.Sprintf("UKNOWN-%x", id)
	}
}

func hpkeIdParse[T constraints.Integer](s string, dict map[T]string) (T, error) {
	// If the string can be parsed as an integer, use that.
	uval, err := strconv.ParseUint(s, 0, 16)
	if err == nil {
		return T(uval), nil
	}

	// Iterate through the map to find a matching string.
	ustring := strings.ToUpper(s)
	for val, name := range dict {
		if ustring == name {
			return T(val), nil
		}
	}

	return 0, fmt.Errorf("unable to parse hpke %T from: %s", T(0), s)
}

var hpkeAeadStrings = map[hpke.AEAD]string{
	hpke.AEAD_AES128GCM:        "AES128GCM",
	hpke.AEAD_AES256GCM:        "AES256GCM",
	hpke.AEAD_ChaCha20Poly1305: "CHAHA20POLY1035",
}

func HpkeAeadString(aead hpke.AEAD) string {
	return hpkeIdString(aead, hpkeAeadStrings)
}

func HpkeAeadParse(s string) (hpke.AEAD, error) {
	return hpkeIdParse(s, hpkeAeadStrings)
}

var hpkeKdfStrings = map[hpke.KDF]string{
	hpke.KDF_HKDF_SHA256: "HKDF-SHA256",
	hpke.KDF_HKDF_SHA384: "HKDF-SHA384",
	hpke.KDF_HKDF_SHA512: "HKDF-SHA512",
}

func HpkeKdfString(kdf hpke.KDF) string {
	return hpkeIdString(kdf, hpkeKdfStrings)
}

func HpkeKdfParse(s string) (hpke.KDF, error) {
	return hpkeIdParse(s, hpkeKdfStrings)
}

var hpkeKemStrings = map[hpke.KEM]string{
	hpke.KEM_P256_HKDF_SHA256:        "P256-HKDF-SHA256",
	hpke.KEM_P384_HKDF_SHA384:        "P384-HKDF-SHA384",
	hpke.KEM_P521_HKDF_SHA512:        "P521-HKDF-SHA512",
	hpke.KEM_X25519_HKDF_SHA256:      "X25519-HKDF-SHA256",
	hpke.KEM_X448_HKDF_SHA512:        "X448-HKDF-SHA512",
	hpke.KEM_X25519_KYBER768_DRAFT00: "X25519-KYBER768-DRAFT00",
}

func HpkeKemString(kem hpke.KEM) string {
	return hpkeIdString(kem, hpkeKemStrings)
}

func HpkeKemParse(s string) (hpke.KEM, error) {
	return hpkeIdParse(s, hpkeKemStrings)
}

func RunHpkeGenerateKey(kemstring string) error {
	// Decode the KEM string into the HPKE algorithm.
	kem, err := HpkeKemParse(kemstring)
	if err != nil {
		return err
	}
	if !kem.IsValid() {
		return fmt.Errorf("unsupported hpke kem")
	}

	// Generate the keypair
	_, privkey, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		return err
	}

	// Marshal the keypair into base64 encoding.
	binPrivkey, err := privkey.MarshalBinary()
	if err != nil {
		return err
	}

	// Output the priate key into PEM encoding
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "HPKE PRIVATE KEY",
		Bytes: binPrivkey,
	})
}
