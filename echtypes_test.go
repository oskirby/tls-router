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
	"testing"

	"golang.org/x/exp/constraints"
	"github.com/cloudflare/circl/hpke"
)

func compareInteger[T constraints.Integer](result T, expect T) error {
	if expect == result {
		return nil
	}
	return fmt.Errorf("expected %d got %d", expect, result)
}

func compareStrings(result string, expect string) error {
	if expect == result {
		return nil
	}
	return fmt.Errorf("expected '%s' got '%s", expect, result)
}

func TestEchSvcbExample(t *testing.T) {
	// The example ECH from https://datatracker.ietf.org/doc/draft-ietf-tls-svcb-ech/
	echExample := "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA="
	echBinary, err := base64.StdEncoding.DecodeString(echExample)
	if err != nil {
		t.Fatalf("base64 decoding failed: %v", err)
	}

	// The expected values to parse.
	//expectConfigId := uint8(1)
	//expectKemId := hpke.KEM_X25519_HKDF_SHA256
	//expectPubkey := 
	//expectMaxName := 100
	//expectCipherKdf := hpke.KDF_HKDF_SHA256
	//expectCipherAead := hpke.AEAD_AES128GCM
	//expectPubName := "ech-sitess.example.net"

	// Parse the ECH config list.
	list := ECHConfigList{}
	err = list.UnmarshalBinary(echBinary)
	if err != nil {
		t.Fatalf("ech decoding failed: %v", err)
	}
	if len(list) == 0 {
		t.Fatalf("ech decoding returned empty results")
	}
	if len(list) > 1 {
		t.Errorf("ech decoding returned too many results")
	}

	// Ensure that we got the expectd values
	ech := list[0]
	if err := compareInteger(ech.ConfigId, 1); err != nil {
		t.Errorf("config_id mismatch: %v", err)
	}
	if err := compareInteger(uint16(ech.KemId), uint16(hpke.KEM_X25519_HKDF_SHA256)); err != nil {
		t.Errorf("kem_id mismatch: %v", err)
	}
	if err := compareStrings(HpkeKemString(hpke.KEM(ech.KemId)), "X25519-HKDF-SHA256"); err != nil {
		t.Errorf("kem_id mismatch: %v", err)
	}
	expectPubkey := "HXfrHFItCGBbF51CFO5KNjXffhfDNuqQBmVac/yq1j4="
	if err := compareStrings(base64.StdEncoding.EncodeToString(ech.PublicKey), expectPubkey); err != nil {
		t.Errorf("public_key mismatch: %v", err)
	}
	if err := compareInteger(ech.MaxNameLength, 100); err != nil {
		t.Errorf("maximum_name_length mismatch: %v", err)
	}
	if err := compareStrings(ech.PublicName, "ech-sites.example.net"); err != nil {
		t.Errorf("public_key mismatch: %v", err)
	}
	if err := compareInteger(len(ech.CipherSuites), 1); err != nil {
		t.Errorf("cipher_suites length mismatch: %v", err)
	}

	cipher := ech.CipherSuites[0]
	if err := compareInteger(uint16(cipher.KdfId), uint16(hpke.KDF_HKDF_SHA256)); err != nil {
		t.Errorf("cipher_suites kdf mismatch: %v", err)
	}
	if err := compareStrings(HpkeKdfString(hpke.KDF(cipher.KdfId)), "HKDF-SHA256"); err != nil {
		t.Errorf("cipher_suites kdf mismatch: %v", err)
	}
	if err := compareInteger(uint16(cipher.AeadId), uint16(hpke.AEAD_AES128GCM)); err != nil {
		t.Errorf("cipher_suites aead mismatch: %v", err)
	}
	if err := compareStrings(HpkeAeadString(hpke.AEAD(cipher.AeadId)), "AES128GCM"); err != nil {
		t.Errorf("cipher_suites aead mismatch: %v", err)
	}

	// Marshal the structure back into binary and it should be the same as what we started with.
	encodeBinary, err := list.MarshalBinary()
	if err != nil {
		t.Fatalf("ech encoding failed: %v", err)
	}
	encodedBase64 := base64.StdEncoding.EncodeToString(encodeBinary)
	if err := compareStrings(encodedBase64, echExample); err != nil {
		t.Errorf("ech base64 mismatch: %v", err)
	}
}
