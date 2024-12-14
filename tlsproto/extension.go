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

package tlsproto

import (
	"encoding/binary"
	"fmt"
)

type ExtensionType uint16

const (
	ExtTypeServerName                 = ExtensionType(0)
	ExtTypeMaxFragmentLength          = ExtensionType(1)
	ExtTypeStatusRequest              = ExtensionType(5)
	ExtTypeSupportedGroups            = ExtensionType(10)
	ExtTypeSignatureAlgorithms        = ExtensionType(13)
	ExtTypeUseStrp                    = ExtensionType(14)
	ExtTypeHeartbeat                  = ExtensionType(15)
	ExtTypeAlpn                       = ExtensionType(16)
	ExtTypeSignedCertificateTimestamp = ExtensionType(16)
	ExtTypeClientCertificateType      = ExtensionType(19)
	ExtTypeServerCertificateType      = ExtensionType(20)
	ExtTypePadding                    = ExtensionType(21)
	ExtTypePresharedKey               = ExtensionType(41)
	ExtTypeEarlyData                  = ExtensionType(42)
	ExtTypeSupportedVersions          = ExtensionType(43)
	ExtTypeCookie                     = ExtensionType(44)
	ExtTypePskKeyExchangeModes        = ExtensionType(45)
	ExtTypeCertificateAuthorities     = ExtensionType(47)
	ExtTypeOidFilters                 = ExtensionType(48)
	ExtTypePostHandshakeAuth          = ExtensionType(49)
	ExtTypeSignatureAlgorithmsCert    = ExtensionType(50)
	ExtTypeEchOuterExtensions         = ExtensionType(0xfd00)
	ExtTypeEncryptedClientHello       = ExtensionType(0xfe0d)
)

type Extension struct {
	ExtType ExtensionType
	ExtData []byte
}

type ExtServerName struct {
	Extension
	ServerNames []string
}

func (ext *Extension) ParseServerName() (*ExtServerName, error) {
	sni := ExtServerName{Extension: *ext}

	if len(ext.ExtData) < 2 {
		return nil, fmt.Errorf("malformed sni")
	}
	sniLength := int(binary.BigEndian.Uint16(ext.ExtData[0:2]))
	sniEnd := 2 + sniLength
	if len(ext.ExtData) < sniEnd {
		return nil, fmt.Errorf("malformed sni")
	}
	offset := 2

	for offset < sniEnd {
		sniType := ext.ExtData[offset]
		if sniType != 0 {
			return nil, fmt.Errorf("unsupported sni type")
		}
		if (offset + 3) > sniEnd {
			return nil, fmt.Errorf("malformed sni")
		}
		sniNameLen := int(binary.BigEndian.Uint16(ext.ExtData[offset+1 : offset+3]))
		sniNext := offset + 3 + sniNameLen
		if sniNext > sniEnd {
			return nil, fmt.Errorf("malformed sni")
		}
		sni.ServerNames = append(sni.ServerNames, string(ext.ExtData[offset+3:sniNext]))
		offset = sniNext
	}

	return &sni, nil
}

type ExtAlpnProtocols struct {
	Extension
	AlpnProtocols []string
}

func (ext *Extension) ParseAlpnProtocols() (*ExtAlpnProtocols, error) {
	alpn := ExtAlpnProtocols{Extension: *ext}

	if len(ext.ExtData) < 2 {
		return nil, fmt.Errorf("malformed alpn")
	}
	alpnLength := int(binary.BigEndian.Uint16(ext.ExtData[0:2]))
	alpnEnd := 2 + alpnLength
	if len(ext.ExtData) < alpnEnd {
		return nil, fmt.Errorf("malformed alpn")
	}
	offset := 2

	for offset < alpnEnd {
		nameLen := int(ext.ExtData[offset])
		alpnNext := offset + 1 + nameLen
		if alpnNext > alpnEnd {
			return nil, fmt.Errorf("malformed alpn")
		}
		alpn.AlpnProtocols = append(alpn.AlpnProtocols, string(ext.ExtData[offset+1:alpnNext]))
		offset = alpnNext
	}

	return &alpn, nil
}

type ExtSupportedVersions struct {
	Extension
	Versions []ProtocolVersion
}

func (ext *Extension) ParseSupportedVersions() (*ExtSupportedVersions, error) {
	versions := ExtSupportedVersions{Extension: *ext}

	if len(ext.ExtData) == 0 {
		return nil, fmt.Errorf("malformed alpn")
	}
	vLength := int(ext.ExtData[0])
	if len(ext.ExtData) < vLength+1 {
		return nil, fmt.Errorf("malformed versions")
	}
	vEnd := 1 + vLength
	for offset := 1; offset+2 <= vEnd; offset += 2 {
		value := binary.BigEndian.Uint16(ext.ExtData[offset : offset+2])
		versions.Versions = append(versions.Versions, ProtocolVersion(value))
	}

	return &versions, nil
}

type ECHClientHelloType uint8

const (
	ECHClientHelloOuter = ECHClientHelloType(0)
	ECHClientHelloInner = ECHClientHelloType(1)
)

type ExtEncryptedClientHello struct {
	Extension
	Type       ECHClientHelloType
	CipherKdf  uint16
	CipherAead uint16
	ConfigId   uint8
	Enc        []byte
	Payload    []byte

	// Not sure if we need this?
	PayloadOffset int
}

func (ext *Extension) ParseEncryptedClientHello() (*ExtEncryptedClientHello, error) {
	ech := ExtEncryptedClientHello{Extension: *ext}

	// Parse the ECH extension type
	if len(ech.ExtData) == 0 {
		return nil, fmt.Errorf("ech malformed extension")
	}
	ech.Type = ECHClientHelloType(ech.ExtData[0])
	if ech.Type == ECHClientHelloInner {
		return &ech, nil
	}
	if ech.Type != ECHClientHelloOuter {
		return nil, fmt.Errorf("ech malformed extension")
	}

	// Parse the outer extension fields.
	if len(ech.ExtData) < 8 {
		return nil, fmt.Errorf("ech malformed extension")
	}
	ech.CipherKdf = binary.BigEndian.Uint16(ech.ExtData[1:3])
	ech.CipherAead = binary.BigEndian.Uint16(ech.ExtData[3:5])
	ech.ConfigId = ech.ExtData[5]

	// Parse the HPKE encapsulated key
	keyLen := int(binary.BigEndian.Uint16(ech.ExtData[6:8]))
	offset := 8
	if len(ech.ExtData) < offset+keyLen+2 {
		return nil, fmt.Errorf("ech malformed extension")
	}
	ech.Enc = ech.ExtData[offset : offset+keyLen]
	offset += keyLen

	// Parse the encrypted payload
	payloadLen := int(binary.BigEndian.Uint16(ech.ExtData[offset : offset+2]))
	offset += 2
	if len(ech.ExtData) < offset+payloadLen {
		return nil, fmt.Errorf("ech malformed extension")
	}
	ech.Payload = ech.ExtData[offset : offset+payloadLen]

	return &ech, nil
}

type ExtEchOuterExtensions struct {
	Extension
	OuterExtensions []ExtensionType
}

func (ext *Extension) ParseEchOuterExtensions() (*ExtEchOuterExtensions, error) {
	echOuter := ExtEchOuterExtensions{Extension: *ext}

	if len(ext.ExtData) == 0 {
		return nil, fmt.Errorf("malformed alpn")
	}
	echOuterLength := int(ext.ExtData[0])
	if len(ext.ExtData) < echOuterLength+1 {
		return nil, fmt.Errorf("malformed versions")
	}

	echOuterEnd := 1 + echOuterLength
	for offset := 1; offset+2 <= echOuterEnd; offset += 2 {
		value := binary.BigEndian.Uint16(ext.ExtData[offset : offset+2])
		echOuter.OuterExtensions = append(echOuter.OuterExtensions, ExtensionType(value))
	}

	return &echOuter, nil
}
