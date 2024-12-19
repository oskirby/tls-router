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
	"bytes"
	"encoding/binary"
	"fmt"
)

type ServerHello struct {
	Version           ProtocolVersion
	Random            [32]byte
	SessionId         []byte
	CipherSuite       CipherSuite
	CompressionMethod uint8
	Extensions        []Extension
}

func (hello *ServerHello) Unmarshal(data []byte) error {
	if len(data) < 35 {
		return fmt.Errorf("server hello truncated")
	}
	hello.Version = ProtocolVersion(binary.BigEndian.Uint16(data[0:2]))
	copy(hello.Random[:], data[2:34])
	offset := 34

	// Parse the session ID
	if len(data) < offset+1 {
		return fmt.Errorf("server hello truncated")
	}
	sidLength := int(data[offset])
	offset++
	if len(data) < (offset + sidLength) {
		return fmt.Errorf("server hello truncated")
	}
	hello.SessionId = make([]byte, sidLength)
	copy(hello.SessionId, data[offset:offset+sidLength])
	offset += sidLength

	// Parse the cipher suite and compression method.
	if len(data) < offset+3 {
		return fmt.Errorf("server hello truncated")
	}
	hello.CipherSuite = CipherSuite(binary.BigEndian.Uint16(data[offset : offset+2]))
	hello.CompressionMethod = data[offset+2]
	offset += 3

	// For SSL3.0 and below, there are no extensions and we can stop here.
	hello.Extensions = nil
	if hello.Version <= VersionSsl30 {
		return nil
	}

	// Parse the extensions
	if len(data) < offset+2 {
		return fmt.Errorf("server hello truncated")
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen
	for offset < extEnd {
		if (offset + 4) > extEnd {
			break
		}
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		extNext := offset + 4 + extLen
		if extNext > extEnd {
			break
		}
		hello.Extensions = append(hello.Extensions, Extension{
			ExtType:    ExtensionType(extType),
			ExtData:    data[offset+4 : extNext],
			ExtContext: HandshakeTypeServerHello,
		})
		offset = extNext
	}

	return nil
}

// TLS1.3 embeds special meaning in the server random bytes.
var HelloRetryRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}
var HelloDowngradeTls12 = []byte{
	0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01,
}
var HelloDowngradeTls11 = []byte{
	0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00,
}

// GetVersion returns the negotiated protocol version, which might be in the
// TLS1.3 supported versions extension.
func (hello *ServerHello) GetVersion() ProtocolVersion {
	for _, ext := range hello.Extensions {
		if ext.ExtType != ExtTypeSupportedVersions {
			continue
		}
		if len(ext.ExtData) < 2 {
			break
		}
		return ProtocolVersion(binary.BigEndian.Uint16(ext.ExtData[0:2]))
	}
	return hello.Version
}

func (hello *ServerHello) IsRetryRequest() bool {
	return bytes.Compare(hello.Random[:], HelloRetryRandom) == 0
}
