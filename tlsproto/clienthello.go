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

type ClientHello struct {
	Version            ProtocolVersion
	Random             [32]byte
	SessionId          []byte
	CipherSuites       []CipherSuite
	CompressionMethods []uint8
	Extensions         []Extension
}

func (hello *ClientHello) Unmarshal(data []byte) error {
	if len(data) < 35 {
		return fmt.Errorf("client hello truncated")
	}
	hello.Version = ProtocolVersion(binary.BigEndian.Uint16(data[0:2]))
	copy(hello.Random[:], data[2:34])
	offset := 34

	// Parse the session ID
	if len(data) < offset+1 {
		return fmt.Errorf("client hello truncated")
	}
	sidLength := int(data[offset])
	offset++
	if len(data) < (offset + sidLength) {
		return fmt.Errorf("client hello truncated")
	}
	hello.SessionId = make([]byte, sidLength)
	copy(hello.SessionId, data[offset:offset+sidLength])
	offset += sidLength

	// Parse the cipher suites.
	if len(data) < offset+2 {
		return fmt.Errorf("client hello truncated")
	}
	cipherLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < (offset + cipherLength) {
		return fmt.Errorf("client hello truncated")
	}
	hello.CipherSuites = make([]CipherSuite, cipherLength/2)
	for i := 0; i < cipherLength; i += 2 {
		suite := binary.BigEndian.Uint16(data[offset+i : offset+i+2])
		hello.CipherSuites[i/2] = CipherSuite(suite)
	}
	offset += cipherLength

	// Parse the compression methods.
	if len(data) < offset {
		return fmt.Errorf("client hello truncated")
	}
	compressionLength := int(data[offset])
	offset++
	if len(data) < (offset + compressionLength) {
		return fmt.Errorf("client hello truncated")
	}
	hello.CompressionMethods = make([]uint8, compressionLength)
	copy(hello.CompressionMethods, data[offset:offset+compressionLength])
	offset += compressionLength

	// Parse the extensions
	// TODO: Support SSL3.0 by assuming an empty extension list.
	if len(data) < offset+2 {
		return fmt.Errorf("client hello truncated")
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
			ExtType:   ExtensionType(extType),
			ExtData:   data[offset+4 : extNext],
			ExtOffset: offset+4,
		})
		offset = extNext
	}

	return nil
}
