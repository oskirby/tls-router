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

	// For SSL3.0 and below, there are no extensions and we can stop here.
	hello.Extensions = nil
	if hello.Version <= VersionSsl30 {
		return nil
	}

	// Parse the extensions
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
			ExtType:    ExtensionType(extType),
			ExtData:    data[offset+4 : extNext],
			ExtContext: HandshakeTypeClientHello,
		})
		offset = extNext
	}

	return nil
}

func (hello *ClientHello) Marshal() ([]byte, error) {
	msgLength := 34
	msgLength += 1 + len(hello.SessionId)
	msgLength += 2 + 2*len(hello.CipherSuites)
	msgLength += 1 + len(hello.CompressionMethods)

	// And the extensions
	extLength := 0
	if hello.Version > VersionTls10 {
		msgLength += 2
		for _, ext := range hello.Extensions {
			extLength += 4 + len(ext.ExtData)
		}
	}

	data := make([]byte, msgLength+extLength)
	binary.BigEndian.PutUint16(data[0:2], uint16(hello.Version))
	copy(data[2:34], hello.Random[:])

	// Encode the session ID
	if len(hello.SessionId) > 255 {
		return nil, fmt.Errorf("session id overflow")
	}
	data[34] = uint8(len(hello.SessionId))
	copy(data[35:35+len(hello.SessionId)], hello.SessionId)
	offset := 35 + len(hello.SessionId)

	// Encode the cipher suites.
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(2*len(hello.CipherSuites)))
	offset += 2
	for _, cipher := range hello.CipherSuites {
		binary.BigEndian.PutUint16(data[offset:offset+2], uint16(cipher))
		offset += 2
	}

	// Encode the compression methods.
	if len(hello.CompressionMethods) > 255 {
		return nil, fmt.Errorf("compression methods overflow")
	}
	data[offset] = uint8(len(hello.CompressionMethods))
	offset++
	copy(data[offset:offset+len(hello.CompressionMethods)], hello.CompressionMethods)
	offset += len(hello.CompressionMethods)

	// Extensions are only supported for TLS1.0 and beyond.
	if hello.Version <= VersionSsl30 {
		return data, nil
	}

	// Encode the extensions
	if extLength > 0xffff {
		return nil, fmt.Errorf("extension overflow")
	}
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(extLength))
	offset += 2
	for _, ext := range hello.Extensions {
		if len(ext.ExtData) > 0xffff {
			return nil, fmt.Errorf("extension overflow")
		}
		binary.BigEndian.PutUint16(data[offset:offset+2], uint16(ext.ExtType))
		binary.BigEndian.PutUint16(data[offset+2:offset+4], uint16(len(ext.ExtData)))
		copy(data[offset+4:offset+4+len(ext.ExtData)], ext.ExtData)
		offset += 4 + len(ext.ExtData)
	}

	return data, nil
}
