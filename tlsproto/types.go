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
	"fmt"
)

type ProtocolVersion uint16

const (
	VersionTls13 = ProtocolVersion(0x0304)
	VersionTls12 = ProtocolVersion(0x0303)
	VersionTls11 = ProtocolVersion(0x0302)
	VersionTls10 = ProtocolVersion(0x0301)
	VersionSsl30 = ProtocolVersion(0x0300)
)

func (v ProtocolVersion) String() string {
	if v <= VersionSsl30 {
		return fmt.Sprintf("SSL%d.%d", (v >> 8), v&0xff)
	} else if (v >> 8) == 0x03 {
		return fmt.Sprintf("TLS1.%d", (v&0xff)-1)
	} else {
		return fmt.Sprintf("Unknown(0x%04x)", v)
	}
}

type ContentType uint8

const (
	ContentTypeInvalid          = ContentType(0)
	ContentTypeChangeCipherSpec = ContentType(20)
	ContentTypeAlert            = ContentType(21)
	ContentTypeHandshake        = ContentType(22)
	ContentTypeApplicationData  = ContentType(23)
)

type RecordHeader struct {
	ContentType ContentType
	Version     ProtocolVersion
	Length      uint16
}

const RecordMaxLength int = 1 << 14

type HandshakeType uint8

const (
	HandshakeTypeHelloRequest       = HandshakeType(0)
	HandshakeTypeClientHello        = HandshakeType(1)
	HandshakeTypeServerHello        = HandshakeType(2)
	HandshakeTypeCertificate        = HandshakeType(11)
	HandshakeTypeServerKeyExchange  = HandshakeType(12)
	HandshakeTypeCertificateRequest = HandshakeType(13)
	HandshakeTypeServerHelloDone    = HandshakeType(14)
	HandshakeTypeCertificateVerify  = HandshakeType(15)
	HandshakeTypeClientKeyExchange  = HandshakeType(16)
	HandshakeTypeFinished           = HandshakeType(20)
)
