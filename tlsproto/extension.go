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
	ExtTypeEncryptedClientHello       = ExtensionType(0xfe0d)
)

type Extension struct {
	ExtType ExtensionType
	ExtData []byte
}
