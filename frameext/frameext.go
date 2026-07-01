// Package frameext implements AAFP frame-level extension encoding and
// decoding per RFC-0002 §6.1.
//
// Wire format per extension:
//
//	[Type:2B][Critical:1B][Reserved:1B][DataLen:4B][Data:N]
//
// This is distinct from handshake-level extensions (RFC-0002 §6.4),
// which use CBOR ExtensionEntry maps.
package frameext

import (
	"encoding/binary"
	"errors"
)

// HeaderSize is the size of a single extension header in bytes.
const HeaderSize = 8

// Extension represents a single frame-level extension.
type Extension struct {
	ExtType  uint16
	Critical bool
	Data     []byte
}

// Encode encodes a list of extensions into the frame body's Extension section.
func Encode(exts []Extension) ([]byte, error) {
	var buf []byte
	for _, ext := range exts {
		if len(ext.Data) > 0xFFFFFFFF {
			return nil, errors.New("frameext: extension data too large")
		}
		header := make([]byte, HeaderSize)
		binary.BigEndian.PutUint16(header[0:2], ext.ExtType)
		if ext.Critical {
			header[2] = 0x01
		}
		header[3] = 0 // reserved
		binary.BigEndian.PutUint32(header[4:8], uint32(len(ext.Data)))
		buf = append(buf, header...)
		buf = append(buf, ext.Data...)
	}
	return buf, nil
}

// Decode parses extensions from the frame body's Extension section.
func Decode(data []byte) ([]Extension, error) {
	var exts []Extension
	pos := 0

	for pos < len(data) {
		if len(data)-pos < HeaderSize {
			return nil, errors.New("frameext: incomplete extension header")
		}

		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		critical := data[pos+2] == 0x01
		// data[pos+3] is reserved, ignored per RFC
		dataLen := binary.BigEndian.Uint32(data[pos+4 : pos+8])
		pos += HeaderSize

		if uint32(len(data)-pos) < dataLen {
			return nil, errors.New("frameext: incomplete extension data")
		}

		extData := make([]byte, dataLen)
		copy(extData, data[pos:pos+int(dataLen)])
		pos += int(dataLen)

		exts = append(exts, Extension{
			ExtType:  extType,
			Critical: critical,
			Data:     extData,
		})
	}

	return exts, nil
}

// FindUnknownCritical returns the type of the first unknown critical
// extension, or 0 if none. knownTypes is the list of extension types
// the implementation understands.
func FindUnknownCritical(exts []Extension, knownTypes []uint16) uint16 {
	for _, ext := range exts {
		if ext.Critical {
			known := false
			for _, kt := range knownTypes {
				if ext.ExtType == kt {
					known = true
					break
				}
			}
			if !known {
				return ext.ExtType
			}
		}
	}
	return 0
}

// FindExtension returns the first extension of the given type, or nil.
func FindExtension(exts []Extension, extType uint16) *Extension {
	for i := range exts {
		if exts[i].ExtType == extType {
			return &exts[i]
		}
	}
	return nil
}
