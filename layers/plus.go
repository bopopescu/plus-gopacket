// Copyright 2017 Roman Müntener. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"github.com/google/gopacket"
	pluspacket "github.com/mami-project/plus-lib/packet"
)

var _ = RegisterLayerTypeDetector(127, &PLUS{})

type PLUS struct {
	BaseLayer
	SFlag        bool
	RFlag        bool
	LFlag        bool
	XFlag        bool
	CAT          uint64
	PSN          uint32
	PSE          uint32
	PCFIntegrity int8
	PCFLen       int8
	PCFType      int32
	PCFValue     []byte
	Magic        uint32
}

func (plus *PLUS) Test(payload []byte, proto string, srcPort uint16, dstPort uint16) bool {

	if len(payload) >= 4 {
		magic := binary.BigEndian.Uint32(payload[0:4]) >> 4

		expected := uint32(0xd8007ff)

		if magic == expected {
			return true
		}
	}

	return false
}

// Utility function for 0/1 -> bool
func toBool(v byte) bool {
	if v == 0 {
		return false
	} else {
		return true
	}
}

func (p *PLUS) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var buf []byte = nil
	var err error

	if p.XFlag {
		_, buf, err = pluspacket.WriteExtendedPacket(
			nil,
			p.LFlag,
			p.RFlag,
			p.SFlag,
			p.CAT,
			p.PSN,
			p.PSE,
			uint16(p.PCFType),
			uint8(p.PCFIntegrity),
			p.PCFValue,
			p.Payload,
		)

		if err != nil {
			return err
		}
	} else {
		_, buf, _ = pluspacket.WriteBasicPacket(
			nil,
			p.LFlag,
			p.RFlag,
			p.SFlag,
			p.CAT,
			p.PSN,
			p.PSE,
			p.Payload,
		)

		
	}

	serBuf, err := b.PrependBytes(len(buf))

	if err != nil {
		return err
	}

	copy(serBuf, buf)

	return nil
}

func (plus *PLUS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	magicAndFlags := data[0:4]

	p := plus

	p.Magic = binary.BigEndian.Uint32(magicAndFlags) >> uint32(4)
	p.XFlag = toBool(data[3] & 0x01)
	p.LFlag = toBool((data[3] >> 3) & 0x01)
	p.RFlag = toBool((data[3] >> 2) & 0x01)
	p.SFlag = toBool((data[3] >> 1) & 0x01)

	p.CAT = binary.BigEndian.Uint64(data[4:])
	p.PSN = binary.BigEndian.Uint32(data[12:])
	p.PSE = binary.BigEndian.Uint32(data[16:])

	if !p.XFlag {
		p.PCFIntegrity = -1
		p.PCFLen = -1
		p.PCFType = -1
		p.PCFValue = nil
		p.Payload = data[20:]

		p.BaseLayer = BaseLayer{Contents: data[:20], Payload : p.Payload}

		return nil
	} else {
		nindex := 20

		if data[nindex] == 0x00 {
			p.PCFType = int32(uint16(data[nindex+1]) << uint16(8))
			nindex += 2
		} else {
			p.PCFType = int32(data[nindex])
			nindex += 1
		}

		if p.PCFType == 0xFF {
			p.PCFLen = -1
			p.PCFType = -1
			p.PCFValue = nil
			p.BaseLayer = BaseLayer{Contents: data[:nindex]}
			return nil
		}

		pcfLenI := data[nindex]

		p.PCFLen = int8(uint8(pcfLenI) >> uint8(2))
		p.PCFIntegrity = int8(pcfLenI & 0x03)

		nindex += 1

		p.PCFValue = data[nindex : nindex+int(p.PCFLen)]
		p.Payload = data[nindex+int(p.PCFLen):]

		nindex += int(p.PCFLen)

		p.BaseLayer = BaseLayer{Contents: data[:nindex], Payload: p.Payload}

		return nil
	}
}

func (p *PLUS) LayerType() gopacket.LayerType { return LayerTypePLUS }

func decodePLUS(data []byte, p gopacket.PacketBuilder) error {
	pLayer := &PLUS{}
	err := pLayer.DecodeFromBytes(data, p)

	last := p.LastLayer()

	p.AddLayer(pLayer)
	if err != nil {
		return err
	}

	switch last.(type) {
	case *UDP:
		u := last.(*UDP)

		var lt gopacket.LayerType

		if lt = u.DstPort.LayerType(); lt != gopacket.LayerTypePayload {

		} else {
			lt = u.SrcPort.LayerType()
		}

		return p.NextDecoder(lt)
	default:
		return nil
	}
}
