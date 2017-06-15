// Copyright 2017 Roman Müntener. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"
	"bytes"
)

func TestEmpty(t *testing.T) {

}

func compare(a *PLUS, b *PLUS) bool {
	pass := a.XFlag == b.XFlag &&
		a.SFlag == b.SFlag &&
		a.LFlag == b.LFlag &&
		a.RFlag == b.RFlag &&
		a.CAT == b.CAT &&
		a.PSN == b.PSN &&
		a.PSE == b.PSE &&
		a.PCFType == b.PCFType &&
		a.PCFLen == b.PCFLen &&
		a.PCFIntegrity == b.PCFIntegrity &&
		bytes.Equal(a.PCFValue, b.PCFValue) &&
		bytes.Equal(a.BaseLayer.Payload, b.BaseLayer.Payload)

	return pass
}

func TestDecode(t *testing.T) {
	packet := []byte{
		0xD8, 0x00, 0x7F, 0xFF, //magic + flags (x bit set)
		0x12, 0x34, 0x56, 0x78, // cat
		0x12, 0x34, 0x56, 0x78, // cat..
		0x13, 0x11, 0x11, 0x11, // psn
		0x23, 0x22, 0x22, 0x22, // pse
		0x01, 0x1B, // PCF Type := 0x01,
		// PCF Len 6, PCF I = 11b,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, // 6 bytes PCF value
		0x99, 0x98, 0x97, 0x96} // 4 bytes payload

	var plus *PLUS = &PLUS{}
	plus.DecodeFromBytes(packet, nil)

	e:= &PLUS {
		XFlag : true, SFlag : true, LFlag : true, RFlag : true,
		CAT : uint64(0x1234567812345678),
		PSN : uint32(0x13111111),
		PSE : uint32(0x23222222),
		PCFType : (0x01),
		PCFLen : (0x06),
		PCFIntegrity : (0x03),
		PCFValue : []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		BaseLayer : BaseLayer { Payload : []byte{0x99, 0x98, 0x97, 0x96} },
	}

	if !compare(e, plus) {
		t.Errorf("DecodeFromBytes is wrong!")
	}

	packet[3] = (0xF << 4) | (0x08)

	plus.DecodeFromBytes(packet, nil)

	e.XFlag = false
	e.LFlag = true
	e.SFlag = false
	e.RFlag = false

	e.PCFType = -1
	e.PCFLen = -1
	e.PCFIntegrity = -1
	e.PCFValue = nil
	e.BaseLayer.Payload = []byte{0x01, 0x1B,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06,
		0x99, 0x98, 0x97, 0x96}

	if !compare(e, plus) {
		t.Errorf("DecodeFromBytes is wrong!")
	}
}
