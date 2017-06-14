// Copyright 2017 MAMI Project. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "github.com/google/gopacket"
import "errors"

var layerTypeDetectors = [128]LayerTypeDetector{}
var heuristicsEnabled = false
var errHeuristicsNotEnabled = errors.New("Heuristics not enabled!")

func EnableHeuristics() {
	heuristicsEnabled = true
}

type LayerTypeDetector interface {
	// Returns true if the LayerTypeDetector is certain that this is payload
	// of a given LayerType
	Test(payload []byte, proto string, srcPort uint16, dstPort uint16) bool
	// The LayerType this detector tries to detect.
	LayerType() gopacket.LayerType
}

// Guesses the LayerType of the payload based on the payload, the proto (udp/tcp)
// and source/destination ports. If it returns an error the LayerType could not
// be guessed.
func GuessLayerType(payload []byte, proto string, srcPort uint16, dstPort uint16) (gopacket.LayerType, error) {
	if !heuristicsEnabled {
		return gopacket.LayerType(-1), errHeuristicsNotEnabled
	}

	for _, v := range layerTypeDetectors {
		if v == nil {
			continue
		}

		if v.Test(payload, proto, srcPort, dstPort) {
			return v.LayerType(), nil
		}
	}

	return gopacket.LayerType(-1), errors.New("No layer detected!")
}

// Registers a LayerTypeDetector.
func RegisterLayerTypeDetector(lvl int, detector LayerTypeDetector) error {
	if layerTypeDetectors[lvl] != nil {
		return errors.New("LayerType already registered!")
	}

	layerTypeDetectors[lvl] = detector

	return nil
}
