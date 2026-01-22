// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Parameter Set
module pslhdsa

import hash
import math
import encoding.binary

// B.2.1 MGF1
// https://www.ietf.org/rfc/rfc3447.txt
// MGF1 is a Mask Generation Function based on a hash function.
//   MGF1 (mgfSeed, maskLen)
//   Options:
//   Hash     hash function (hLen denotes the length in octets of the hash
//            function output)
//   Input:
//   mgfSeed  seed from which mask is generated, an octet string
//   maskLen  intended length in octets of the mask, at most 2^32 hLen
//   Output:
//   mask     mask, an octet string of length maskLen

@[direct_array_access; inline]
fn mgf1(seed []u8, masklen int, mut h crypto.Hash) ![]u8 {
	// If maskLen > 2^32 hLen, output "mask too long" and stop.
	// Its should happen, masklen was u32-based value
	if u64(masklen) > u64(max_u32) * u64(h.size()) {
		return error('mask too long')
	}
	// Let T be the empty octet string.
	mut maskout := []u8{len: masklen}

	// Calculate how many hash outputs we need
	hlen := u32(h.size())
	iterations := u32(math.ceil(f64(masklen) / f64(hlen)))

	mut counter := []u8{len: 4}

	// For counter from 0 to \ceil (maskLen / hLen) - 1, do the
	// following:
	for i := 0; i < iterations; i++ {
		// reset the hash
		h.reset()
		// Convert counter to an octet string C of length 4 octets
		binary.big_endian_put_u32(mut counter, u32(i))
		// Concatenate the hash of the seed mgfSeed and C to the octet
		// string T:
		//     T = T || Hash(mgfSeed || C)
		//
		// Write seed and counter to hash
		h.write(seed)!
		h.write(counter)!
		// Calculate hash
		digest := h.sum([]u8{})

		// Copy to output buffer, ensuring we don't go beyond its end
		offset := i * hlen
		remaining := masklen - offset
		if remaining >= hlen {
			copy(mut maskout[offset..offset + hlen], digest)
		} else {
			copy(maskout[offset..], digest[..remaining])
			break
		}
	}
	return maskout
}
