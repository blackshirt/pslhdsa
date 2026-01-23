// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Mask Generation Function based on a hash function (MGF1) x
// used in accross of SLH-DSA
module pslhdsa

import hash
import math
import encoding.binary

// B.2.1 MGF1
// https://www.rfc-editor.org/rfc/rfc8017.html#appendix-B.2
//
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
//
// mgf1 is a mask generation function (MGF) acts as a cryptographic primitive similar
// to a cryptographic hash function except that while a hash function's
// output has a fixed size, a MGF supports output of a variable length.
// h is SHA-256 or SHA-512, respectively.
@[direct_array_access; inline]
fn mgf1(seed []u8, masklen int, mut h hash.Hash) ![]u8 {
	// If maskLen > 2^32 hLen, output "mask too long" and stop.
	// Its should never happen, masklen was int-based value
	if u64(masklen) > u64(max_u32) * u64(h.size()) {
		return error('mask too long')
	}
	// Let T be the empty octet string.
	mut maskout := []u8{len: masklen}

	// Calculate how many hash outputs we need
	hlen := h.size()
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

		// Copy to output buffer
		offset := i * hlen
		remaining := masklen - offset
		if remaining >= hlen {
			copy(mut maskout[offset..offset + hlen], digest)
		} else {
			copy(mut maskout[offset..], digest[..remaining])
			break
		}
	}
	// Output the leading maskLen octets of T as the octet string mask.
	return maskout
}
