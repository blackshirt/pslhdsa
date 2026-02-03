// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Some utilities used across the module
module pslhdsa

import crypto

// Algorithm 1 gen_len2(𝑛, 𝑙𝑔𝑤)
//
@[inline]
fn gen_len2(n int, lgw int) int {
	ww := u32(1) << u32(lgw)
	len1 := ((u32(n) << 3) + u32(lgw) - 1) / u32(lgw)
	max_checksum := len1 * (ww - 1)
	mut out := 1
	mut capacity := ww
	for capacity <= max_checksum {
		out += 1
		capacity *= ww
	}
	return out
}

// Algorithm 2 toInt(𝑋, 𝑛)
//
// Converts a byte string to an integer
// Input: 𝑛-byte string 𝑋.
@[direct_array_access; inline]
fn to_int(x []u8, n int) u64 {
	assert n <= 8
	if n == 0 {
		return 0
	}
	mut total := u64(0)
	for i := 0; i < n; i++ {
		total = total << 8
		total += u64(x[i])
	}
	return total
}

// Algorithm 3 toByte(𝑥, 𝑛)
//
// Converts an integer to a byte string.
// Input: Integer 𝑥, string length 𝑛.
// Output: Byte string of length 𝑛 containing binary representation of 𝑥 in big-endian byte-order.
@[inline]
fn to_byte(x u64, n int) []u8 {
	if n == 0 {
		return []u8{}
	}
	mut t := x
	mut out := []u8{len: n}
	for i := 0; i < n; i++ {
		out[n - 1 - i] = u8(t & 0xFF)
		t >>= 8
	}
	return out
}

// Compute ceil(n/k)
@[inline]
fn cdiv(n int, k int) int {
	return (n + k - 1) / k
}

// Algorithm 4 base_2b(𝑋, 𝑏, 𝑜𝑢𝑡_𝑙𝑒𝑛)
//
// Computes the base 2^𝑏 representation of 𝑋.
// Input: Byte string 𝑋 of length at least ⌈ 𝑜𝑢𝑡_𝑙𝑒𝑛⋅𝑏 / 8⌉, integer 𝑏, output length 𝑜𝑢𝑡_𝑙𝑒𝑛.
// Output: Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range [0, … , 2𝑏 − 1].
// The base_2b function is used to break the message to be signed and the checksum value
// into arrays of base-𝑤 integers.
@[direct_array_access; inline]
fn base_2b(x []u8, b int, outlen int) []u32 {
	mut input := u32(0)
	mut bits := 0
	mut total := u32(0)

	// output buffer with outlen capacity
	mut out := []u32{cap: outlen}
	// set up total mask with u64-value to overcome the wrapping behaviour for u32
	mask := u32(u64(1) << b - 1)

	for i := 0; i < outlen; i++ {
		for bits < b {
			total = (total << 8) + u32(x[input])
			input += 1
			bits += 8
		}
		bits -= b
		tmp := (total >> bits) & mask

		out << tmp
	}
	return out
}

// is_zero tells whether seed is all zeroes in constant time.
@[direct_array_access; inline]
fn is_zero(seed []u8) bool {
	mut acc := u8(0)
	for b in seed {
		acc |= b
	}
	return acc == 0
}

// name_to_hfunc get the Hash enum and their size from string name, usually for testing purposes
@[inline]
fn name_to_hfunc(name string) !(crypto.Hash, int) {
	match name {
		'SHAKE-128' {
			return crypto.Hash.md4, 32
		} // not availables on crypto.Hash enum, map to md4
		'SHAKE-256' {
			return crypto.Hash.md5, 64
		} // map to 64-size
		'SHA2-224' {
			return crypto.Hash.sha224, 28
		} // 224/8-bytes
		'SHA2-256' {
			return crypto.Hash.sha256, 32
		} // 256/8-bytes
		'SHA2-384' {
			return crypto.Hash.sha384, 48
		} // 384/8-bytes
		'SHA2-512' {
			return crypto.Hash.sha512, 64
		} // 512/8-bytes
		'SHA2-512/224' {
			return crypto.Hash.sha512_224, 28
		} // 224/8-bytes
		'SHA2-512/256' {
			return crypto.Hash.sha512_256, 32
		} // 256/8-bytes
		'SHA3-224' {
			return crypto.Hash.sha3_224, 28
		} // 224/8-bytes
		'SHA3-256' {
			return crypto.Hash.sha3_256, 32
		} // 256/8-bytes
		'SHA3-384' {
			return crypto.Hash.sha3_384, 48
		} // 384/8-bytes
		'SHA3-512' {
			return crypto.Hash.sha3_512, 64
		} // 512/8-bytes
		else {
			return error('hash algorithm ${name} not supported')
		}
	}
}
