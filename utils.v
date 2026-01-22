// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
module pslhdsa

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

// Algorithm 4 base_2exp_b(𝑋, 𝑏, 𝑜𝑢𝑡_𝑙𝑒𝑛)
//
// Computes the base 2^𝑏 representation of 𝑋.
// Input: Byte string 𝑋 of length at least ⌈ 𝑜𝑢𝑡_𝑙𝑒𝑛⋅𝑏 / 8⌉, integer 𝑏, output length 𝑜𝑢𝑡_𝑙𝑒𝑛.
// Output: Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range [0, … , 2𝑏 − 1].
// The base_2exp_b function is used to break the message to be signed and the checksum value
// into arrays of base-𝑤 integers.
@[direct_array_access; inline]
fn base_2exp_b(x []u8, b int, out_len int) []u32 {
	assert b > 0
	assert out_len > 0

	mut idx := 0
	mut bits := 0
	mut total := u32(0)

	mask := (u32(1) << b) - 1
	mut out := []u32{cap: out_len}

	for i := 0; i < out_len; i++ {
		for bits < b {
			total = (total << 8) + x[idx]
			idx += 1
			bits += 8
		}
		bits -= b
		tmp := (total >> bits) & mask
		out << tmp
	}
	return out
}

//  revert if not big endian
@[inline]
fn rev8_be32(x u32) u32 {
	$if !big_endian {
		return ((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) | ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24)
	}

	// otherwise not changed
	return x
}

@[inline]
fn rev8_be64(x u64) u64 {
	$if !big_endian {
		return (x << 56) | ((x & 0x0000_0000_0000_FF00) << 40) | ((x & 0x0000_0000_00FF_0000) << 24) | ((x & 0x0000_0000_FF00_0000) << 8) | ((x & 0x0000_00FF_0000_0000) >> 8) | ((x & 0x0000_FF00_0000_0000) >> 24) | ((x & 0x00FF_0000_0000_0000) >> 40) | (x >> 56)
	}
	return x
}
