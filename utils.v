module pslhdsa

import crypto.sha256
import crypto.sha512

// Algorithm 2 toInt(𝑋, 𝑛)
//
// Converts a byte string to an integer
// Input: 𝑛-byte string 𝑋.
fn to_int(x []u8, n int) u64 {
	if n == 0 {
		return 0
	}
	mut out := u64(0)
	for i := 0; i < n; i++ {
		out <<= 8
		out += u64(x[i])
	}
	return out
}

// Algorithm 3 toByte(𝑥, 𝑛)
//
// Converts an integer to a byte string.
// Input: Integer 𝑥, string length 𝑛.
// Output: Byte string of length 𝑛 containing binary representation of 𝑥 in big-endian byte-order.
fn to_byte(x u64, n int) []u8 {
	if n == 0 {
		return []u8{}
	}
	mut t := x
	mut s := []u8{len: n}
	for i := 0; i < n; i++ {
		s[n - 1 - i] = u8(t & 0xFF)
		t >>= 8
	}
	return s
}

// Algorithm 4 base_2exp_b(𝑋, 𝑏, 𝑜𝑢𝑡_𝑙𝑒𝑛)
//
// Computes the base 2^𝑏 representation of 𝑋.
// Input: Byte string 𝑋 of length at least ⌈ 𝑜𝑢𝑡_𝑙𝑒𝑛⋅𝑏 / 8⌉, integer 𝑏, output length 𝑜𝑢𝑡_𝑙𝑒𝑛.
// Output: Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range [0, … , 2𝑏 − 1].
// The base_2exp_b function is used to break the message to be signed and the checksum value
// into arrays of base-𝑤 integers.
fn base_2exp_b(x []u8, b u32, out_len int) []u32 {
	mut bits := u32(0)
	mut total := u32(0)
	mut pos := 0
	mut baseb := []u32{len: out_len}

	for out := 0; out < out_len; out++ {
		for bits < b {
			total = (total << 8) + x[pos]
			pos += 1
			bits += 8
		}
		bits -= b
		baseb[out] = (total >> bits) & max_u32
	}
	return baseb
}

// Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
//
// Chaining function used in WOTS+.
// Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS.
// Output: Value of F iterated 𝑠 times on 𝑋.
// (where 𝑖 + 𝑠 < w
fn chain(x []u8, idx int, step int, pk PublicKey, address Adrs) []u8 {
	tmp := x.clone()
	for j := idx; j < idx + step; j++ {
		address.setHashAddress(j)
		tmp = hash_fn(pk.seed, address, tmp)
	}
	return tmp
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
fn rev8_be64(u64 x) {
	$if !big_endian {
		return (x << 56) | ((x & 0x0000_0000_0000_FF00) << 40) | ((x & 0x0000_0000_00FF_0000) << 24) | ((x & 0x0000_0000_FF00_0000) << 8) | ((x & 0x0000_00FF_0000_0000) >> 8) | ((x & 0x0000_FF00_0000_0000) >> 24) | ((x & 0x00FF_0000_0000_0000) >> 40) | (x >> 56)
	}
	return x
}

const sha256_hash_size = sha256.size

// A mask generation function (MGF) is a cryptographic primitive similar
// to a cryptographic hash function except that while a hash function's
// output has a fixed size, a MGF supports output of a variable length.
fn mgf1_sha256(seed []u8, length int) ![]u8 {
	if length > (sha256_hash_size << 32) {
		return error('Length Too Big')
	}
	mut result := []u8{}
	mut counter := u32(0)

	for result.len < length {
		mut b := []u8{len: 4}
		big_endian_put_u32(mut b, counter)

		mut data := seed.clone()
		data << b

		result << sha256.sum256(data)
		counter += 1
	}
	return result[..length]
}

const sha512_hash_length = sha512.size

fn mgf1_sha512(seed []u8, length int) ![]u8 {
	if length > (sha512_hash_length << 32) {
		return error('Length Too Big')
	}
	mut result := []u8{}
	mut counter := u32(0)

	for result.len < length {
		mut b := []u8{len: 4}
		big_endian_put_u32(mut b, counter)
		mut data := seed.clone()
		data << b
		result << sha512.sum512(data)
		counter += 1
	}
	return result[..length]
}
