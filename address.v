// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// 4.2 Addresses
module pslhdsa

// Address fundamentally 32 bytes long composed from:
// -- layer address  4 bytes 	0	0..4
// -- tree address  12 bytes 	1	4..8
// -- tree address  			2	8..12
// -- tree address   			3	12..16
// -- 𝑡𝑦𝑝𝑒           4 bytes 	4	16..20
// -- final          12 bytes	5	20..24, keypair
// -- final          			6 	24..28, chain, tree height
// -- final          			7 	28..32, hash, tree index
@[noinit]
struct Address {
mut:
	data [8]u32
}

// bytes returns bytes representation of Addres ad in big-endian form
@[direct_array_access; inline]
fn (ad Address) bytes() []u8 {
	mut x := []u8{len: 32}
	x[0] = u8((ad.data[0] >> 24) & 0xff)
	x[1] = u8((ad.data[0] >> 16) & 0xff)
	x[2] = u8((ad.data[0] >> 8) & 0xff)
	x[3] = u8((ad.data[0] >> 0) & 0xff)

	x[4] = u8((ad.data[1] >> 24) & 0xff)
	x[5] = u8((ad.data[1] >> 16) & 0xff)
	x[6] = u8((ad.data[1] >> 8) & 0xff)
	x[7] = u8((ad.data[1] >> 0) & 0xff)

	x[8] = u8((ad.data[2] >> 24) & 0xff)
	x[9] = u8((ad.data[2] >> 16) & 0xff)
	x[10] = u8((ad.data[2] >> 8) & 0xff)
	x[11] = u8((ad.data[2] >> 0) & 0xff)

	x[12] = u8((ad.data[3] >> 24) & 0xff)
	x[13] = u8((ad.data[3] >> 16) & 0xff)
	x[14] = u8((ad.data[3] >> 8) & 0xff)
	x[15] = u8((ad.data[3] >> 0) & 0xff)

	x[16] = u8((ad.data[4] >> 24) & 0xff)
	x[17] = u8((ad.data[4] >> 16) & 0xff)
	x[18] = u8((ad.data[4] >> 8) & 0xff)
	x[19] = u8((ad.data[4] >> 0) & 0xff)

	x[20] = u8((ad.data[5] >> 24) & 0xff)
	x[21] = u8((ad.data[5] >> 16) & 0xff)
	x[22] = u8((ad.data[5] >> 8) & 0xff)
	x[23] = u8((ad.data[5] >> 0) & 0xff)

	x[24] = u8((ad.data[6] >> 24) & 0xff)
	x[25] = u8((ad.data[6] >> 16) & 0xff)
	x[26] = u8((ad.data[6] >> 8) & 0xff)
	x[27] = u8((ad.data[6] >> 0) & 0xff)

	x[28] = u8((ad.data[7] >> 24) & 0xff)
	x[29] = u8((ad.data[7] >> 16) & 0xff)
	x[30] = u8((ad.data[7] >> 8) & 0xff)
	x[31] = u8((ad.data[7] >> 0) & 0xff)

	return x
}

// 18. Compressed address (ADRS ) 22 bytes
//
// layer address 1 byte
// tree address 8 bytes
// 𝑡𝑦𝑝𝑒 1 byte
// final 12 bytes
// compress compress the Address ad into 22-bytes output
@[direct_array_access; inline]
fn (ad Address) compress() []u8 {
	mut x := []u8{len: 22}
	// TODO: using binary.big_endian variant
	// 1 byte at 3..4
	x[0] = u8(ad.data[0] & 0xff)

	// 8 bytes at 8..16
	x[1] = u8((ad.data[2] >> 24) & 0xff)
	x[2] = u8((ad.data[2] >> 16) & 0xff)
	x[3] = u8((ad.data[2] >> 8) & 0xff)
	x[4] = u8((ad.data[2] >> 0) & 0xff)
	x[5] = u8((ad.data[3] >> 24) & 0xff)
	x[6] = u8((ad.data[3] >> 16) & 0xff)
	x[7] = u8((ad.data[3] >> 8) & 0xff)
	x[8] = u8((ad.data[3] >> 0) & 0xff)

	// 1 byte at 19..20
	x[9] = u8(ad.data[4] & 0xff)

	// 12 bytes at 20..32,
	x[10] = u8((ad.data[5] >> 24) & 0xff)
	x[11] = u8((ad.data[5] >> 16) & 0xff)
	x[12] = u8((ad.data[5] >> 8) & 0xff)
	x[13] = u8((ad.data[5] >> 0) & 0xff)
	x[14] = u8((ad.data[6] >> 24) & 0xff)
	x[15] = u8((ad.data[6] >> 16) & 0xff)
	x[16] = u8((ad.data[6] >> 8) & 0xff)
	x[17] = u8((ad.data[6] >> 0) & 0xff)
	x[18] = u8((ad.data[7] >> 24) & 0xff)
	x[19] = u8((ad.data[7] >> 16) & 0xff)
	x[20] = u8((ad.data[7] >> 8) & 0xff)
	x[21] = u8((ad.data[7] >> 0) & 0xff)
	return x
}

// clone clones the Address ad into new Address
@[direct_array_access; inline]
fn (ad Address) clone() Address {
	mut out := [8]u32{}
	for i, v in ad.data {
		out[i] = v
	}
	return Address{
		data: out
	}
}

// Member functions for addresses
//

// Layer parts
@[direct_array_access; inline]
fn (ad Address) get_layer_address() u32 {
	return ad.data[0]
}

// ADRS.setLayerAddress(𝑙) ADRS ← toByte(𝑙, 4) ∥ ADRS[4 ∶ 32]
@[direct_array_access; inline]
fn (mut ad Address) set_layer_address(v u32) {
	// reverts bits into big-endian if necessary
	ad.data[0] = rev8_be32(v)
}

// Tree parts
fn (ad Address) get_tree_address() u64 {
	return u64(ad.data[2]) << 32 | u64(ad.data[3])
}

// ADRS.setTreeAddress(𝑡) ADRS ← ADRS[0 ∶ 4] ∥ toByte(𝑡, 12) ∥ ADRS[16 ∶ 32]
@[direct_array_access; inline]
fn (mut ad Address) set_tree_address(v u64) {
	ad.data[1] = 0
	ad.data[2] = u32((v >> 32) & 0xFFFF_FFFF)
	ad.data[3] = u32(v & 0xFFFF_FFFF)
}

// KEYPAIR
// ADRS.setKeyPairAddress(𝑖) ADRS ← ADRS[0 ∶ 20] ∥ toByte(𝑖, 4) ∥ ADRS[24 ∶ 32]
@[direct_array_access; inline]
fn (mut ad Address) set_keypair_address(v u32) {
	ad.data[5] = rev8_be32(v)
}

// 𝑖 ← ADRS.getKeyPairAddress() 𝑖 ← toInt(ADRS[20 ∶ 24], 4)
@[direct_array_access; inline]
fn (ad Address) get_keypair_address() u32 {
	return ad.data[5]
}

// Set WOTS+ chain address.
// ADRS.setChainAddress(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
@[direct_array_access; inline]
fn (mut ad Address) set_chain_address(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	// bytes := to_bytes(x, 4)
	// at 24..28
	// ad.data[24..28] = bytes
	ad.data[6] = rev8_be32(v)
}

// ADRS.setTreeHeight(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
// sets FORS tree height
@[direct_array_access; inline]
fn (mut ad Address) set_tree_height(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 3 (FORS_TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF), 𝑡𝑦𝑝𝑒 = 2 (TREE)
	ad.data[6] = rev8_be32(v)
}

// ADRS.setTreeIndex(𝑖) ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
// Set FORS tree index.
@[direct_array_access; inline]
fn (mut ad Address) set_tree_index(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	// at 28..32
	// bytes := to_bytes(x, 4)
	// ad.data[28..32] = bytes
	ad.data[7] = rev8_be32(v)
}

// 𝑖 ← ADRS.getTreeIndex() 𝑖 ← toInt(ADRS[28 ∶ 32], 4)
// Get FORS tree index.
@[direct_array_access; inline]
fn (ad Address) get_tree_index() u32 {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	// return u32(to_int(ad.data[28..32], 4))
	return ad.data[7]
}

// ADRS.setHashAddress(𝑖), ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
@[direct_array_access; inline]
fn (mut ad Address) set_hash_address(v u32) {
	// 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	// bytes := to_bytes(x, 4)
	// ad.data[28..32] = bytes
	ad.data[7] = rev8_be32(v)
}

fn (ad Address) get_type() !AddressType {
	val := ad.data[4]
	return new_addrtype(val)!
}

// ADRS.setTypeAndClear(𝑌) ADRS ← ADRS[0 ∶ 16] ∥ toByte(𝑌 , 4) ∥ toByte(0, 12)
@[direct_array_access; inline]
fn (mut ad Address) set_type_and_clear(new_type AddressType) {
	ad.data[4] = u32(new_type)
	ad.data[5] = 0
	ad.data[6] = 0
	ad.data[7] = 0
}

@[direct_array_access; inline]
fn (mut ad Address) set_type_and_clear_not_kp(new_type AddressType) {
	ad.data[4] = u32(new_type)
	ad.data[6] = 0
	ad.data[7] = 0
}

// The Address type word will have a value of 0, 1, 2, 3, 4, 5, or 6.
// In order to improve readability, these values will be
// referred to in this standard by the constants WOTS_HASH, WOTS_PK, TREE,
// FORS_TREE, FORS_ROOTS, WOTS_PRF, and FORS_PRF, respectively
enum AddressType as u32 {
	wots_hash  = 0
	wots_pk    = 1
	tree       = 2
	fors_tree  = 3
	fors_roots = 4
	wots_prf   = 5
	fors_prf   = 6
}

// new_addrtype creates a new AddressType from u32 value v.
@[inline]
fn new_addrtype(v u32) !AddressType {
	match v {
		0 { return .wots_hash }
		1 { return .wots_pk }
		2 { return .tree }
		3 { return .fors_tree }
		4 { return .fors_roots }
		5 { return .wots_prf }
		6 { return .fors_prf }
		else { return error('Bad address type value') }
	}
}

@[noinit]
struct CompressedAddress {
mut:
	data [22]u8
}

fn (c CompressedAddress) bytes() []u8 {
	return c.data[..]
}
