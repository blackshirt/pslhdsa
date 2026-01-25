// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Addresses handling module
module pslhdsa

import encoding.binary

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

// new_address creates an empty address
@[inline]
fn new_address() Address {
	return Address{}
}

// bytes returns the bytes representation of Addres ad in big-endian form
@[direct_array_access; inline]
fn (ad Address) bytes() []u8 {
	mut x := []u8{len: 32}
	binary.big_endian_put_u32(mut x[0..4], ad.data[0])
	binary.big_endian_put_u32(mut x[4..8], ad.data[1])
	binary.big_endian_put_u32(mut x[8..12], ad.data[2])
	binary.big_endian_put_u32(mut x[12..16], ad.data[3])
	binary.big_endian_put_u32(mut x[16..20], ad.data[4])
	binary.big_endian_put_u32(mut x[20..24], ad.data[5])
	binary.big_endian_put_u32(mut x[24..28], ad.data[6])
	binary.big_endian_put_u32(mut x[28..32], ad.data[7])
	return x
}

// 18. Compressed address (ADRS ) 22 bytes
//
// layer address   1 byte
// tree address    8 bytes
// 𝑡𝑦𝑝𝑒             1 byte
// final          12 bytes
//
// compress compressing the Address ad into 22-bytes compressed address
// ie, ADRS𝑐 = ADRS[3] ∥ ADRS[8 ∶ 16] ∥ ADRS[19] ∥ ADRS[20 ∶ 32]).
@[direct_array_access; inline]
fn (ad Address) compress() []u8 {
	mut x := []u8{len: 22}
	// 1 byte at 3..4
	x[0] = u8(ad.data[0] & 0xff)

	// 8 bytes at 8..16
	binary.big_endian_put_u32(mut x[1..5], ad.data[2])
	binary.big_endian_put_u32(mut x[5..9], ad.data[3])

	// 1 byte at 19..20
	x[9] = u8(ad.data[4] & 0xff)

	// 12 bytes at 20..32,
	binary.big_endian_put_u32(mut x[10..14], ad.data[5])
	binary.big_endian_put_u32(mut x[14..18], ad.data[6])
	binary.big_endian_put_u32(mut x[18..22], ad.data[7])

	return x
}

// clone clones the Address ad into new Address
@[direct_array_access; inline]
fn (ad Address) clone() Address {
	mut out := [8]u32{}
	// directly, copy the address data into out
	unsafe { vmemcpy(out, ad.data, sizeof(out)) }

	return Address{
		data: out
	}
}

// Member functions for addresses
//

// Layer parts
@[inline]
fn (ad Address) get_layer_address() u32 {
	return ad.data[0]
}

// ADRS.setLayerAddress(𝑙) ADRS ← toByte(𝑙, 4) ∥ ADRS[4 ∶ 32]
@[inline]
fn (mut ad Address) set_layer_address(v u32) {
	ad.data[0] = v
}

// Tree parts
@[inline]
fn (ad Address) get_tree_address() u64 {
	// TODO: tree address was 12-bytes in size, its currently only handle low 64-bits
	return u64(ad.data[2]) << 32 | u64(ad.data[3])
}

// ADRS.setTreeAddress(𝑡) ADRS ← ADRS[0 ∶ 4] ∥ toByte(𝑡, 12) ∥ ADRS[16 ∶ 32]
@[inline]
fn (mut ad Address) set_tree_address(v u64) {
	// TODO: tree address is 12-bytes in size, its currently only handle 64-bits
	// bytes a[4:8] of tree address are always zero
	// ad.data[1] = 0
	ad.data[2] = u32(v >> 32)
	ad.data[3] = u32(v & 0xFFFF_FFFF)
}

// KEYPAIR
// ADRS.setKeyPairAddress(𝑖) ADRS ← ADRS[0 ∶ 20] ∥ toByte(𝑖, 4) ∥ ADRS[24 ∶ 32]
@[inline]
fn (mut ad Address) set_keypair_address(v u32) {
	ad.data[5] = v
}

// 𝑖 ← ADRS.getKeyPairAddress() 𝑖 ← toInt(ADRS[20 ∶ 24], 4)
@[inline]
fn (ad Address) get_keypair_address() u32 {
	return ad.data[5]
}

// Set WOTS+ chain address.
// ADRS.setChainAddress(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
@[inline]
fn (mut ad Address) set_chain_address(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	// bytes := to_bytes(x, 4)
	// at 24..28
	// ad.data[24..28] = bytes
	ad.data[6] = v
}

// ADRS.setTreeHeight(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
// sets FORS tree height
@[inline]
fn (mut ad Address) set_tree_height(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 3 (FORS_TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF), 𝑡𝑦𝑝𝑒 = 2 (TREE)
	ad.data[6] = v
}

// ADRS.setTreeIndex(𝑖) ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
// Set FORS tree index.
@[inline]
fn (mut ad Address) set_tree_index(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	// at 28..32
	// bytes := to_bytes(x, 4)
	// ad.data[28..32] = bytes
	ad.data[7] = v
}

// 𝑖 ← ADRS.getTreeIndex() 𝑖 ← toInt(ADRS[28 ∶ 32], 4)
// Get FORS tree index.
@[inline]
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
	ad.data[7] = v
}

fn (ad Address) get_type() !AddressType {
	val := ad.data[4]
	return new_addrtype(val)!
}

fn (mut ad Address) set_type(t AddressType) {
	ad.data[4] = u32(t)
}

// ADRS.setTypeAndClear(𝑌) ADRS ← ADRS[0 ∶ 16] ∥ toByte(𝑌 , 4) ∥ toByte(0, 12)
@[inline]
fn (mut ad Address) set_type_and_clear(t AddressType) {
	ad.data[4] = u32(t)
	ad.data[5] = 0
	ad.data[6] = 0
	ad.data[7] = 0
}

@[inline]
fn (mut ad Address) set_type_and_clear_not_kp(t AddressType) {
	ad.data[4] = u32(t)
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
