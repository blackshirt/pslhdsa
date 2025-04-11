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
struct Address {
mut:
	data []u32 = []u32{len: 8}
}

@[direct_array_access; inline]
fn (addr Address) bytes() []u8 {
	mut x := []u8{len: 32}
	// addr.0 was layer address, written into x0..x3
	binary.big_endian_put_u32(mut x[0..4], addr.data[0])

	// addr.1..addr.3 was tree address, written into x4..x15
	binary.big_endian_put_u32(mut x[4..8], addr.data[1])
	binary.big_endian_put_u32(mut x[8..12], addr.data[2])
	binary.big_endian_put_u32(mut x[12..16], addr.data[3])

	// addr.4 was address type
	binary.big_endian_put_u32(mut x[16..20], addr.data[4])

	// last 3 u32 was final address
	binary.big_endian_put_u32(mut x[20..24], addr.data[5])
	binary.big_endian_put_u32(mut x[24..28], addr.data[6])
	binary.big_endian_put_u32(mut x[28..32], addr.data[7])

	return x
}

@[direct_array_access; inline]
fn (addr Address) clone() Address {
	return Address{
		data: addr.data.clone()
	}
}

@[direct_array_access; inline]
fn (mut addr Address) reset() {
	unsafe {
		addr.data.reset()
	}
}

// 18. Compressed address (ADRS ) 22 bytes
//
// layer address 1 byte
// tree address 8 bytes
// 𝑡𝑦𝑝𝑒 1 byte
// final 12 bytes
@[direct_array_access; inline]
fn (addr Address) compress() []u8 {
	mut x := []u8{len: 22}
	// layer, byte at 3-4
	x[0] = u8(addr.data[0] & 0xff)
	// tree
	binary.big_endian_put_u32(mut x[1..5], addr.data[2])
	binary.big_endian_put_u32(mut x[5..9], addr.data[3])
	// type
	x[9] = u8(addr.data[4] & 0xff)
	// final
	binary.big_endian_put_u32(mut x[10..14], addr.data[5])
	binary.big_endian_put_u32(mut x[14..18], addr.data[6])
	binary.big_endian_put_u32(mut x[18..22], addr.data[7])
	return x
}

// Member functions for addresses
//

// Layer parts
@[direct_array_access; inline]
fn (addr Address) get_layer_address() u32 {
	return addr.data[0]
}

// ADRS.setLayerAddress(𝑙) ADRS ← toByte(𝑙, 4) ∥ ADRS[4 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_layer_address(v u32) {
	addr.data[0] = v
}

// Tree parts
fn (addr Address) get_tree_address() u64 {
	return rev8_be64(u64(addr.data[2]) << 32) | rev8_be64(u64(addr.data[3]))
}

// ADRS.setTreeAddress(𝑡) ADRS ← ADRS[0 ∶ 4] ∥ toByte(𝑡, 12) ∥ ADRS[16 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_tree_address(v u64) {
	addr.data[1] = 0
	addr.data[2] = u32(v >> 32)
	addr.data[3] = u32(v & 0xFFFF_FFFF)
}

// KEYPAIR
// ADRS.setKeyPairAddress(𝑖) ADRS ← ADRS[0 ∶ 20] ∥ toByte(𝑖, 4) ∥ ADRS[24 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_keypair_address(v u32) {
	addr.data[5] = v
}

// 𝑖 ← ADRS.getKeyPairAddress() 𝑖 ← toInt(ADRS[20 ∶ 24], 4)
@[direct_array_access; inline]
fn (addr Address) get_keypair_address() u32 {
	return addr.data[5]
}

// Set WOTS+ chain address.
// ADRS.setChainAddress(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_chain_address(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	// bytes := to_byte(x, 4)
	// at 24..28
	// addr.data[24..28] = bytes
	addr.data[6] = v
}

// ADRS.setTreeHeight(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
// sets FORS tree height
@[direct_array_access; inline]
fn (mut addr Address) set_tree_height(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 3 (FORS_TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF), 𝑡𝑦𝑝𝑒 = 2 (TREE)
	addr.data[6] = v
}

// ADRS.setTreeIndex(𝑖) ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
// Set FORS tree index.
@[direct_array_access; inline]
fn (mut addr Address) set_tree_index(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	// at 28..32
	// bytes := to_byte(x, 4)
	// addr.data[28..32] = bytes
	addr.data[7] = v
}

// 𝑖 ← ADRS.getTreeIndex() 𝑖 ← toInt(ADRS[28 ∶ 32], 4)
// Get FORS tree index.
@[direct_array_access; inline]
fn (addr Address) get_tree_index() u32 {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	// return u32(to_int(addr.data[28..32], 4))
	return addr.data[7]
}

// ADRS.setHashAddress(𝑖), ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
@[direct_array_access; inline]
fn (mut addr Address) set_hash_address(v u32) {
	// 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	// bytes := to_byte(x, 4)
	// addr.data[28..32] = bytes
	addr.data[7] = v
}

fn (addr Address) get_type() !AddressType {
	val := addr.data[4]
	return address_type_from_u32(val)!
}

// ADRS.setTypeAndClear(𝑌) ADRS ← ADRS[0 ∶ 16] ∥ toByte(𝑌 , 4) ∥ toByte(0, 12)
@[direct_array_access; inline]
fn (mut addr Address) set_type_and_clear(new_type AddressType) {
	addr.data[4] = u32(new_type)
	addr.data[5] = 0
	addr.data[6] = 0
	addr.data[7] = 0
}

@[direct_array_access; inline]
fn (mut addr Address) set_type_and_clear_not_kp(new_type AddressType) {
	addr.data[4] = u32(new_type)
	addr.data[6] = 0
	addr.data[7] = 0
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

fn address_type_from_u32(v u32) !AddressType {
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
