module pslhdsa

import encoding.binary

// vfmt off
const addr_layer_start 	= 0
const addr_layer_end	= 4
const addr_tree_start	= 4
const addr_tree_end		= 16
const addr_type_start 	= 16
const addr_type_end		= 20
const addr_final_start	= 20
const addr_final_end	= 32
// inside final address, when type was a WOTS_HASH, 
// It can contains key pair address, chain address and hash address
// 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH)
// key pair address	4 bytes
// chain address	4 bytes
// hash address		4 bytes
const addr_keypair_start 	= 20
const addr_keypair_end		= 24
const addr_chain_start		= 24 
const addr_chain_end		= 28 
const addr_hash_start		= 28
const addr_hash_end			= 32

// vfmt on

// Address fundamentally 32 bytes long composed from:
// -- layer address  4 bytes 0-4
// -- tree address  12 bytes 4-16
// -- 𝑡𝑦𝑝𝑒           4 bytes 16-20
// -- final         12 bytes 20-32
struct Address {
mut:
	data []u8 = []u8{len: 32}
}

@[direct_array_access; inline]
fn (addr Address) bytes() []u8 {
	return addr.data
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
	mut out := []u8{}
	out << addr.data[3..4]
	out << addr.data[8..16]
	out << addr.data[19..32]

	assert out.len == 22
	return out
}

// Member functions for addresses
//

// Layer parts
@[direct_array_access; inline]
fn (addr Address) get_layer_address() u32 {
	return binary.big_endian_u32(addr.data[addr_layer_start..addr_layer_end])
}

// ADRS.setLayerAddress(𝑙) ADRS ← toByte(𝑙, 4) ∥ ADRS[4 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_layer_address(v u32) {
	// bytes := to_byte(x, 4)
	// addr.data[addr_layer_start..addr_layer_end] = bytes
	binary.big_endian_put_u32(mut addr.data[addr_layer_start..addr_layer_end], v)
}

// Tree parts
// ADRS.setTreeAddress(𝑡) ADRS ← ADRS[0 ∶ 4] ∥ toByte(𝑡, 12) ∥ ADRS[16 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_tree_address(v u64) {
	// TODO: tree address should fit in 12 bytes instead, [4..16]
	//  bytes a[4:8] of tree address are always zero
	binary.big_endian_put_u64(mut addr.data[addr_tree_start + 4..addr_tree_end], v)
}

// KEYPAIR
// ADRS.setKeyPairAddress(𝑖) ADRS ← ADRS[0 ∶ 20] ∥ toByte(𝑖, 4) ∥ ADRS[24 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_keypair_address(v u32) {
	// final 20-24
	// bytes := to_byte(x, 4)
	// addr.data[addr_final_start..addr_final_start + 4] = bytes
	binary.big_endian_put_u32(mut addr.data[addr_keypair_start..addr_keypair_end], v)
}

// 𝑖 ← ADRS.getKeyPairAddress() 𝑖 ← toInt(ADRS[20 ∶ 24], 4)
@[direct_array_access; inline]
fn (addr Address) get_keypair_address() u32 {
	// return u32(to_int(addr.data[addr_final_start..addr_final_start + 4], 4))
	return binary.big_endian_u32(addr.data[addr_keypair_start..addr_keypair_end])
}

// Set WOTS+ chain address.
// ADRS.setChainAddress(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
@[direct_array_access; inline]
fn (mut addr Address) set_chain_address(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	// bytes := to_byte(x, 4)
	// at 24..28
	// addr.data[24..28] = bytes
	binary.big_endian_put_u32(mut addr.data[addr_chain_start..addr_chain_end], v)
}

// ADRS.setTreeHeight(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
// sets FORS tree height
@[direct_array_access; inline]
fn (mut addr Address) set_tree_height(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 3 (FORS_TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF), 𝑡𝑦𝑝𝑒 = 2 (TREE)
	// tree height was on second index of final field, ie, final[1]
	// bytes := to_byte(x, 4)
	// at 24..28
	// addr.data[24..28] = bytes
	binary.big_endian_put_u32(mut addr.data[24..28], v)
}

// ADRS.setTreeIndex(𝑖) ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
// Set FORS tree index.
@[direct_array_access; inline]
fn (mut addr Address) set_tree_index(v u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	// at 28..32
	// bytes := to_byte(x, 4)
	// addr.data[28..32] = bytes
	binary.big_endian_put_u32(mut addr.data[28..32], v)
}

// 𝑖 ← ADRS.getTreeIndex() 𝑖 ← toInt(ADRS[28 ∶ 32], 4)
// Get FORS tree index.
@[direct_array_access; inline]
fn (addr Address) get_tree_index() u32 {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	// return u32(to_int(addr.data[28..32], 4))
	return binary.big_endian_u32(addr.data[28..32])
}

// ADRS.setHashAddress(𝑖), ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
@[direct_array_access; inline]
fn (mut addr Address) set_hash_address(v u32) {
	// 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	// bytes := to_byte(x, 4)
	// addr.data[28..32] = bytes
	binary.big_endian_put_u32(mut addr.data[28..32], v)
}

// ADRS.setTypeAndClear(𝑌) ADRS ← ADRS[0 ∶ 16] ∥ toByte(𝑌 , 4) ∥ toByte(0, 12)
@[direct_array_access; inline]
fn (mut addr Address) set_type_and_clear(new_type AddressType) {
	// set type
	// bytes_type := to_byte(u32(new_type), 4)
	// addr.data[addr_type_start..addr_type_end] = bytes_type
	binary.big_endian_put_u32(mut addr.data[addr_type_start..addr_type_end], u32(new_type))
	// clear final
	unsafe {
		addr.data[addr_final_start..addr_final_end].reset()
	}
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
