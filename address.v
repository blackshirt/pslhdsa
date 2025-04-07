module pslhdsa

import encoding.binary

// Address fundamentally 32 bytes long composed from:
// -- layer address  4 bytes
// -- tree address  12 bytes
// -- 𝑡𝑦𝑝𝑒           4 bytes
// -- final         12 bytes
struct Address {
mut:
	layer u32
	// 4 bytes
	tree [3]u32
	// 12 bytes
	tipe  AddressType
	final [3]u32
	// 12 bytes
}

fn (addr Address) full_to_bytes() []u8 {
	mut out := []u8{len: 32}

	// layer
	binary.big_endian_put_u32(mut out[0..4], addr.layer)

	// tree
	binary.big_endian_put_u32(mut out[4..8], addr.tree[0])
	binary.big_endian_put_u32(mut out[8..12], addr.tree[1])
	binary.big_endian_put_u32(mut out[12..16], addr.tree[1])

	// type
	binary.big_endian_put_u32(mut out[16..20], addr.tipe)

	// final address
	binary.big_endian_put_u32(mut out[20..24], addr.final[0])
	binary.big_endian_put_u32(mut out[24..28], addr.final[1])
	binary.big_endian_put_u32(mut out[28..32], addr.final[2])

	return out
}

// 18. Compressed address (ADRS ) 22 bytes
//
// layer address 1 byte
// tree address 8 bytes
// 𝑡𝑦𝑝𝑒 1 byte
// final 12 bytes
fn (addr Address) compress() []u8 {
	data := addr.full_to_bytes()

	mut out := []u8{}
	out << data[3..4]
	out << data[8..16]
	out << data[19..32]

	return out
}

fn (mut addr Address) reset() {
	addr.layer = 0
	addr.tree[0] = 0
	addr.tree[1] = 0
	addr.tree[2] = 0

	// reset tipe
	addr.final[0] = 0
	addr.final[1] = 0
	addr.final[2] = 0
}

// Member functions for addresses

// ADRS.setTypeAndClear(𝑌) ADRS ← ADRS[0 ∶ 16] ∥ toByte(𝑌 , 4) ∥ toByte(0, 12)
fn (mut addr Address) set_type_and_clear(new_type AddressType) {
	addr.tipe = new_type
	// Whenever the type in an address changes, the final 12 bytes of the address are
	// initialized to zero.
	addr.final[0] = 0
	addr.final[1] = 0
	addr.final[2] = 0
}

// ADRS.setLayerAddress(𝑙) ADRS ← toByte(𝑙, 4) ∥ ADRS[4 ∶ 32]
fn (mut addr Address) set_layer_address(x u32) {
	v := rev8_be32(x)
	addr.layer = v
}

// ADRS.setTreeAddress(𝑡) ADRS ← ADRS[0 ∶ 4] ∥ toByte(𝑡, 12) ∥ ADRS[16 ∶ 32]
fn (mut addr Address) set_tree_address(x u64) {
	// tree[0] of tree address are always zero
	addr.tree[1] = rev8_be32(x >> 32)
	addr.tree[2] = rev8_be32(x & 0xFFFF_FFFF)
}

// ADRS.setKeyPairAddress(𝑖) ADRS ← ADRS[0 ∶ 20] ∥ toByte(𝑖, 4) ∥ ADRS[24 ∶ 32]
fn (mut addr Address) set_keypair_address(x u32) {
	addr.final[0] = rev8_be32(x)
}

// 𝑖 ← ADRS.getKeyPairAddress() 𝑖 ← toInt(ADRS[20 ∶ 24], 4)
fn (addr Address) get_keypair_address() u32 {
	return rev8_be32(addr.final[0])
}

// ADRS.setTreeHeight(𝑖) ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
// sets FORS tree height
fn (mut addr Address) set_tree_height(x u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 3 (FORS_TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF), 𝑡𝑦𝑝𝑒 = 2 (TREE)
	// tree height was on second index of final field, ie, final[1]
	addr.final[1] = rev8_be32(x)
}

// Set WOTS+ chain address.
// ADRS.setChainAddress(𝑖)
fn (mut addr Address) set_chain_address(x u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	addr.final[1] = rev8_be32(x)
}

// ADRS.setTreeIndex(𝑖) ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
// Set FORS tree index.
fn (mut addr Address) set_tree_index(x u32) {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	addr.final[2] = rev8_be32(x)
}

// 𝑖 ← ADRS.getTreeIndex() 𝑖 ← toInt(ADRS[28 ∶ 32], 4)
// Get FORS tree index.
fn (addr Address) get_tree_index() u32 {
	// TODO: assert correct type, 𝑡𝑦𝑝𝑒 = 2 (TREE), 𝑡𝑦𝑝𝑒 = 6 (FORS_PRF)
	return rev8_be32(addr.final[2])
}

// ADRS.setHashAddress(𝑖)
fn (mut addr Address) set_hash_address(x u32) {
	// 𝑡𝑦𝑝𝑒 = 0 (WOTS_HASH), 𝑡𝑦𝑝𝑒 = 5 (WOTS_PRF)
	addr.final[2] = rev8_be32(x)
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

// serializes AddressType to bytes in big endian order
fn (adt AddressType) to_bytes() []u8 {
	return binary.big_endian_get_u32(u32(adt))
}

// Parameters Set
struct ParamSet {
	// Algorithm name
	alg_id string

	n u32
	//  Security level / hash size { 16,24,32 }.
	h u32
	//  Bits h used to select FORS key.
	d u32
	//  Number of hypertree layers d.
	hp u32
	//  Merkle tree height h' (XMSS).
	a u32
	//  String length t = 2**a (FORS).
	k u32
	//  Number of strings (FORS).
	lgw u32
	//  Number of bits in chain index (WOTS+)
	m u32
	//  Length in bytes of message digest.
}
