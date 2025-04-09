module pslhdsa

import crypto.hmac
import crypto.sha3
import crypto.sha256
import crypto.sha512
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

fn (addr Address) clone() Address {
	return Address{
		layer: addr.layer
		tree:  addr.tree
		tipe:  addr.tipe
		final: addr.final
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

fn (addr Address) full_to_bytes() []u8 {
	mut out := []u8{len: 32}

	// layer
	binary.big_endian_put_u32(mut out[0..4], addr.layer)

	// tree
	binary.big_endian_put_u32(mut out[4..8], addr.tree[0])
	binary.big_endian_put_u32(mut out[8..12], addr.tree[1])
	binary.big_endian_put_u32(mut out[12..16], addr.tree[1])

	// type
	binary.big_endian_put_u32(mut out[16..20], u32(addr.tipe))

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
	addr.tree[1] = rev8_be32(u32(x >> 32))
	addr.tree[2] = rev8_be32(u32(x & 0xFFFF_FFFF))
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

// serializes AddressType to bytes in big endian order
fn (adt AddressType) to_bytes() []u8 {
	return binary.big_endian_get_u32(u32(adt))
}

const sha256_hash_size = sha256.size

// A mask generation function (MGF) is a cryptographic primitive similar
// to a cryptographic hash function except that while a hash function's
// output has a fixed size, a MGF supports output of a variable length.
@[inline]
fn mgf1_sha256(seed []u8, mlen int) []u8 {
	mut out := []u8{}
	for c := 0; c < cdiv(mlen, sha256_hash_size); c++ {
		mut data := seed.clone()
		data << to_byte(c, 4)
		// seed + to_byte(c, 4)
		out << sha256.sum256(data)
	}
	return out[..mlen]
}

const sha512_hash_size = sha512.size

@[inline]
fn mgf1_sha512(seed []u8, mlen int) []u8 {
	mut out := []u8{}
	for c := 0; c < cdiv(mlen, sha512_hash_size); c++ {
		mut data := seed.clone()
		data << to_byte(c, 4)
		// seed + to_byte(c, 4)
		out << sha512.sum512(data)
	}
	return out[..mlen]
}

@[inline]
fn hmac_sha256(seed []u8, data []u8) []u8 {
	out := hmac.new(seed, data, sha256.sum256, sha256.size)
	return out
}

@[inline]
fn hmac_sha512(seed []u8, data []u8) []u8 {
	return hmac.new(seed, data, sha512.sum512, sha512.size)
}

struct Context {
	prm ParamSet
}

fn new_context(k Kind) Context {
	prm := ParamSet.from_kind(k)
	return Context{
		prm: prm
	}
}

// is_shake tells underlying hash was a shake-family algorithm
@[inline]
fn (c Context) is_shake() bool {
	return c.prm.id.is_shake()
}

// 4.1 Hash Functions and Pseudorandom Functions
//
// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛) is a pseudorandom function
// (PRF) that generates the randomizer (𝑅) for the randomized hashing of the message to be
// signed.
fn (c Context) prf_msg(sk_prf []u8, opt_rand []u8, msg []u8) ![]u8 {
	if c.is_shake() {
		mut data := []u8{}
		data << sk_prf
		data << opt_rand
		data << msg

		// if c.prm.id in [.shake_128f, .shake_128s] {
		//	return sha3.shake128(data, c.prm.n)
		// }
		return sha3.shake256(data, c.prm.n)
	}
	// sha2 family
	mut data := []u8{}
	data << msg
	data << opt_rand
	mut out := hmac_sha256(sk_prf, data)

	if c.prm.sc != 1 {
		out = hmac_sha512(sk_prf, data)
	}
	return out[..c.prm.n]
}

// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑚) is used to generate the
// digest of the message to be signed.
fn (c Context) h_msg(r []u8, pk_seed []u8, pk_root []u8, msg []u8) ![]u8 {
	if c.is_shake() {
		mut data := []u8{}
		data << r
		data << pk_seed
		data << pk_root
		data << msg
		if c.prm.id in [.shake_128f, .shake_128s] {
			return sha3.shake128(data, c.prm.m)
		}
		return sha3.shake256(data, c.prm.m)
	}
	// mgf1_sha256(R + pk_seed + sha256(R + pk_seed + pk_root + M)
	mut first_seed := []u8{}
	first_seed << r
	first_seed << pk_seed

	mut second_seed := first_seed.clone()
	second_seed << pk_root
	second_seed << msg

	mut hashed_2nd_seed := sha256.sum256(second_seed)

	if c.prm.sc != 1 {
		hashed_2nd_seed = sha512.sum512(second_seed)
	}

	mut seed := []u8{}
	seed << first_seed
	seed << hashed_2nd_seed

	if c.prm.sc != 1 {
		return mgf1_sha512(seed, c.prm.m)
	}
	return mgf1_sha256(seed, c.prm.m)
}

// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛) is a PRF that is used to
// generate the secret values in WOTS+ and FORS private keys.
fn (c Context) prf(pk_seed []u8, sk_seed []u8, addr Address) ![]u8 {
	if c.is_shake() {
		mut data := []u8{}
		data << pk_seed
		data << addr.full_to_bytes()
		data << sk_seed
		if c.prm.id in [.shake_128f, .shake_128s] {
			return sha3.shake128(data, c.prm.n)
		}
		return sha3.shake256(data, c.prm.n)
	}
	// sha2 family,
	// SLH-DSA Using SHA2 for Security Category 1
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << to_byte(0, 64 - c.prm.n)
	data << addrs_c
	data << sk_seed
	mut out := sha256.sum256(data)
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	// Really the same with category 1
	// if c.prm.sc != 1 {
	//	out = sha512.sum512(data)
	// }
	return out[..c.prm.n]
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
fn (c Context) tlen(pk_seed []u8, addr Address, ml []u8) ![]u8 {
	if c.is_shake() {
		// Tℓ(PK.seed, ADRS, 𝑀ℓ) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀ℓ, 8𝑛)
		mut data := []u8{}
		data << pk_seed
		data << addr.full_to_bytes()
		data << ml

		return sha3.shake256(data, c.prm.n)
	}
	// sha2 family,
	//
	// SLH-DSA Using SHA2 for Security Category 1
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed
	if c.prm.sc == 1 {
		data << to_byte(0, 64 - c.prm.n)
	} else {
		data << to_byte(0, 128 - c.prm.n)
	}
	data << addrs_c
	data << ml
	mut out := sha256.sum256(data)
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	if c.prm.sc != 1 {
		out = sha512.sum512(data)
	}
	return out[..c.prm.n]
}

// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛) is a special case of Tℓ that takes a
// 2𝑛-byte message as input.
fn (c Context) h(pk_seed []u8, addr Address, m2 []u8) ![]u8 {
	if c.is_shake() {
		// H(PK.seed, ADRS, 𝑀2) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
		mut data := []u8{}
		data << pk_seed
		data << addr.full_to_bytes()
		data << m2

		return sha3.shake256(data, c.prm.n)
	}
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed

	if c.prm.sc == 1 {
		data << to_byte(0, 64 - c.prm.n)
	} else {
		data << to_byte(0, 128 - c.prm.n)
	}
	data << addrs_c
	data << m2

	mut out := sha256.sum256(data)
	if c.prm.sc != 1 {
		out = sha512.sum512(data)
	}
	return out[..c.prm.n]
}

// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛) is a hash function that takes an 𝑛-byte
// message as input and produces an 𝑛-byte output.
fn (c Context) f(pk_seed []u8, addr Address, m1 []u8) ![]u8 {
	if c.is_shake() {
		mut data := []u8{}
		data << pk_seed
		data << addr.full_to_bytes()
		data << m1

		return sha3.shake256(data, c.prm.n)
	}
	// 11.2.1 SLH-DSA Using SHA2 for Security Category 1
	// F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	// SLH-DSA Using SHA2 for Security Categories 3 and 5
	// F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	addrs_c := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << to_byte(0, 64 - c.prm.n)
	data << addrs_c
	data << m1

	out := sha256.sum256(data)
	return out[..c.prm.n]
}
