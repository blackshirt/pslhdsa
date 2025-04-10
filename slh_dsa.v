module pslhdsa

import crypto.rand
// import crypto.sha3
// import crypto.sha256
// import crypto.sha512

@[params]
struct SignerOpts {
	randomize     bool
	deterministic bool
}

// 9.2 SLH-DSA Signature Generation
//
// Algorithm 19 slh_sign_internal(𝑀, SK, 𝑎𝑑𝑑𝑟𝑛𝑑)
// Generates an SLH-DSA signature.
// Input: Message 𝑀, private key SK = (SK.seed, SK.prf, PK.seed, PK.root),
// (optional) additional random 𝑎𝑑𝑑𝑟𝑛𝑑
// Output: SLH-DSA signature SIG.
fn slh_sign_internal(c Context, m []u8, sk Sk, addrnd []u8, opt SignerOpts) ![]u8 {
	// ADRS ← toByte(0, 32)
	mut addr := Address{}
	// substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛
	mut opt_rand := addrnd.clone()
	if opt.deterministic {
		opt_rand = unsafe { sk.pk.seed }
	}
	if opt.randomize {
		opt_rand = unsafe { rand.read(c.n)! }
	}
	// generate randomizer, 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 )
	r := c.prf_msg(sk.prf, opt_rand, m)!
	// SIG ← r
	mut sig := r.clone()

	// compute message digest, 	𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := c.h_msg(r, sk.pk.seed, sk.pk.root, m)!
	// 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ (𝑘⋅𝑎 ⌉ 8 )]
	md := digest[0..cdiv(c.k * c.a, 8)]

	// (k*a)/8 .. (k*a)/8 + (h-h/d)/8
	tmp_idx_tree := digest[cdiv(c.k * c.a, 8)..cdiv(c.k * c.a, 8) + cdiv(c.h - (c.h / c.d), 8)]

	// (k*a)/8 + (h-h/d)/8 .. (k*a)/8 + (h-h/d)/8 + h/8d
	tmp_idx_leaf := digest[cdiv(c.k * c.a, 8) + cdiv(c.h - (c.h / c.d), 8)..cdiv(c.k * c.a, 8) +
		cdiv(c.h - (c.h / c.d), 8) + cdiv(c.h, 8 * c.d)]
	idx_tree := to_int(tmp_idx_tree, cdiv(c.h - c.h / c.d, 8)) % (1 << (c.h - c.h / c.d)) // mod 2^(ℎ−ℎ/d)
	idx_leaf := to_int(tmp_idx_leaf, cdiv(c.h, 8 * c.d)) % (1 << (c.h / c.d))

	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	addr.set_tree_address(u32(idx_tree))

	// ADRS.setTypeAndClear(FORS_TREE)
	addr.set_type_and_clear(.fors_tree)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	addr.set_keypair_address(u32(idx_leaf))
	// SIG𝐹𝑂𝑅𝑆 ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
	sig_fors := fors_sign(c, md, sk.seed, sk.pk.seed, mut addr)!
	// SIG ← SIG ∥ SIG𝐹𝑂𝑅s
	sig << sig_fors

	// get FORS key, PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pk_fors := fors_pkfromsig(c, sig_fors, md, sk.pk.seed, mut addr)!
	// 17: SIG𝐻𝑇 ← ht_sign(PK𝐹𝑂𝑅𝑆, SK.seed, PK.seed,𝑖𝑑𝑥𝑡𝑟𝑒𝑒,𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	sig_ht := ht_sign(c, pk_fors, sk.seed, sk.pk.seed, int(idx_tree), int(idx_leaf))!

	// : SIG ← SIG ∥ SIG𝐻t
	sig << sig_ht
	// : return SIG
	return sig
}

// The private key has a size of 4 * n bytes, which includes the public key components.
// i.e. It consists of the concatenation of SK.seed, SK.prf, PK.seed and PF.root
struct Sk {
mut:
	seed []u8
	prf  []u8
	pk   Pk
}

fn (sk Sk) bytes() []u8 {
	mut out := []u8{}
	out << sk.seed
	out << sk.prf
	out << sk.pk.seed
	out << sk.pk.root

	return out
}

// The public key has a size of 2 * n bytes. i.e. It consists of the concatenation of PK.seed and PK.root
struct Pk {
mut:
	seed []u8
	root []u8
}

fn (pk Pk) bytes() []u8 {
	mut out := []u8{}
	out << pk.seed
	out << pk.root

	return out
}

// 10.1 SLH-DSA Key Generation
//
// Algorithm 21 slh_keygen()
// Generates an SLH-DSA key pair.
// Input: (none)
// Output: SLH-DSA key pair (SK, PK)
fn slh_keygen(c Context) !(Sk, Pk) {
	// set SK.seed, SK.prf, and PK.seed to random 𝑛-byte
	sk_seed := rand.read(c.n)!
	sk_prf := rand.read(c.n)!
	pk_seed := rand.read(c.n)!

	return slh_keygen_internal(c, sk_seed, sk_prf, pk_seed)!
}

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//
// Generates an SLH-DSA key pair.
// Input: Secret seed SK.seed, PRF key SK.prf, public seed PK.seed
// Output: SLH-DSA key pair (SK, PK).
fn slh_keygen_internal(c Context, sk_seed []u8, sk_prf []u8, pk_seed []u8) !(Sk, Pk) {
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷
	mut addr := Address{}
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(u32(c.d - 1))
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pk_root := xmss_node(c, sk_seed, 0, c.hp, pk_seed, mut addr)!
	// 4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
	pk := Pk{
		seed: pk_seed
		root: pk_root
	}
	sk := Sk{
		seed: sk_seed
		prf:  sk_prf
		pk:   pk
	}
	return sk, pk
}

// 9.3 SLH-DSA Signature Verification
//
// Algorithm 20 slh_verify_internal(𝑀, SIG, PK)
// Verifies an SLH-DSA signature.
// Input: Message 𝑀, signature SIG, public key PK = (PK.seed, PK.root).
// Output: Boolean.
fn slh_verify_internal(c Context, m []u8, sig []u8, pk Pk) !bool {
	// if |SIG| ≠ (1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 { return false }
	exp_length := (1 + c.k * (1 + c.a) + c.h + c.d * c.wots_len()) * c.n
	if sig.len != exp_length {
		return false
	}

	// ADRS ← toByte(0, 32)
	mut addr := Address{}
	// 𝑅 ← SIG.getR(), ▷ SIG[0 ∶ n]
	r := sig[0..c.n].clone()
	// SIG𝐹𝑂𝑅𝑆 ← SIG.getSIG_FORS(), SIG[𝑛 ∶ (1 + 𝑘(1 + 𝑎)) ⋅ 𝑛]
	sig_fors := sig[c.n..(1 + c.k * (1 + c.a)) * c.n]
	// SIG𝐻𝑇 ← SIG.getSIG_HT(), SIG[(1 + 𝑘(1 + 𝑎)) ⋅ 𝑛 ∶ (1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛]
	sig_ht := sig[(1 + c.k * (1 + c.a)) * c.n..(1 + c.k * (1 + c.a) + c.h + c.d * c.wots_len()) * c.n]

	// compute message digest, 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := c.h_msg(r, pk.seed, pk.root, m)!

	// first (k.a)/8 bytes, 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎]/8]
	md := digest[0..cdiv(c.k * c.a, 8)]

	// next ⌈ℎ−ℎ/𝑑]/8 ⌉ bytes
	tmp_idx_tree := digest[cdiv(c.k * c.a, 8)..cdiv(c.k * c.a, 8) + cdiv(c.h - c.h / c.d, 8)]

	// next [h/8𝑑] bytes
	tmp_idx_leaf := digest[cdiv(c.k * c.a, 8) + cdiv(c.h - c.h / c.d, 8)..cdiv(c.k * c.a, 8) +
		cdiv(c.h - c.h / c.d, 8) + cdiv(c.h, 8 * c.d)]

	idx_tree := to_int(tmp_idx_tree, cdiv(c.h - c.h / c.d, 8)) % (1 << (c.h - c.h / c.d)) // mod 2^(ℎ−ℎ/d)
	idx_leaf := to_int(tmp_idx_leaf, cdiv(c.h, 8 * c.d)) % (1 << (c.h / c.d)) // mod 2^(ℎ/d)

	// compute FORS public key
	addr.set_tree_address(u32(idx_tree))
	addr.set_type_and_clear(.fors_tree)
	addr.set_keypair_address(u32(idx_leaf))

	// PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pk_fors := fors_pkfromsig(c, sig_fors, md, pk.seed, mut addr)!

	// return ht_verify(PK𝐹𝑂𝑅𝑆, SIG𝐻𝑇, PK.seed,𝑖𝑑𝑥𝑡𝑟𝑒𝑒,𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.root)
	return ht_verify(c, pk_fors, sig_ht, pk.seed, int(idx_tree), int(idx_leaf), pk.root)!
}

const max_allowed_context_string = 255
// 10.2.1 Pure SLH-DSA Signature Generation
//
// Algorithm 22 slh_sign(𝑀, 𝑐𝑡𝑥, SK)
// Generates a pure SLH-DSA signature.
// Input: Message 𝑀, context string 𝑐𝑥, private key SK.
// Output: SLH-DSA signature SIG.
fn slh_sign(c Context, m []u8, cx []u8, sk Sk, opt SignerOpts) ![]u8 {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	mut addrnd := []u8{}
	if opt.randomize {
		addrnd = rand.read(c.n)!
	}

	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msg := []u8{}
	msg << to_byte(0, 1)
	msg << to_byte(u64(cx.len), 1)
	msg << cx
	msg << m

	// SIG ← slh_sign_internal(𝑀′, SK, 𝑎𝑑𝑑𝑟𝑛𝑑) ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(c, msg, sk, addrnd, opt)!

	return sig
}

/*
// 10.2.2 HashSLH-DSA Signature Generation
//
// Algorithm 23 hash_slh_sign(𝑀, 𝑐𝑡𝑥, PH, SK)
// Generates a pre-hash SLH-DSA signature.
// Input: Message 𝑀, context string 𝑐𝑡𝑥, pre-hash function PH, private key SK.
// Output: SLH-DSA signature SIG.
fn hash_slh_sign(c Context, m []u8, cx []u8, ph crypto.Hash, sk Sk, opt SignerOpts) ![]u8 {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	mut addrnd := []u8{}
	if opt.randomize {
		addrnd = rand.read(c.n)!
	}

	// default to sha256
	// OID ← toByte(0x0609608648016503040201, 11)
	mut oid := to_byte(u64(0x0609608648016503040201), 11)
	// PH𝑀 ← SHA-256(𝑀 )
	mut phm := sha256.sum256(m)

	match ph {
		.sha256 {
			// do nothing
		}
		.sha512 {
			// OID ← toByte(0x0609608648016503040203, 11) ▷ 2.16.840.1.101.3.4.2.3
			oid = to_byte(u64(0x0609608648016503040203), 11)
			// PH𝑀 ← SHA-512(𝑀 )
			phm = sha512.sum512(m)
		}
		// need to be patched into .shake128
		.sha3_224 {
			// OID ← toByte(0x060960864801650304020B, 11) ▷ 2.16.840.1.101.3.4.2.11
			oid = to_byte(u64(0x060960864801650304020B), 11)
			// 17: PH𝑀 ← SHAKE128(𝑀, 256)
			phm = sha3.shake128(m, 256)
		}
		// // need to be patched into .shake256
		.sha3_256 {
			// OID ← toByte(0x060960864801650304020C, 11) ▷ 2.16.840.1.101.3.4.2.12
			oid = to_byte(u64(0x060960864801650304020C), 11)
			// PH𝑀 ← SHAKE256(𝑀, 512)
			phm = sha3.shake256(m, 512)
		}
		else {
			return error('Unsupported hash')
		}
	}

	// 𝑀′ ← toByte(1, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PHm
	mut msg := []u8{}
	msg << to_byte(1, 1)
	msg << to_byte(cx.len, 1)
	msg << cx
	msg << oid
	msg << phm

	// SIG ← slh_sign_internal(𝑀′, SK, 𝑎𝑑𝑑𝑟𝑛𝑑) ▷ omit 𝑎𝑑𝑑𝑟𝑛𝑑 for the deterministic variant
	sig := slh_sign_internal(msg, sk, addrnd, opt)!

	return sig
}
*/

// 10.3 SLH-DSA Signature Verification
//
// Algorithm 24 slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PK)
// Verifies a pure SLH-DSA signature.
// Input: Message 𝑀, signature sig , context string 𝑐𝑡𝑥, public key PK.
// Output: Boolean.
fn slh_verify(c Context, m []u8, sig []u8, cx []u8, pk Pk) !bool {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// 𝑀′ ← toByte(0, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ m
	mut msg := []u8{}
	msg << to_byte(0, 1)
	msg << to_byte(u64(cx.len), 1)
	msg << cx
	msg << m

	// return slh_verify_internal(𝑀′, SIG, PK)
	return slh_verify_internal(c, msg, sig, pk)!
}

/*
// Algorithm 25 hash_slh_verify(𝑀, SIG, 𝑐𝑡𝑥, PH, PK)
// Verifies a pre-hash SLH-DSA signature.
// Input: Message 𝑀, signature SIG, context string 𝑐𝑡𝑥, pre-hash function PH, public key PK.
// Output: Boolean.
fn hash_slh_verify(c Context, m []u8, sig []u8, cx []u8, ph crypto.Hash, pk Pk) !bool {
	if cx.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
	// default to sha256
	// OID ← toByte(0x0609608648016503040201, 11)
	mut oid := to_byte(u64(0x0609608648016503040201), 11)
	// PH𝑀 ← SHA-256(𝑀 )
	mut phm := sha256.sum256(m)

	match ph {
		.sha256 {
			// do nothing
		}
		.sha512 {
			// OID ← toByte(0x0609608648016503040203, 11) ▷ 2.16.840.1.101.3.4.2.3
			oid = to_byte(u64(0x0609608648016503040203), 11)
			// PH𝑀 ← SHA-512(𝑀 )
			phm = sha512.sum512(m)
		}
		// need to be patched into .shake128
		.sha3_224 {
			// OID ← toByte(0x060960864801650304020B, 11) ▷ 2.16.840.1.101.3.4.2.11
			oid = to_byte(u64(0x060960864801650304020B), 11)
			// 17: PH𝑀 ← SHAKE128(𝑀, 256)
			phm = sha3.shake128(m, 256)
		}
		// // need to be patched into .shake256
		.sha3_256 {
			// OID ← toByte(0x060960864801650304020C, 11) ▷ 2.16.840.1.101.3.4.2.12
			oid = to_byte(u64(0x060960864801650304020C), 11)
			// PH𝑀 ← SHAKE256(𝑀, 512)
			phm = sha3.shake256(m, 512)
		}
		else {
			return error('Unsupported hash')
		}
	}
	// 𝑀′ ← toByte(1, 1) ∥ toByte(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PHm
	mut msg := []u8{}
	msg << to_byte(1, 1)
	msg << to_byte(u64(cx.len), 1)
	msg << cx
	msg << oid
	msg << phm

	// return slh_verify_internal(𝑀′, SIG, PK)
	return slh_verify_internal(c, msg, sig, pk)!
}
*/
