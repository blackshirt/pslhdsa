module pslhdsa

import crypto.rand

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
fn slh_sign_internal(ctx Context, m []u8, sk Sk, addrnd []u8, opt SignerOpts) ![]u8 {
	// ADRS ← toByte(0, 32)
	mut addr := to_byte(0, 32)
	// substitute 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← PK.seed for the deterministic variant, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ← 𝑎𝑑𝑑𝑟𝑛
	mut opt_rand := addrnd.clone()
	if opt.deterministic {
		opt_rand = sk.pk.seed
	}
	if opt.randomize {
		opt_rand = rand.read(ctx.prm.n)!
	}
	// generate randomizer, 𝑅 ← PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 )
	r := ctx.prf_msg(sk.prf, opt_rand, m)!
	// SIG ← r
	mut sig := r.clone()

	// compute message digest, 	𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := ctx.h_msg(r, pk.seed, pk.root, m)!
	// 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ (𝑘⋅𝑎 ⌉ 8 )]
	md := digest[0..cdiv(ctx.prm.k * ctx.prm.a, 8)]

	// (k*a)/8 .. (k*a)/8 + (h-h/d)/8
	tmp_idx_tree := digest[cdiv(ctx.prm.k * ctx.prm.a, 8)..cdiv(ctx.prm.k * ctx.prm.a, 8) +
		cdiv(ctx.prm.h - (ctx.prm.h / ctx.prm.d), 8)]

	// (k*a)/8 + (h-h/d)/8 .. (k*a)/8 + (h-h/d)/8 + h/8d
	tmp_idx_leaf = digest[cdiv(ctx.prm.k * ctx.prm.a, 8) +
		cdiv(ctx.prm.h - (ctx.prm.h / ctx.prm.d), 8)..cdiv(ctx.prm.k * ctx.prm.a, 8) +
		cdiv(ctx.prm.h - (ctx.prm.h / ctx.prm.d), 8) + cdiv(ctx.prm.h, 8 * ctx.prm.d)]
	idx_tree := to_int(tmp_idx_tree, cdiv(ctx.prm.h - ctx.prm.h / ctx.prm.d, 8)) % (1 << (ctx.prm.h - ctx.prm.h / ctx.prm.d)) // mod 2^(ℎ−ℎ/d)
	idx_leaf := to_int(tmp_idx_leaf, cdiv(ctx.prm.h, 8 * ctx.prm.d)) % (1 << (ctx.prm.h / ctx.prm.d))

	// ADRS.setTreeAddress(𝑖𝑑𝑥𝑡𝑟𝑒𝑒)
	addr.set_tree_address(idx_tree)

	// ADRS.setTypeAndClear(FORS_TREE)
	addr.set_type_and_clear(.fors_tree)
	// ADRS.setKeyPairAddress(𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	addr.set_keypair_address(idx_leaf)
	// SIG𝐹𝑂𝑅𝑆 ← fors_sign(𝑚𝑑, SK.seed, PK.seed, ADRS)
	sig_fors := fors_sign(ctx, md, sk.seed, sk.pk.seed, addr)!
	// SIG ← SIG ∥ SIG𝐹𝑂𝑅s
	sig << sig_fors

	// get FORS key, PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pk_fors := fors_pkfromsig(ctx, sig_fors, md, sk.pk.seed, addr)!
	// 17: SIG𝐻𝑇 ← ht_sign(PK𝐹𝑂𝑅𝑆, SK.seed, PK.seed,𝑖𝑑𝑥𝑡𝑟𝑒𝑒,𝑖𝑑𝑥𝑙𝑒𝑎𝑓)
	sig_ht := ht_sign(ctx, pk_fors, sk.seed, sk.pk.seed, idx_tree, idx_leaf)!

	// : SIG ← SIG ∥ SIG𝐻�
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

// The public key has a size of 2 * n bytes. i.e. It consists of the concatenation of PK.seed and PK.root
struct Pk {
mut:
	seed []u8
	root []u8
}

// 10.1 SLH-DSA Key Generation
//
// Algorithm 21 slh_keygen()
// Generates an SLH-DSA key pair.
// Input: (none)
// Output: SLH-DSA key pair (SK, PK)
fn slh_keygen(ctx Context) ! {
	// set SK.seed, SK.prf, and PK.seed to random 𝑛-byte
	sk_seed := rand.read(ctx.prm.n)!
	sk_prf := rand.read(ctx.prm.n)!
	pk_seed := rand.read(ctx.prm.n)!

	return slh_keygen_internal(ctx, sk_seed, sk_prf, pk_seed)!
}

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//
// Generates an SLH-DSA key pair.
// Input: Secret seed SK.seed, PRF key SK.prf, public seed PK.seed
// Output: SLH-DSA key pair (SK, PK).
fn slh_keygen_internal(ctx Context, sk_seed []u8, sk_prf []u8, pk_seed []u8) !(Sk, Pk) {
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷
	mut addr := to_byte(0, 32)
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(ctx.prm.d - 1)
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pk_root := xmms_node(ctx, sk_seed, 0, ctx.prm.hp, pk_seed, mut addr)!
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
fn slh_verify_internal(ctx Context, m []u8, sig []u8, pk Pk) !bool {
	// if |SIG| ≠ (1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛 { return false }
	exp_length := (1 + ctx.prm.k * (1 + ctx.prm.a) + ctx.prm.h + ctx.prm.d * ctx.prm.wots_len()) * ctx.prm.n
	if sig.len != exp_length {
		return false
	}

	// ADRS ← toByte(0, 32)
	mut addr := to_byte(0, 32)
	// 𝑅 ← SIG.getR(), ▷ SIG[0 ∶ n]
	r := sig[0..ctx.prm.n].clone()
	// SIG𝐹𝑂𝑅𝑆 ← SIG.getSIG_FORS(), SIG[𝑛 ∶ (1 + 𝑘(1 + 𝑎)) ⋅ 𝑛]
	sig_fors := sig[ctx.prm.n..(1 + ctx.prm.k * (1 + ctx.prm.a)) * ctx.prm.n]
	// SIG𝐻𝑇 ← SIG.getSIG_HT(), SIG[(1 + 𝑘(1 + 𝑎)) ⋅ 𝑛 ∶ (1 + 𝑘(1 + 𝑎) + ℎ + 𝑑 ⋅ 𝑙𝑒𝑛) ⋅ 𝑛]
	sig_ht := sig[(1 + ctx.prm.k * (1 + ctx.prm.a)) * ctx.prm.n..(1 + ctx.prm.k * (1 + ctx.prm.a) +
		ctx.prm.h + ctx.prm.d * ctx.prm.wots_len()) * ctx.prm.n]

	// compute message digest, 𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := ctx.h_msg(r, pk.seed, pk.root, m)!

	// first (k.a)/8 bytes, 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ ⌈𝑘⋅𝑎]/8]
	md := digest[0..cdiv(ctx.prm.k * ctx.prm.a, 8)]

	// next ⌈ℎ−ℎ/𝑑]/8 ⌉ bytes
	tmp_idx_tree := digest[cdiv(ctx.k * ctx.prm.a, 8)..cdiv(ctx.prm.k * ctx.prm.a, 8) +
		cdiv(ctx.prm.h - ctx.prm.h / ctx.prm.d, 8)]

	// next [h/8𝑑] bytes
	tmp_idx_leaf = digest[cdiv(ctx.prm.k * ctx.a, 8) + cdiv(ctx.prm.h - ctx.prm.h / ctx.prm.d, 8)..
		cdiv(ctx.prm.k * ctx.prm.a, 8) + cdiv(ctx.prm.h - ctx.prm.h / ctx.prm.d, 8) +
		cdiv(ctx.prm.h, 8 * ctx.prm.d)]

	idx_tree := to_int(tmp_idx_tree, cdiv(ctx.prm.h - ctx.prm.h / ctx.prm.d, 8)) % (1 << (ctx.prm.h - ctx.prm.h / ctx.prm.d)) // mod 2^(ℎ−ℎ/d)
	idx_leaf := to_int(tmp_idx_leaf, cdiv(ctx.prm.h, 8 * ctx.prm.d)) % (1 << (ctx.prm.h / ctx.prm.d)) // mod 2^(ℎ/d)

	// compute FORS public key
	addr.set_tree_address(idx_tree)
	addr.set_type_and_clear(.fors_tree)
	addr.set_key_pair_address(idx_leaf)

	// PK𝐹𝑂𝑅𝑆 ← fors_pkFromSig(SIG𝐹𝑂𝑅𝑆, 𝑚𝑑, PK.seed, ADRS)
	pk_fors := fors_pkfromsig(ctx, sig_fors, md, pk.seed, addr)!

	// return ht_verify(PK𝐹𝑂𝑅𝑆, SIG𝐻𝑇, PK.seed,𝑖𝑑𝑥𝑡𝑟𝑒𝑒,𝑖𝑑𝑥𝑙𝑒𝑎𝑓, PK.root)
	return ht_verify(ctx, pk_fors, sig_ht, pk.seed, idx_tree, idx_leaf, pk.root)!
}

const max_allowed_context_string = 255
// 10.2.1 Pure SLH-DSA Signature Generation
//
// Algorithm 22 slh_sign(𝑀, 𝑐𝑡𝑥, SK)
// Generates a pure SLH-DSA signature.
// Input: Message 𝑀, context string 𝑐𝑡𝑥, private key SK.
// Output: SLH-DSA signature SIG.
fn slh_sign(ctx Context, m []u8, cxs []u8, sk Sk) ![]u8 {
	if cxs.len > max_allowed_context_string {
		return error('pure SLH-DSA signature failed: exceed context-string')
	}
}
