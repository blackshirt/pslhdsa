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
	sig := r.clone()

	// compute message digest, 	𝑑𝑖𝑔𝑒𝑠𝑡 ← H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 )
	digest := ctx.h_msg(r, pk.seed, pk.root, m)!
	// 𝑚𝑑 ← 𝑑𝑖𝑔𝑒𝑠𝑡 [0 ∶ (𝑘⋅𝑎 ⌉ 8 )]
	md := digest[0..cdiv(ctx.prm.k * ctx.prm.a, 8)]

	// (k*a)/8 .. (k*a)/8 + (h-h/d)/8
	tmp_idx_tree := digest[cdiv(ctx.prm.k * ctx.prm.a, 8)..cdiv(ctx.prm.k * ctx.prm.a, 8) +
		cdiv(ctx.prm.h - (ctx.prm.h / ctx.prm.d), 8)]
	tmp_idx_leaf = digest[cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8) : cdiv(ctx.k*ctx.a,8)+cdiv(ctx.h-ctx.h//ctx.d,8)+cdiv(ctx.h,8*ctx.d)]
	// idx_tree := toInt(tmp_idx_tree, cdiv(ctx.h-ctx.h//ctx.d,8)) % 2**(ctx.h-ctx.h//ctx.d)
	// idx_leaf := toInt(tmp_idx_leaf, cdiv(ctx.h,8*ctx.d)) % 2**(ctx.h//ctx.d)
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
