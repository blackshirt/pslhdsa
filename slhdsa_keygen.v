// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA key generation module
module pslhdsa

import crypto.rand

// 10.1 SLH-DSA Key Generation
//
// Algorithm 21 slh_keygen()
// Generates an SLH-DSA key pair.
// Input: (none)
// Output: SLH-DSA secret key
// slh_keygen generates a SLH-DSA key with the given kind.
@[inline]
fn slh_keygen(k Kind) !&SigningKey {
	// create a new context for the key generation
	ctx := new_context(k)
	// set SK.seed, SK.prf, and PK.seed to random 𝑛-byte
	skseed := rand.read(ctx.prm.n)!
	skprf := rand.read(ctx.prm.n)!
	pkseed := rand.read(ctx.prm.n)!

	// check if the seed is all zeroes
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) {
		return error('seed is all zeroes')
	}

	return slh_keygen_internal(ctx, skseed, skprf, pkseed)!
}

// slh_keygen_with_seed generates a SLH-DSA key with the given seed.
@[direct_array_access; inline]
fn slh_keygen_with_seed(ctx &Context, skseed []u8, skprf []u8, pkseed []u8) !&SigningKey {
	// check if the seed is all zeroes
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) {
		return error('seed is all zeroes')
	}
	if skseed.len != ctx.prm.n || skprf.len != ctx.prm.n || pkseed.len != ctx.prm.n {
		return error('seed length must be equal to n')
	}

	return slh_keygen_internal(ctx, skseed, skprf, pkseed)!
}

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//
// Generates an SLH-DSA key pair.
// Input: Secret seed SK.seed, PRF key SK.prf, public seed PK.seed
// Output: SLH-DSA key pair (SK, PK).
@[direct_array_access; inline]
fn slh_keygen_internal(ctx &Context, skseed []u8, skprf []u8, pkseed []u8) !&SigningKey {
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(u32(ctx.prm.d - 1))
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pkroot_node := xmss_node(ctx, skseed, 0, u32(ctx.prm.hp), pkseed, mut addr)!
	// Check if the xmss_node function call was successful
	if pkroot_node.len != ctx.prm.n {
		return error('xmss_node failed')
	}
	// 4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
	return &SigningKey{
		ctx:    unsafe { ctx }
		seed:   skseed
		prf:    skprf
		pkseed: pkseed
		pkroot: pkroot_node
	}
}
