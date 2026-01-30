// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// The main SLH-DSA key generation module
module pslhdsa

import crypto.rand
import crypto.internal.subtle

// 10.1 SLH-DSA Key Generation
//
// Algorithm 21 slh_keygen()
// Generates an SLH-DSA key pair.
// Input: (none)
// Output: SLH-DSA key pair (SK, PK).
// slh_keygen generates a SLH-DSA key pair with the given kind.
// If the kind is not supported, it returns an error.
// Its uses crypto.rand to generate random seed for the key generation.
pub fn slh_keygen(c &Context) !&SigningKey {
	// set SK.seed, SK.prf, and PK.seed to random 𝑛-byte
	skseed := rand.read(c.prm.n)!
	skprf := rand.read(c.prm.n)!
	pkseed := rand.read(c.prm.n)!

	// check if the seed is all zeroes
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) {
		return error('seed is all zeroes')
	}

	return slh_keygen_internal(c, skseed, skprf, pkseed)!
}

// slh_keygen_from_bytes generates a SLH-DSA key with the given bytes.
// By default, it will check if the public key root is valid for the given context.
// If opt.check_pk is set to false, it will not check the public key root.
@[direct_array_access]
pub fn slh_keygen_from_bytes(ctx &Context, bytes []u8, opt Options) !&SigningKey {
	// check if the bytes length is equal to n * 4
	if bytes.len != 4 * ctx.prm.n {
		return error('seed length must be equal to n * 4')
	}
	skseed := bytes[..ctx.prm.n]
	skprf := bytes[ctx.prm.n..2 * ctx.prm.n]
	pkseed := bytes[2 * ctx.prm.n..3 * ctx.prm.n]
	pkroot := bytes[3 * ctx.prm.n..]

	// check for unallowed zeros in the seed
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) || is_zero(pkroot) {
		return error('seed is all zeroes')
	}
	// check if the public key root is valid for the given context by doing
	// procedure step in Algorithm 18 of slh_keygen_internal
	if opt.check_pk {
		mut addr := new_address()
		// 2: ADRS.setLayerAddress(𝑑 − 1)
		addr.set_layer_address(u32(ctx.prm.d - 1))
		// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
		pkroot_node := xmss_node(ctx, skseed, 0, u32(ctx.prm.hp), pkseed, mut addr)!
		// Check if the xmss_node function call was successful
		if pkroot_node.len != ctx.prm.n {
			return error('xmss_node failed')
		}
		// 4: Check if the computed root matches the provided root
		if subtle.constant_time_compare(pkroot_node, pkroot) != 1 {
			return error('public key root is not valid for given context')
		}
	}
	// otherwise, its ok to return the signing key
	return &SigningKey{
		ctx:    ctx.clone()
		seed:   skseed
		prf:    skprf
		pkseed: pkseed
		pkroot: pkroot
	}
}

// slh_keygen_from_seed generates a SLH-DSA key with the given seed.
// The every seed must be of length ctx.prm.n.
@[direct_array_access]
pub fn slh_keygen_from_seed(ctx &Context, skseed []u8, skprf []u8, pkseed []u8) !&SigningKey {
	// check for the length	
	if skseed.len != ctx.prm.n || skprf.len != ctx.prm.n || pkseed.len != ctx.prm.n {
		return error('seed length must be equal to n')
	}
	// check if the seed is all zeroes
	if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) {
		return error('seed is all zeroes')
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
	sk := &SigningKey{
		ctx:    ctx.clone()
		seed:   skseed
		prf:    skprf
		pkseed: pkseed
		pkroot: pkroot_node
	}

	return sk
}
