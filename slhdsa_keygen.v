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
// Generates an SLH-DSA signing key.
// Input: The optional options for key generation or use default one
// Output: SLH-DSA signing key
// slh_keygen generates a SLH-DSA signing key with the given options.
// By default, it uses crypto.rand to generate random seed for the key generation.
// Internally, the signing key result embeds the public key part of the key pair.
// You can get the public key part by calling the `pk := sk.pubkey()` method.
pub fn slh_keygen(t SLHType) !&SigningKey {
	// makes the SLH-DSA context from tipe t
	mut c := new_context(t)

	// Set SK.seed, SK.prf, and PK.seed to random 𝑛-byte
	//
	// Note: instead of 3 times call on the `rand.read`, we do single `rand.read` call with 3*n size
	seed := rand.read(3 * c.prm.n)!
	skseed := unsafe { seed[0..c.prm.n] }
	skprf := unsafe { seed[c.prm.n..2 * c.prm.n] }
	pkseed := unsafe { seed[2 * c.prm.n..3 * c.prm.n] }

	// 10.1.1 Key Generation Steps
	return slh_keygen_internal(mut c, skseed, skprf, pkseed)!
}

// slh_keygen_from_bytes generates a SLH-DSA signing key with the given bytes.
// By default, it will check if the public key root is valid for the given context.
// If opt.check_pk is set to false, it will not check the public key root.
// NOTE: For each invocation of key generation, bytes of values shall be a fresh
// (i.e., not previously used) random value generated using an approved random bit generator
@[direct_array_access]
pub fn slh_keygen_from_bytes(bytes []u8, opt Options) !&SigningKey {
	// makes the SLH-DSA context from the tipe in the options
	mut c := new_context(opt.slh_type)
	// check if the bytes length is equal to n * 4
	if bytes.len != (c.prm.n << 2) {
		return error('seed length must be equal to n * 4')
	}
	skseed := bytes[..c.prm.n]
	skprf := bytes[c.prm.n..2 * c.prm.n]
	pkseed := bytes[2 * c.prm.n..3 * c.prm.n]
	pkroot := bytes[3 * c.prm.n..]

	// check for unallowed zeros in the seed
	if !opt.allow_zeros {
		if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) || is_zero(pkroot) {
			return error('seed is all or one of them are zeros bytes')
		}
	}
	// check if the public key root is valid for the given context by doing
	// procedure step in Algorithm 18 of slh_keygen_internal
	if opt.check_pk {
		mut addr := new_address()
		// 2: ADRS.setLayerAddress(𝑑 − 1)
		addr.set_layer_address(u32(c.prm.d - 1))
		// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
		pkroot_node := xmss_node(mut c, skseed, 0, u32(c.prm.hp), pkseed, mut addr)!
		// Check if the xmss_node function call was successful
		if pkroot_node.len != c.prm.n {
			return error('xmss_node failed')
		}
		// 4: Check if the computed root matches the provided root
		if subtle.constant_time_compare(pkroot_node, pkroot) != 1 {
			return error('public key root is not valid for given context')
		}
	}
	// otherwise, its ok to return the signing key
	return &SigningKey{
		ctx:    c
		seed:   skseed
		prf:    skprf
		pkseed: pkseed
		pkroot: pkroot
	}
}

// slh_keygen_from_seed generates a SLH-DSA signing key with the given seed.
// The every seed must be of length ctx.prm.n bytes.
// NOTE: For each invocation of key generation, these seed of values shall be a fresh
// (i.e., not previously used) random value generated using an approved random bit generator
@[direct_array_access]
pub fn slh_keygen_from_seed(skseed []u8, skprf []u8, pkseed []u8, opt Options) !&SigningKey {
	// makes the SLH-DSA context from the options
	mut c := new_context(opt.slh_type)
	// check for the length	
	if skseed.len != c.prm.n || skprf.len != c.prm.n || pkseed.len != c.prm.n {
		return error('every seed length must be equal to n bytes')
	}
	// check for any (all) zeros seed
	if !opt.allow_zeros {
		if is_zero(skseed) || is_zero(skprf) || is_zero(pkseed) {
			return error('seed is all or one of them are zeros bytes')
		}
	}
	return slh_keygen_internal(mut c, skseed, skprf, pkseed)!
}

// Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)
//
// Generates an SLH-DSA signing key with the given seed.
// Input: SLH-DSA context, secret seed SK.seed, PRF key SK.prf, public seed PK.seed
// Output: SLH-DSA signing key.
@[direct_array_access]
fn slh_keygen_internal(mut c Context, skseed []u8, skprf []u8, pkseed []u8) !&SigningKey {
	// generate the public key for the top-level XMSS tree
	// 1: ADRS ← toByte(0, 32) ▷ set layer and tree address to bottom layer	
	mut addr := new_address()
	// 2: ADRS.setLayerAddress(𝑑 − 1)
	addr.set_layer_address(u32(c.prm.d - 1))
	// 3: PK.root ← xmss_node(SK.seed, 0, ℎ′ , PK.seed, ADRS)
	pkroot_node := xmss_node(mut c, skseed, 0, u32(c.prm.hp), pkseed, mut addr)!
	// Check if the xmss_node function call was successful
	if pkroot_node.len != c.prm.n {
		return error('xmss_node failed')
	}
	// 4: return ( (SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root) )
	sk := &SigningKey{
		ctx:    c
		seed:   skseed
		prf:    skprf
		pkseed: pkseed
		pkroot: pkroot_node
	}

	return sk
}
