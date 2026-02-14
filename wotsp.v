// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Winternitz One-Time Signature Plus Scheme (WOTS+) module
module pslhdsa

// 5.1 WOTS+ Public-Key Generation
//
// Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS)
// Generates a WOTS+ public key.
// Input: Secret seed SK.seed, public seed PK.seed, address ADRS.
// Output: WOTS+ public key 𝑝k
@[direct_array_access]
fn wots_pkgen(mut c Context, skseed []u8, pkseed []u8, mut adr Address) ![]u8 {
	assert adr.get_type()! == .wots_hash
	// copy address to create key generation key address
	mut sk_addr := adr.clone()
	// skADRS.setTypeAndClear(WOTS_PRF)
	sk_addr.set_type_and_clear(.wots_prf)
	// skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	sk_addr.set_keypair_address(adr.get_keypair_address())

	// gets wotsp length from the current context
	length := c.wots_len()
	// temporary buffer to store output
	mut tmp := [][]u8{len: length}
	for i := u32(0); i < length; i++ {
		// skADRS.setChainAddress(𝑖)
		sk_addr.set_chain_address(i)
		// compute secret value for chain i, 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)
		sk := c.prf(pkseed, skseed, sk_addr, c.prm.n)!
		// ADRS.setChainAddress(𝑖)
		adr.set_chain_address(i)
		// compute public value for chain 𝑖, 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑘, 0, 𝑤 − 1, PK.seed, ADRS)
		// w == 16 in this standard
		tmp[i] = chain(mut c, sk, 0, 15, pkseed, mut adr)!
		// tmp << tmp_i
	}
	// copy address to create WOTS+public key address, wotspkADRS ← ADRS
	mut wots_pkadr := adr.clone()
	// wotspkADRS.setTypeAndClear(WOTS_PK)
	wots_pkadr.set_type_and_clear(.wots_pk)
	// wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	// TODO: remove int cast
	wots_pkadr.set_keypair_address(adr.get_keypair_address())
	// compress public key, 𝑝𝑘 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS,𝑡𝑚𝑝)
	pk := c.tl(pkseed, wots_pkadr, tmp, c.prm.n)!

	return pk
}

// 5.2 WOTS+ Signature Generation
// A WOTS+ signature is an array of 𝑙𝑒𝑛 byte strings of length n
//
// Algorithm 7 wots_sign(𝑀, SK.seed, PK.seed, ADRS)
// Generates a WOTS+ signature on an 𝑛-byte message.
// Input: Message 𝑀, secret seed SK.seed, public seed PK.seed, address ADRS.
// Output: WOTS+ signature 𝑠𝑖𝑔.
@[direct_array_access]
fn wots_sign(mut c Context, m []u8, skseed []u8, pkseed []u8, mut adr Address) ![][]u8 {
	// get some context variables
	length := c.wots_len()
	len1 := c.wots_len1()
	len2 := c.wots_len2()

	// convert message to base w, ie, 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1)
	mut msg := base_2b(m, c.prm.lgw, len1)

	// compute checksum of msg of []u32
	mut csum := wots_csum(c, msg)

	// convert to base w, 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈(𝑙𝑒𝑛2*𝑙𝑔𝑤)/8⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2)
	// mlen := 2 // cdiv(len2 * c.prm.lgw, 8)
	mlen := ((len2 * c.prm.lgw) + 7) >> 3
	bytes := to_byte(csum, mlen)
	msg << base_2b(bytes, c.prm.lgw, len2)

	// copy address to create key generation key address
	mut sk_addr := adr.clone()
	// skADRS.setTypeAndClear(WOTS_PRF)
	sk_addr.set_type_and_clear(.wots_prf)
	// skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	// TODO: handle int > larger than max_int
	sk_addr.set_keypair_address(adr.get_keypair_address())

	mut sig := [][]u8{len: length}
	for i := u32(0); i < length; i++ {
		// skADRS.setChainAddress(𝑖)
		sk_addr.set_chain_address(i)
		// compute chain 𝑖 secret value, 𝑠𝑘 ← PRF(PK.seed, SK.seed, skADRS)
		sk := c.prf(pkseed, skseed, sk_addr, c.prm.n)!
		// ADRS.setChainAddress(𝑖)
		adr.set_chain_address(i)
		// compute chain 𝑖 signature value, 𝑠𝑖𝑔[𝑖] ← chain(𝑠𝑘, 0, 𝑚𝑠𝑔[𝑖], PK.seed, ADRS)
		sig[i] = chain(mut c, sk, 0, msg[i], pkseed, mut adr)!
		// sig << sig_i
	}
	return sig
}

// 5.3 Computing a WOTS+ Public Key From a Signature
//
// Algorithm 8 wots_pkFromSig(𝑠𝑖𝑔, 𝑀, PK.seed, ADRS)
// Computes a WOTS+ public key from a message and its signature.
// Input: WOTS+ signature 𝑠𝑖𝑔, message 𝑀, public seed
// Output: WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔.
@[direct_array_access]
fn wots_pkfromsig(mut c Context, sig [][]u8, m []u8, pkseed []u8, mut adr Address) ![]u8 {
	// get some context variables
	length := c.wots_len()
	len1 := c.wots_len1()
	len2 := c.wots_len2()

	// convert message to base w, ie, 𝑚𝑠𝑔 ← base_2b(𝑀, 𝑙𝑔𝑤, 𝑙𝑒𝑛1)
	mut msg := base_2b(m, c.prm.lgw, len1)

	// compute checksum of msg of []u32
	mut csum := wots_csum(c, msg)

	// convert to base w, 𝑚𝑠𝑔 ← 𝑚𝑠𝑔 ∥ base_2b (toByte (𝑐𝑠𝑢𝑚, ⌈(𝑙𝑒𝑛2*𝑙𝑔𝑤)/8⌉) , 𝑙𝑔𝑤, 𝑙𝑒𝑛2)
	// by lgw == 4 defined in standard, normally its has value 2
	mlen := ((len2 * c.prm.lgw) + 7) >> 3
	msg << base_2b(to_byte(csum, mlen), c.prm.lgw, len2)

	// setup temporary buffers with appropriate length
	mut tmp := [][]u8{len: length}

	for i := u32(0); i < length; i++ {
		// ADRS.setChainAddress(𝑖)
		adr.set_chain_address(i)
		// 𝑡𝑚𝑝[𝑖] ← chain(𝑠𝑖𝑔[𝑖], 𝑚𝑠𝑔[𝑖], 𝑤 − 1 − 𝑚𝑠𝑔[𝑖], PK.seed, ADRS)
		// x := sig[i * c.prm.n..(i + 1) * c.prm.n]
		tmp[i] = chain(mut c, sig[i], msg[i], u32(w) - 1 - msg[i], pkseed, mut adr)!
	}
	// copy address to create WOTS+ public key address, wotspkADRS ← ADRS
	mut wots_pkadr := adr.clone()
	// wotspkADRS.setTypeAndClear(WOTS_PK)
	wots_pkadr.set_type_and_clear(.wots_pk)
	// wotspkADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
	// TODO: remove int casts ??
	wots_pkadr.set_keypair_address(adr.get_keypair_address())
	// 𝑝𝑘𝑠𝑖𝑔 ← T𝑙𝑒𝑛(PK.seed, wotspkADRS,𝑡𝑚𝑝)
	pk_sig := c.tl(pkseed, wots_pkadr, tmp, c.prm.n)!

	return pk_sig
}

// WOTS+ chaining function
//
// Algorithm 5 chain(𝑋, 𝑖, 𝑠, PK.seed, ADRS)
//
// Chaining function used in WOTS+.
// Input: Input string 𝑋, start index 𝑖, number of steps 𝑠, public seed PK.seed, address ADRS.
// Output: Value of F iterated 𝑠 times on 𝑋.
// (where 𝑖 + 𝑠 < w
// NOTE: should this be inlined ?
@[direct_array_access]
fn chain(mut c Context, x []u8, i u32, s u32, pkseed []u8, mut adr Address) ![]u8 {
	// We omit the check, its internal function and controllable
	// if i + s >= w {
	// 	return error('Invalid wots+ params')
	// }
	// TODO: should we make x as mutable  for performance reason ?
	mut tmp := x.clone()
	for j := i; j < i + s; j++ {
		// ADRS.setHashAddress(𝑗)
		adr.set_hash_address(j)
		// 𝑡𝑚𝑝 ← F(PK.seed, ADRS,𝑡𝑚𝑝)
		tmp = c.f(pkseed, adr, tmp, c.prm.n)!
	}
	return tmp
}

@[direct_array_access]
fn wots_csum(c &Context, m []u32) u64 {
	mut csum := u64(0)
	t := u32((1 << c.prm.lgw) - 1)

	len1 := c.wots_len1()
	len2 := c.wots_len2()

	// for 𝑖 from 0 to 𝑙𝑒𝑛1 − 1 do
	for i := 0; i < len1; i++ {
		// 𝑐𝑠𝑢𝑚 ← 𝑐𝑠𝑢𝑚 + 𝑤 − 1 − 𝑚𝑠𝑔[𝑖]
		csum += t - m[i]
	}
	// csum <<= 4
	csum <<= u64((8 - ((len2 * c.prm.lgw) & 7)) & 7)

	return csum
}
