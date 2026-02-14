// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Parameter Set and context opaque to work on SLH-DSA parameter set
module pslhdsa

import hash
import arrays
import crypto.hmac
import crypto.sha3
import crypto.sha256
import crypto.sha512

// new_context creates a new SLH-DSA Context to operate on
@[inline]
pub fn new_context(t SLHType) &Context {
	return &Context{
		tipe: t
		prm:  new_param(t)
	}
}

// new_context_from_name creates a new SLH-DSA Context from name string
// name should be one of the supported tipe name, e.g. 'SLH-DSA-SHA2-192f'
// See `SLHType` for the list of supported types.
pub fn new_context_from_name(name string) !&Context {
	return new_context(new_slh_type(name)!)
}

// SLH-DSA Context
//
// The Context structure describes SLH-DSA type and underlying parameter set
// defined in the FIPS205 standard.
@[noinit]
struct Context {
	// The type of SLH-DSA context, set on the context creation
	tipe SLHType
	// An underlying SLH-DSA parameter set described on the standard
	prm ParamSet
mut:
	// h2 and h5 was a sha256 and sha512 hash respectively.
	// Its defined here to reduce hash allocation on the context addressing routines.
	// NOTE: the simple rule is that you must call `.reset` before calling `.write` on the hash.
	// TODO: This is rather a hack than a nice solution, find a better way to do this.
	// TODO: add support for SHAKE-family hash
	h2 &hash.Hash = sha256.new()
	h5 &hash.Hash = sha512.new()

	// buffer is preallocated buffer for storing serialized (or compressed) Address.
	// For compressed address, it only take on the first 22-bytes of the buffer,
	// where normal Address take full 32-bytes of the buffer.
	// Its defined here to reduce allocation and reused buffer internally for address bytes handling.
	buffer []u8 = []u8{len: 32}
}

// slh_type returns an underlying of SLH-DSA type
pub fn (c &Context) slh_type() SLHType {
	return c.tipe
}

// name returns an underlying of SLH-DSA type name
pub fn (c &Context) name() string {
	return c.prm.name
}

// clone returns a clone of this context
fn (c &Context) clone() &Context {
	return &Context{
		tipe: c.tipe
		prm:  c.prm
		// we dont make a copy
		buffer: unsafe { c.buffer }
	}
}

// equal returns true if this context is equal to the other context
fn (c &Context) equal(o &Context) bool {
	// for sake of simplicity, only check for tipe equality, not the parameter set
	return c.tipe == o.tipe
}

// Hash Addressing and Pseudorandom Functions for SLH-DSA context
//

// prf_msg is a pseudorandom function (PRF) that generates the randomizer (𝑅)
// for the randomized hashing of the message to be signed
@[direct_array_access]
fn (c &Context) prf_msg(skprf []u8, optrand []u8, msg []u8, outlen int) ![]u8 {
	// setup buffer with enough capacity to avoid reallocation
	mut data := []u8{cap: skprf.len + optrand.len + msg.len}

	// Is this context was a SHAKE-based type? If yes procees with SHAKE-based PRF
	// For SHAKE-based family, use SHAKE256 hash
	//
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀, 8𝑛)
	if c.is_shake_family() {
		data << skprf
		data << optrand
		data << msg
		// return the shake256 digest
		return sha3.shake256(data, outlen)
	}
	// Otherwise, process with SHA2-based type
	//
	// begin by appending into data buffer
	data << optrand
	data << msg

	// For SHA2-based type with security category 1, use HMAC-SHA-256 PRF
	//
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-256(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	if c.is_sha2_seccat1() {
		digest := hmac_sha256(skprf, data)
		return digest[..outlen].clone()
	}
	// Otherwise, its should belong to type with security categories 3 or 5 and use HMAC-SHA-512 PRF
	//
	// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) = Trunc𝑛(HMAC-SHA-512(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 ))
	digest := hmac_sha512(skprf, data)

	// return the clone with appropriate outlen size
	return digest[0..outlen].clone()
}

// hmsg was used to generate the digest of the message to be signed.
@[direct_array_access]
fn (c &Context) hmsg(r []u8, pkseed []u8, pkroot []u8, msg []u8, outlen int) ![]u8 {
	// setup buffer size to avoid reallocation by initializing enough capacity
	mut basic_size := r.len + pkseed.len + pkroot.len + msg.len
	size := if c.is_shake_family() { basic_size } else { basic_size + r.len + pkseed.len }
	mut data := []u8{cap: size}

	// Is this context was SHAKE-based family?
	//
	// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = SHAKE256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀, 8𝑚)
	if c.is_shake_family() {
		data << r
		data << pkseed
		data << pkroot
		data << msg
		return sha3.shake256(data, outlen)
	}
	// Otherwise, its a SHA2-based PRF
	//
	// For security category 1, use MGF1-SHA-256
	// 		H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-256(𝑅 ∥ PK.seed ∥ SHA-256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)
	// For security category 3 and 5, use MGF1-SHA-512
	// 		H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) = MGF1-SHA-512(𝑅 ∥ PK.seed ∥ SHA-512(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 ), 𝑚)

	// 𝑅 ∥ PK.seed
	mut rpk_data := []u8{cap: r.len + pkseed.len}
	rpk_data << r
	rpk_data << pkseed

	// Based on the security category number, choose the right hash algorithm
	mut h := if c.is_sha2_seccat1() { c.h2 } else { c.h5 }

	// write the data into hash, SHA-256 (or SHA-512) (𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 )
	// dont forget to call `.reset` first
	unsafe { h.reset() }
	h.write(r)!
	h.write(pkseed)!
	h.write(pkroot)!
	h.write(msg)!

	// Gets the digest sum
	digest := h.sum([]u8{})

	// Now data acts as a new seed to mgf1
	data << rpk_data
	data << digest

	// mgf1 calls `h.reset()` internally, so we dont reset the hash here
	// unsafe { h.reset() }
	return mgf1(data, outlen, mut h)!
}

// prf is a pseudorandom function (PRF) that is used to generate the secret values
// in WOTS+ and FORS private keys.
@[direct_array_access]
fn (mut c Context) prf(pkseed []u8, skseed []u8, addr Address, outlen int) ![]u8 {
	// Setup enough buffer to store concatenated data
	mut data := []u8{cap: pkseed.len + skseed.len + 32 + 64 - c.prm.n}

	// SHAKE-based PRF
	//
	// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed ∥ ADRS ∥ SK.seed, 8𝑛)
	// addr.encode(mut c.buffer) == 32
	if c.is_shake_family() {
		addr.encode(mut c.buffer)
		data << pkseed
		data << c.buffer
		data << skseed
		return sha3.shake256(data, outlen)
	}
	// Otherwise, its a SHA2-based PRF
	//
	// For SHA2-based PRF using SHA-256, only differs on n number, depends on the security category
	// of underlying tipe of SLH-DSA parameter set
	// ie, n = 16, n = 24 and n = 32 for security category 1, 3 and 5 respectively
	//
	// PRF(PK.seed, SK.seed, ADRS) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ SK.seed))
	//

	// start by compressing the address
	addr.compress(mut c.buffer)

	// concatenates the bytes into data buffer
	//
	data << pkseed
	data << []u8{len: 64 - c.prm.n}
	data << c.buffer[0..compressed_addr_size]
	data << skseed

	// Gets the digest sum with SHA-256 hash
	unsafe { c.h2.reset() }
	c.h2.write(data)!
	out := c.h2.sum([]u8{})

	result := out[0..outlen].clone()
	unsafe { out.free() }
	return result
}

// tl is a hash function that maps an ℓ𝑛-byte message to an 𝑛-byte message.
@[direct_array_access]
fn (mut c Context) tl(pkseed []u8, addr Address, msgsln [][]u8, outlen int) ![]u8 {
	// flatten the arrays of msg in msgsln
	flatten_msg := arrays.flatten[u8](msgsln)

	// setup buffer data with enough capacity
	data_size := pkseed.len + 32 + flatten_msg.len + 128 - c.prm.n
	mut data := []u8{cap: data_size}

	// Handle for SHAKE-based PRF
	//
	// Tℓ(PK.seed, ADRS, 𝑀ℓ) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀ℓ, 8𝑛)
	if c.is_shake_family() {
		addr.encode(mut c.buffer)
		data << pkseed
		data << c.buffer
		data << flatten_msg // arrays.flatten[u8](msgsln)

		return sha3.shake256(data, outlen)
	}
	// Otherwise its a SHA2-based PRF
	//
	// For SHA2 family with security category 1, its using SHA-256 hash
	// 		Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))
	// where security category 3 and 5 using SHA-512
	// 		Tℓ(PK.seed, ADRS, 𝑀ℓ) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀ℓ))

	// Get correct underlying hash
	mut h := if c.is_sha2_seccat1() { c.h2 } else { c.h5 }
	// setup base number for toByte calculation
	bnum := if c.is_sha2_seccat1() { 64 } else { 128 }

	// Start by compressing the address
	addr.compress(mut c.buffer)

	// Concatenates the bytes into data buffer
	//
	data << pkseed
	data << []u8{len: bnum - c.prm.n}
	data << c.buffer[0..compressed_addr_size]
	data << flatten_msg

	// write the data into hash and gets the digest
	unsafe { h.reset() }
	h.write(data)!
	digest := h.sum([]u8{})

	// return with appropriate outlen size
	return digest[0..outlen].clone()
}

// h is a special case of Tℓ that takes a 2𝑛-byte message as input.
@[direct_array_access]
fn (mut c Context) h(pkseed []u8, addr Address, m2 []u8, outlen int) ![]u8 {
	// setup data buffer with enough capacity to hold all size of data
	mut data := []u8{cap: pkseed.len + 32 + m2.len + 128 - c.prm.n}

	// Handle for SHAKE-based PRF
	//
	// H(PK.seed, ADRS, 𝑀2) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
	if c.is_shake_family() {
		// Serializes address into context buffer
		addr.encode(mut c.buffer)
		// appends the bytes into data buffer and get the shake256 sum
		data << pkseed
		data << c.buffer
		data << m2

		return sha3.shake256(data, outlen)
	}
	// Otherwise, its a SHA2-based PRF
	//
	bnum := if c.is_sha2_seccat1() { 64 } else { 128 }
	// compress the address into first 22-bytes of context buffer
	// Note: you should only take the first of 22-bytes from context buffer
	addr.compress(mut c.buffer)

	// concatenates the bytes into data buffer
	data << pkseed
	// append zeros bytes directly
	data << []u8{len: bnum - c.prm.n}
	data << c.buffer[0..compressed_addr_size] // only take first 22-bytes of context buffer
	data << m2

	// For Security category 1 use SHA-256 PRF
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	//
	// For Security category 3 and 5 use SHA-512 PRF
	// H(PK.seed, ADRS, 𝑀2) = Trunc𝑛(SHA-512(PK.seed ∥ toByte(0, 128 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀2))
	mut h := if c.is_sha2_seccat1() { c.h2 } else { c.h5 }
	unsafe { h.reset() }
	h.write(data)!
	out := h.sum([]u8{})

	digest := out[0..outlen].clone()
	// freeing allocated output resources and return the result
	unsafe { out.free() }

	return digest
}

// f is a hash function that takes an 𝑛-byte message as input and produces an 𝑛-byte output.
@[direct_array_access]
fn (mut c Context) f(pkseed []u8, addr Address, m1 []u8, outlen int) ![]u8 {
	// Allocates data buffer with enough capacities
	mut data := []u8{cap: pkseed.len + 32 + m1.len + 64 - c.prm.n}

	// Handle for SHAKE-based PRF
	//
	// F(PK.seed, ADRS, 𝑀1) = SHAKE256(PK.seed ∥ ADRS ∥ 𝑀1, 8𝑛)
	if c.is_shake_family() {
		addr.encode(mut c.buffer)
		data << pkseed
		data << c.buffer
		data << m1

		return sha3.shake256(data, outlen)
	}
	// Otherwise, use SHA2-based PRF
	//
	// 11.2.1 SLH-DSA Using SHA2 for Security Category 1, (also applied to 3 and 5)
	//
	// 1 : 		F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	// 3 and 5: F(PK.seed, ADRS, 𝑀1) = Trunc𝑛(SHA-256(PK.seed ∥ toByte(0, 64 − 𝑛) ∥ ADRS𝑐 ∥ 𝑀1))
	// NOTE: use context prm.n number directly
	//

	// Compress the address into the first 22-bytes of c.buffer
	addr.compress(mut c.buffer)

	// concatenates bytes data into buffer
	data << pkseed
	data << []u8{len: 64 - c.prm.n}
	data << c.buffer[0..compressed_addr_size]
	data << m1

	// Get the sum, dont forget to call .reset first
	// NOTE: Its all using SHA-256 hash
	unsafe { c.h2.reset() }
	c.h2.write(data)!
	out := c.h2.sum([]u8{})

	result := out[0..outlen].clone()
	// explicitly free the output resource
	unsafe { out.free() }

	return result
}

// Helpers for pseudorandom function
//

// hmac_sha256 creates HMAC bytes with SHA256 hash
@[direct_array_access; inline]
fn hmac_sha256(seed []u8, data []u8) []u8 {
	// fn new(key []u8, data []u8, hash_func fn ([]u8) []u8, blocksize int) []u8
	// NOTE: use block_size instead of size
	return hmac.new(seed, data, sha256.sum256, sha256.block_size)
}

// hmac_sha512 creates new HMAC bytes with SHA512 hash
@[direct_array_access; inline]
fn hmac_sha512(seed []u8, data []u8) []u8 {
	// fn new(key []u8, data []u8, hash_func fn ([]u8) []u8, blocksize int) []u8
	// NOTE: use block_size instead of size
	return hmac.new(seed, data, sha512.sum512, sha512.block_size)
}

// is_shake_family tells if this context was a SHAKE-based family
fn (c &Context) is_shake_family() bool {
	match c.tipe {
		.shake_128f, .shake_128s, .shake_192f, .shake_192s, .shake_256f, .shake_256s {
			return true
		}
		else {
			return false
		}
	}
}

// is_sha2_seccat1 tells if this context was a SHA2-based family with security category 1
fn (c &Context) is_sha2_seccat1() bool {
	match c.tipe {
		.sha2_128f, .sha2_128s { return true }
		else { return false }
	}
}

// ParamSet describes SLH-DSA Parameter set
//
@[noinit]
struct ParamSet {
pub:
	// The name indicates SLH-DSA its belong to
	name string
	// the length in bits of the security parameter 𝑛, Its parameters for WOTS+
	n int
	// XMSS and the SLH-DSA hypertree (ℎ and 𝑑)
	h int
	d int
	//  A Merkle tree of height ℎ′
	hp int

	// FORS parameters (𝑘 and 𝑎)
	a int
	k int
	// The parameter 𝑙𝑔𝑤 indicates the number of bits that are encoded by each
	// hash chain that is used. 𝑙𝑔𝑤 is 4 for all parameter sets in this standard
	// Its parameters for WOTS+
	lgw int = 4
	// SLH-DSA uses one additional parameter 𝑚, which is the length in bytes of the message digest.
	m int
	// security category
	sc int
	// public key size
	pksize int
	// signature size
	sigsize int
}

// Table 2. SLH-DSA parameter sets
//
// name					𝑛 	ℎ  𝑑 ℎ′ 𝑎 𝑘 𝑙𝑔𝑤 𝑚 securitycategory pkbytes sigbytes
// SLH-DSA-SHA2-128s	16 63 7 9 12 14 4 30 1 32 7856
// SLH-DSA-SHAKE-128s 	16 63 7 9 12 14 4 30 1 32 7856
// ----------------------------------------------------
// SLH-DSA-SHA2-128f	16 66 22 3 6 33 4 34 1 32 17088
// SLH-DSA-SHAKE-128f 	16 66 22 3 6 33 4 34 1 32 17088
// ----------------------------------------------------
// SLH-DSA-SHA2-192s	24 63 7 9 14 17 4 39 3 48 16224
// SLH-DSA-SHAKE-192s 	24 63 7 9 14 17 4 39 3 48 16224
// ----------------------------------------------------
// SLH-DSA-SHA2-192f	24 66 22 3 8 33 4 42 3 48 35664
// SLH-DSA-SHAKE-192f 	24 66 22 3 8 33 4 42 3 48 35664
// ----------------------------------------------------
// SLH-DSA-SHA2-256s	32 64 8 8 14 22 4 47 5 64 29792
// SLH-DSA-SHAKE-256s 	32 64 8 8 14 22 4 47 5 64 29792
// ----------------------------------------------------
// SLH-DSA-SHA2-256f	32 68 17 4 9 35 4 49 5 64 49856
// SLH-DSA-SHAKE-256f 	32 68 17 4 9 35 4 49 5 64 49856
//
// new_param creates SLH-DSA parameter set from SLHType k
fn new_param(k SLHType) ParamSet {
	match k {
		// SHA2-based family			name     		  𝑛   ℎ   𝑑  ℎp  𝑎  𝑘  𝑙𝑔𝑤 𝑚  sc pksize sigsize
		.sha2_128s { return ParamSet{'SLH-DSA-SHA2-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856} }
		.sha2_128f { return ParamSet{'SLH-DSA-SHA2-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088} }
		.sha2_192s { return ParamSet{'SLH-DSA-SHA2-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224} }
		.sha2_192f { return ParamSet{'SLH-DSA-SHA2-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664} }
		.sha2_256s { return ParamSet{'SLH-DSA-SHA2-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792} }
		.sha2_256f { return ParamSet{'SLH-DSA-SHA2-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856} }
		// SHAKE-based family
		.shake_128s { return ParamSet{'SLH-DSA-SHAKE-128s', 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856} }
		.shake_128f { return ParamSet{'SLH-DSA-SHAKE-128f', 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088} }
		.shake_192s { return ParamSet{'SLH-DSA-SHAKE-192s', 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224} }
		.shake_192f { return ParamSet{'SLH-DSA-SHAKE-192f', 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664} }
		.shake_256s { return ParamSet{'SLH-DSA-SHAKE-256s', 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792} }
		.shake_256f { return ParamSet{'SLH-DSA-SHAKE-256f', 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856} }
	}
}

// SLHType is an enumeration type of the SLH-DSA key.
// See Table 2. SLH-DSA parameter sets of the Chapter 11. Parameter Sets
//
// Each sets name indicates:
// 	- the hash function family (SHA2 or SHAKE) that is used to instantiate the hash functions.
//	- the length in bits of the security parameter, in the 128, 192, and 256 respectives number.
//	- the mnemonic name indicates parameter to create relatively small signatures (`s`)
//	  or to have relatively fast signature generation (`f`).
pub enum SLHType {
	// SHA2-based family
	sha2_128s
	sha2_128f
	sha2_192s
	sha2_192f
	sha2_256s
	sha2_256f
	// SHAKE-based family
	shake_128s
	shake_128f
	shake_192s
	shake_192f
	shake_256s
	shake_256f
}

// new_slh_type make a SLHType from name string
pub fn new_slh_type(name string) !SLHType {
	match name {
		// SHA2-based family
		'SLH-DSA-SHA2-128s' { return .sha2_128s }
		'SLH-DSA-SHA2-128f' { return .sha2_128f }
		'SLH-DSA-SHA2-192s' { return .sha2_192s }
		'SLH-DSA-SHA2-192f' { return .sha2_192f }
		'SLH-DSA-SHA2-256s' { return .sha2_256s }
		'SLH-DSA-SHA2-256f' { return .sha2_256f }
		// SHAKE-based family
		'SLH-DSA-SHAKE-128s' { return .shake_128s }
		'SLH-DSA-SHAKE-128f' { return .shake_128f }
		'SLH-DSA-SHAKE-192s' { return .shake_192s }
		'SLH-DSA-SHAKE-192f' { return .shake_192f }
		'SLH-DSA-SHAKE-256s' { return .shake_256s }
		'SLH-DSA-SHAKE-256f' { return .shake_256f }
		else { return error('Invalid SLH-DSA name string ${name}') }
	}
}

// str returns string representation of this SLHType k
fn (t SLHType) str() string {
	match t {
		// SHA2-based family
		.sha2_128s { return 'sha2_128s' }
		.sha2_128f { return 'sha2_128f' }
		.sha2_192s { return 'sha2_192s' }
		.sha2_192f { return 'sha2_192f' }
		.sha2_256s { return 'sha2_256s' }
		.sha2_256f { return 'sha2_256f' }
		// SHAKE-based family
		.shake_128s { return 'shake_128s' }
		.shake_128f { return 'shake_128f' }
		.shake_192s { return 'shake_192s' }
		.shake_192f { return 'shake_192f' }
		.shake_256s { return 'shake_256s' }
		.shake_256f { return 'shake_256f' }
	}
}

// When 𝑙𝑔𝑤 = 4, 𝑤 = 16, 𝑙𝑒𝑛1 = 2𝑛, 𝑙𝑒𝑛2 = 3, and 𝑙𝑒𝑛 = 2𝑛 + 3.
// See FIPS 205 page 17
// w := uint32(1 << lgw)
const w = 16

// TODO: should be inlined ?
fn (c &Context) wots_len() int {
	return 2 * c.prm.n + 3
}

fn (c &Context) wots_len1() int {
	return 2 * c.prm.n
}

fn (c &Context) wots_len2() int {
	return 3
}
