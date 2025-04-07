module pslhdsa

import crypto.sha256
import crypto.sha512
import crypto.sha3 // for shake
import crypto.hmac

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
fn (ctx Context) is_shake() bool {
	return ctx.prm.id.is_shake()
}

// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛) is a pseudorandom function
// (PRF) that generates the randomizer (𝑅) for the randomized hashing of the message to be
// signed.
fn (ctx Context) prf_msg(sk_prf []u8, opt_rand []u8, msg []u8) []u8 {
	if ctx.is_shake() {
		return shake256_prf_msg(sk_prf, opt_rand, msg, ctx.prm.n)
	}
	// sha2 family
	if ctx.prm.sc == 1 {
		return sha256_prf_msg(sk_prf, opt_rand, msg, ctx.prm.n)
	}
	// else use sha512
	return sha512_prf_msg(sk_prf, opt_rand, msg, ctx.prm.n)
}

// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑚) is used to generate the
// digest of the message to be signed.
fn (ctx Context) h_msg(r []u8, pk_seed []u8, pk_root []u8, msg []u8, m int) []u8 {
	if ctx.is_shake() {
		return shake256_h_msg(r, pk_seed, pk_root, msg, ctx.prm.m)
	}
	if ctx.prm.sc == 1 {
		return sha256_h_msg(r, pk_seed, pk_root, msg, ctx.prm.m)
	}
	// sha512
	return sha512_h_msg(r, pk_seed, pk_root, msg, ctx.prm.m)
}

// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛) is a PRF that is used to
// generate the secret values in WOTS+ and FORS private keys.
fn (ctx Context) prf(pk_seed []u8, sk_seed []u8, addr Address) []u8 {
	if ctx.is_shake() {
		return shake256_prf(pk_seed, sk_seed, addr, ctx.prm.n)
	}
	if ctx.prm.sc == 1 {
		return sha256_prf(pk_seed, sk_seed, addr, ctx.prm.n)
	}
	return sha512_prf(pk_seed, sk_seed, addr, ctx.prm.n)
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
fn (ctx Context) tlen(pk_seed []u8, addr Address, ml []u8) []u8 {
	if ctx.is_shake() {
		return shake256_tlen(pk_seed, addr, ml, ctx.prm.n)
	}
	if ctx.prm.sc == 1 {
		return sha256_tlen(pk_seed, addr, ml, ctx.prm.n)
	}
	return sha512_tlen(pk_seed, addr, ml, ctx.prm.n)
}

// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛) is a special case of Tℓ that takes a
// 2𝑛-byte message as input.
fn (ctx Context) h(pk_seed []u8, addr Address, m2 []u8) []u8 {
	if ctx.is_shake() {
		return shake256_h(pk_seed, addr, m2, ctx.prm.n)
	}
	if ctx.prm.sc == 1 {
		return sha256_h(pk_seed, addr, m2, ctx.prm.n)
	}
	return sha512_h(pk_seed, addr, m2, ctx.prm.n)
}

// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛) is a hash function that takes an 𝑛-byte
// message as input and produces an 𝑛-byte output.
fn (ctx Context) f(pk_seed []u8, addr Address, m1 []u8) []u8 {
	if ctx.is_shake() {
		return shake256_f(pk_seed, addr, m1, ctx.prm.m)
	}
	if ctx.prm.sc == 1 {
		return sha256_f(pk_seed, addr, m1, ctx.prm.m)
	}
	return sha512_f(pk_seed, addr, m1, ctx.prm.m)
}

// The enumeration type of the SLH-DSA key.
// See Table 2. SLH-DSA parameter sets of the Chapter 11. Parameter Sets<br>
// Each sets name indicates:
//
// 	- the hash function family (SHA2 or SHAKE) that is used to instantiate the hash functions.
//	- the length in bits of the security parameter, in the 128, 192, and 256 respectives number.
//	- the mnemonic name indicates parameter to create relatively small signatures (`s`)
//	  or to have relatively fast signature generation (`f`).
pub enum Kind {
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

@[inline]
fn (k Kind) is_shake() bool {
	match k {
		.shake_128s, .shake_128f, .shake_192s, .shake_192f, .shake_256s, .shake_256f { return true }
		else { return false }
	}
}

// nsize returns the size of underlying n parameter from current type.
@[inline]
fn (n Kind) nsize() int {
	match n {
		.sha2_128s, .sha2_128f, .shake_128s, .shake_128f { return 16 }
		.sha2_192s, .sha2_192f, .shake_192s, .shake_192f { return 24 }
		.sha2_256s, .sha2_256f, .shake_256s, .shake_256f { return 32 }
	}
}

fn (n Kind) str() string {
	match n {
		// vfmt off
		// SHA2-based family
		.sha2_128s { return "sha2_128s" }
		.sha2_128f { return "sha2_128f" }
		.sha2_192s { return "sha2_192s" }
		.sha2_192f { return "sha2_192f" }
		.sha2_256s { return "sha2_256s" }
		.sha2_256f { return "sha2_256f" }
		// SHAKE-based family
		.shake_128s { return "shake_128s" }
		.shake_128f { return "shake_128f" }
		.shake_192s { return "shake_192s" }
		.shake_192f { return "shake_192f" }
		.shake_256s { return "shake_256s" }
		.shake_256f { return "shake_256f" }
		// vfmt on
	}
}

// Chapter 11. Parameters Set
struct ParamSet {
	// Algorithm name
	id  Kind
	n   int
	h   int
	d   int
	hp  int
	a   int
	k   int
	lgw int = 4
	m   int
	sc  int
	pkb int
	sig int
}

// When 𝑙𝑔𝑤 = 4, 𝑤 = 16, 𝑙𝑒𝑛1 = 2𝑛, 𝑙𝑒𝑛2 = 3, and 𝑙𝑒𝑛 = 2𝑛 + 3.
// See FIPS 205 p17
const w = 16
const len2 = 3

@[inline]
fn (p ParamSet) len1() int {
	return 2 * p.n
}

@[inline]
fn (p ParamSet) wots_len() int {
	return 2 * p.n + 3
}

// Table 2. SLH-DSA parameter sets
const paramset = {
	// 						     id 	𝑛 	ℎ 	𝑑 	ℎ′  𝑎 	𝑘 	𝑙𝑔𝑤 𝑚  sc pkb  sig
	'sha2_128s':  ParamSet{.sha2_128s, 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'sha2_128f':  ParamSet{.sha2_128f, 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'sha2_192s':  ParamSet{.sha2_192s, 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'sha2_192f':  ParamSet{.sha2_192f, 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'sha2_256s':  ParamSet{.sha2_256s, 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'sha2_256f':  ParamSet{.sha2_256f, 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
	// SHAKE family
	'shake_128s': ParamSet{.shake_128s, 16, 63, 7, 9, 12, 14, 4, 30, 1, 32, 7856}
	'shake_128f': ParamSet{.shake_128f, 16, 66, 22, 3, 6, 33, 4, 34, 1, 32, 17088}
	'shake_192s': ParamSet{.shake_192s, 24, 63, 7, 9, 14, 17, 4, 39, 3, 48, 16224}
	'shake_192f': ParamSet{.shake_192f, 24, 66, 22, 3, 8, 33, 4, 42, 3, 48, 35664}
	'shake_256s': ParamSet{.shake_256s, 32, 64, 8, 8, 14, 22, 4, 47, 5, 64, 29792}
	'shake_256f': ParamSet{.shake_256f, 32, 68, 17, 4, 9, 35, 4, 49, 5, 64, 49856}
}

fn ParamSet.from_kind(k Kind) ParamSet {
	return paramset[k.str()]
}

// SHAKE
//
// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛) is a pseudorandom function
// (PRF) that generates the randomizer (𝑅) for the randomized hashing of the message to be
// signed.
@[inline]
fn shake256_prf_msg(sk_prf []u8, opt_rand []u8, msg []u8, n int) []u8 {
	mut data := []u8{}
	data << sk_prf
	data << opt_rand
	data << m

	out := sha3.shake256(data, n)
	return out
}

// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑚) is used to generate the
// digest of the message to be signed.
@[inline]
fn shake256_h_msg(r []u8, pk_seed []u8, pk_root []u8, msg []u8, m int) []u8 {
	mut data := []u8{}
	data << r
	data << pk_seed
	data << pk_root
	data << msg

	return sha3.shake256(data, m)
}

// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛) is a PRF that is used to
// generate the secret values in WOTS+ and FORS private keys.
@[inline]
fn shake256_prf(pk_seed []u8, sk_seed []u8, addr Address, n int) []u8 {
	mut data := []u8{}
	data << pk_seed
	data << sk_seed
	data << addr.full_to_bytes()

	return sha3.shake256(data, n)
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
@[inline]
fn shake256_tlen(pk_seed []u8, addr Address, ml []u8, n int) []u8 {
	mut data := []u8{}
	data << pk_seed
	data << addr.full_to_bytes()
	data << ml

	return sha3.shake256(data, n)
}

// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛) is a special case of Tℓ that takes a
// 2𝑛-byte message as input.
fn shake256_h(pk_seed []u8, addr Address, m2 []u8, n int) []u8 {
	mut data := []u8{}
	data << pk_seed
	data << addr.full_to_bytes()
	data << m2

	return sha3.shake256(data, n)
}

// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛) is a hash function that takes an 𝑛-byte
// message as input and produces an 𝑛-byte output.
fn shake256_f(pk_seed []u8, addr Address, m1 []u8, n int) []u8 {
	mut data := []u8{}
	data << pk_seed
	data << addr.full_to_bytes()
	data << m1

	return sha3.shake256(data, n)
}

// SHA256
//
// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛) is a pseudorandom function
// (PRF) that generates the randomizer (𝑅) for the randomized hashing of the message to be
// signed.
@[inline]
fn sha256_prf_msg(sk_prf []u8, opt_rand []u8, msg []u8, n int) []u8 {
	// return trunc(hmac_digest(sk_prf, opt_rand + msg, "sha256"), n)
	mut data := opt_rand.clone()
	data << msg

	out := hmac.new(sk_prf, data, sha256.sum256, sha256.block_size)
	// trunc
	result := out[..n]
	return result
}

// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑚) is used to generate the
// digest of the message to be signed.
@[inline]
fn sha256_h_msg(r []u8, pk_seed []u8, pk_root []u8, msg []u8, m int) []u8 {
	mut data := r.clone()
	data << pk_seed

	mut extended := data.clone()
	extended << pk_root
	extended << msg

	digest := sha256.sum256(extended)
	return mgf1_sha256(data, digest, m)
}

// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛) is a PRF that is used to
// generate the secret values in WOTS+ and FORS private keys.
@[inline]
fn sha256_prf(pk_seed []u8, sk_seed []u8, addr Address, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << sk_seed

	out := sha256.sum256(data)
	result := out[..n]

	return result
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
@[inline]
fn sha256_tlen(pk_seed []u8, addr Address, ml []u8, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << ml

	out := sha256.sum256(data)
	result := out[..n]

	return result
}

// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛) is a special case of Tℓ that takes a
// 2𝑛-byte message as input.
@[inline]
fn sha256_h(pk_seed []u8, addr Address, m2 []u8, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << m2

	out := sha256.sum256(data)
	result := out[..n]

	return result
}

// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛) is a hash function that takes an 𝑛-byte
// message as input and produces an 𝑛-byte output.
@[inline]
fn sha256_f(pk_seed []u8, addr Address, m1 []u8, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << m1

	out := sha256.sum256(data)
	result := out[..n]

	return result
}

// SHA512
//
// PRF𝑚𝑠𝑔(SK.prf, 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑛) is a pseudorandom function
// (PRF) that generates the randomizer (𝑅) for the randomized hashing of the message to be
// signed.
@[inline]
fn sha512_prf_msg(sk_prf []u8, opt_rand []u8, msg []u8, n int) []u8 {
	// return trunc(hmac_digest(sk_prf, opt_rand + msg, "sha256"), n)
	mut data := opt_rand.clone()
	data << msg

	out := hmac.new(sk_prf, data, sha512.sum512, sha512.block_size)
	// trunc
	result := out[..n]
	return result
}

// H𝑚𝑠𝑔(𝑅, PK.seed, PK.root, 𝑀 ) (𝔹𝑛 × 𝔹𝑛 × 𝔹𝑛 × 𝔹∗ → 𝔹𝑚) is used to generate the
// digest of the message to be signed.
@[inline]
fn sha512_h_msg(r []u8, pk_seed []u8, pk_root []u8, msg []u8, m int) []u8 {
	mut data := r.clone()
	data << pk_seed

	mut extended := data.clone()
	extended << pk_root
	extended << msg

	digest := sha512.sum512(extended)
	return mgf1_sha512(data, digest, m)
}

// PRF(PK.seed, SK.seed, ADRS) (𝔹𝑛 × 𝔹𝑛 × 𝔹32 → 𝔹𝑛) is a PRF that is used to
// generate the secret values in WOTS+ and FORS private keys.
@[inline]
fn sha512_prf(pk_seed []u8, sk_seed []u8, addr Address, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << sk_seed

	out := sha512.sum512(data)
	result := out[..n]

	return result
}

// Tℓ(PK.seed, ADRS, 𝑀ℓ) (𝔹𝑛 × 𝔹32 × 𝔹ℓ𝑛 → 𝔹𝑛) is a hash function that maps an
// ℓ𝑛-byte message to an 𝑛-byte message.
@[inline]
fn sha512_tlen(pk_seed []u8, addr Address, ml []u8, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << ml

	out := sha512.sum512(data)
	result := out[..n]

	return result
}

// H(PK.seed, ADRS, 𝑀2) (𝔹𝑛 × 𝔹32 × 𝔹2𝑛 → 𝔹𝑛) is a special case of Tℓ that takes a
// 2𝑛-byte message as input.
@[inline]
fn sha512_h(pk_seed []u8, addr Address, m2 []u8, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << m2

	out := sha512.sum512(data)
	result := out[..n]

	return result
}

// F(PK.seed, ADRS, 𝑀1) (𝔹𝑛 × 𝔹32 × 𝔹𝑛 → 𝔹𝑛) is a hash function that takes an 𝑛-byte
// message as input and produces an 𝑛-byte output.
@[inline]
fn sha512_f(pk_seed []u8, addr Address, m1 []u8, n int) []u8 {
	compressed := addr.compress()
	mut data := []u8{}
	data << pk_seed
	data << []u8{len: 64 - n}
	data << compressed
	data << m1

	out := sha512.sum512(data)
	result := out[..n]

	return result
}
