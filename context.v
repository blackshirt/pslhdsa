module pslhdsa

import crypto.sha256
import crypto.sha512
import crypto.sha3 // for shake
import crypto.hmac

enum HashSuite {
	sha256
	sha512
	shake
}

struct Context {
	hs  HashSuite = .sha256
	prm ParamSet
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
fn shake256_tl(pk_seed []u8, addr Address, ml []u8, n int) []u8 {
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
fn sha256_tl(pk_seed []u8, addr Address, ml []u8, n int) []u8 {
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
fn sha512_tl(pk_seed []u8, addr Address, ml []u8, n int) []u8 {
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
