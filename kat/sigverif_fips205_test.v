// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Signature verification test vectors
// NOTE: Its a big test, so be quiet
import pslhdsa
import os
import crypto
import encoding.hex
import x.json2

// Availables hashAlg on the test vectors
// SHAKE
// SHAKE-128
// SHAKE-256
//
// SHA2
// SHA2-224
// SHA2-256
// SHA2-384
// SHA2-512
// SHA2-512/224
// SHA2-512/256
//
// SHA3
// SHA3-224
// SHA3-256
// SHA3-384
// SHA3-512

fn name_to_hfunc(name string) !(crypto.Hash, int) {
	match name {
		'SHAKE-128' {
			return crypto.Hash.md4, 32
		} // not availables on crypto.Hash enum, map to md4
		'SHAKE-256' {
			return crypto.Hash.md5, 54
		} // map to 64-size
		'SHA2-224' {
			return crypto.Hash.sha224, 28
		} // 224/8-bytes
		'SHA2-256' {
			return crypto.Hash.sha256, 32
		} // 256/8-bytes
		'SHA2-384' {
			return crypto.Hash.sha384, 48
		} // 384/8-bytes
		'SHA2-512' {
			return crypto.Hash.sha512, 64
		} // 512/8-bytes
		'SHA2-512/224' {
			return crypto.Hash.sha512_224, 28
		} // 224/8-bytes
		'SHA2-512/256' {
			return crypto.Hash.sha512_256, 32
		} // 256/8-bytes
		'SHA3-224' {
			return crypto.Hash.sha3_224, 28
		} // 224/8-bytes
		'SHA3-256' {
			return crypto.Hash.sha3_256, 32
		} // 256/8-bytes
		'SHA3-384' {
			return crypto.Hash.sha3_384, 48
		} // 384/8-bytes
		'SHA3-512' {
			return crypto.Hash.sha3_512, 64
		} // 512/8-bytes
		else {
			return error('hash algorithm ${name} not supported')
		}
	}
}

const supported_prehash_algo = [crypto.Hash.sha256, .sha512, .md4, .md5]

// Only test external interface
fn test_slhdsa_sigverify_fips205_external_test_vectors() {
	// read the sigverif_fips205.json file
	// The test material was taken from SLH-DSA sigVer-FIPS205 test vectors for signature verification
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json
	json_str := os.read_file('./kat/sigverif_fips205_kat.json')!
	// parse the json string into a SigVerifTest struct
	sigver_test := json2.decode[SigVerifTest](json_str)!
	// Test for every test group
	for tg in sigver_test.testgroups {
		ctx := pslhdsa.new_context_from_name(tg.parameterset)!
		mode := tg.prehash // "pure", "prehash" or "none" (for internal interface)
		mut opt := pslhdsa.Options{}
		for t in tg.tests {
			// only test pure prehash message encoding currently
			// skip for prehash encoding
			if mode != 'pure' {
				continue
			}
			// We only test for signature verification step, so
			// we ommit signature generation step
			pkb := hex.decode(t.pk)!
			message := hex.decode(t.message)!
			cx := hex.decode(t.context)!
			addrnd := hex.decode(t.additionalrandomness)!
			signature := hex.decode(t.signature)!
			// set testing options and related entropy for testing
			opt.testing = true
			opt.entropy = addrnd

			pk := pslhdsa.new_pubkey(ctx, pkb)!

			// Some test cases has invalid signature size, and return error
			// when be parsed into internal SLHSignature opaque struct
			verified := pk.verify(message, signature, cx, opt) or { false }
			assert verified == t.testpassed
			// explicitly release the resource
			unsafe {
				pkb.free()
				message.free()
				cx.free()
				addrnd.free()
				signature.free()
			}
		}
	}
}

// Test for signature verification
struct SigVerifTest {
	vsid       int
	algorithm  string
	mode       string
	revision   string
	issample   bool
	testgroups []SigVerifGroupItem
}

struct SigVerifGroupItem {
	tgid               int
	testtype           string
	parameterset       string
	signatureinterface string
	prehash            string
	tests              []SigVerifCaseItem
}

struct SigVerifCaseItem {
	tcid                 int
	testpassed           bool
	deferred             bool
	sk                   string
	pk                   string
	additionalrandomness string
	message              string
	context              string
	hashalg              string
	signature            string
	reason               string
}
