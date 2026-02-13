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

// copied here from utils, its not publicly availables
fn name_to_hfunc(name string) !crypto.Hash {
	match name {
		'SHAKE-128' {
			return crypto.Hash.shake128
		}
		'SHAKE-256' {
			return crypto.Hash.shake256
		} // map to 64-size
		'SHA2-224' {
			return crypto.Hash.sha224
		} // 224/8-bytes
		'SHA2-256' {
			return crypto.Hash.sha256
		} // 256/8-bytes
		'SHA2-384' {
			return crypto.Hash.sha384
		} // 384/8-bytes
		'SHA2-512' {
			return crypto.Hash.sha512
		} // 512/8-bytes
		'SHA2-512/224' {
			return crypto.Hash.sha512_224
		} // 224/8-bytes
		'SHA2-512/256' {
			return crypto.Hash.sha512_256
		} // 256/8-bytes
		'SHA3-224' {
			return crypto.Hash.sha3_224
		} // 224/8-bytes
		'SHA3-256' {
			return crypto.Hash.sha3_256
		} // 256/8-bytes
		'SHA3-384' {
			return crypto.Hash.sha3_384
		} // 384/8-bytes
		'SHA3-512' {
			return crypto.Hash.sha3_512
		} // 512/8-bytes
		else {
			return error('hash algorithm ${name} not supported')
		}
	}
}

// Only test external interface
fn test_slhdsa_sigverify_fips205_external_test_vectors() {
	// read the sigverif_fips205.json file
	// The test material was taken from SLH-DSA sigVer-FIPS205 test vectors for signature verification
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json
	json_str := os.read_file('./kat/sigverif_fips205.json')!
	// parse the json string into a SigVerifTest struct
	sigver_test := json2.decode[SigVerifTest](json_str)!
	// Test for every test group
	for tg in sigver_test.testgroups {
		ctx := pslhdsa.new_context_from_name(tg.parameterset)!
		// get message encoding mode
		mode := if tg.prehash == 'pure' {
			pslhdsa.MsgEncoding.pure
		} else {
			if tg.prehash == 'prehash' {
				pslhdsa.MsgEncoding.pre
			} else {
				pslhdsa.MsgEncoding.noencode
			}
		}
		// build an options for signing (verifying)
		mut opt := pslhdsa.Options{
			// This is non-deterministic test
			// set testing to true, its need for testing
			testing:      true
			msg_encoding: mode
		}
		for t in tg.tests {
			// We only test for signature verification step, so
			// we ommit signature generation step
			pkb := hex.decode(t.pk)!
			msg := hex.decode(t.message)!
			cx := hex.decode(t.context)!
			addrnd := hex.decode(t.additionalrandomness)!
			signature := hex.decode(t.signature)!

			mut pk := pslhdsa.new_pubkey(pkb, slh_type: ctx.tipe)!
			// get hash function when its in pre-hashed mode
			if opt.msg_encoding == pslhdsa.MsgEncoding.pre {
				opt.hfunc = name_to_hfunc(t.hashalg)!
			}
			// set the randomness value
			opt.entropy = addrnd

			// Some test cases has invalid signature size, and return error
			// when be parsed into internal SLHSignature opaque struct
			verified := pk.verify(msg, signature, cx, opt) or { false }
			assert verified == t.testpassed
			// explicitly release the resource
			unsafe {
				pkb.free()
				msg.free()
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
