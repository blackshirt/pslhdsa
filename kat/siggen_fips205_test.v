// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Signature generation test vectors
// NOTE: Its a big test, so be quiet
import pslhdsa
import os
import crypto
import encoding.hex
import x.json2

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

// Test for SLH-DSA external signature generation API
// For internal test, its resides in siggen_fips205_internal_test.v file of the main module.
fn test_slhdsa_siggen_fips205_test_vectors() {
	// read the siggen_fips205.json file (the mini version)
	// The test material was taken from SLH-DSA sigGen-FIPS205 test vectors for signature generation
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json
	json_str := os.read_file('./kat/siggen_fips205_mini.json')!
	// parse the json string into a SigGenTest struct
	siggen_test := json2.decode[SigGenTest](json_str)!
	// Test for every test group
	for tg in siggen_cases {
		ctx := new_context_from_name(tg.parameterset)!
		// get message encoding mode
		mode := if tg.prehash == 'pure' {
			MsgEncoding.pure
		} else {
			if tg.prehash == 'prehash' { MsgEncoding.pre } else { MsgEncoding.noencode }
		}
		mut opt := Options{
			deterministic: tg.deterministic
			msg_encoding:  mode
		}
		for t in tg.tests {
			skb := hex.decode(t.sk)!
			pkb := hex.decode(t.pk)!
			msg := hex.decode(t.message)!
			cx := hex.decode(t.context)!
			addrnd := hex.decode(t.additionalrandomness)!
			sig := hex.decode(t.signature)!

			//
			sk := slh_keygen_from_bytes(ctx, skb)!
			pk := new_pubkey(ctx, pkb)!
			assert sk.pubkey().bytes() == pkb
			assert pk.bytes() == pkb

			// get hash function when its pre-hashed mode
			if opt.msg_encoding == .pre {
				hfn, _ := name_to_hfunc(t.hashalg)!
				opt.hfunc = hfn
			}
			opt.testing = true
			// Get the randomness value
			opt_rnd := if opt.deterministic {
				pk.seed
			} else {
				addrnd
			}
			opt.entropy = opt_rnd

			// SK.sign(msg []u8, cx []u8, opt Options) API
			signature := sk.sign(msg, cx, opt)!
			assert signature == sig

			// verification path
			// verify(msg []u8, sig []u8, cx []u8, opt Options)
			valid := pk.verify(msg, signature, cx, opt)!
			assert valid

			// explicitly release resources
			unsafe {
				pkb.free()
				skb.free()
				msg.free()
				cx.free()
				addrnd.free()
				signature.free()
				sig.free()
			}
		}
	}
}

struct SigGenTest {
	vsid       int
	algorithm  string
	mode       string
	revision   string
	issample   bool
	testgroups []SiggenGroupItem
}

struct SiggenGroupItem {
	tgid               int
	testtype           string
	parameterset       string
	deterministic      bool
	signatureinterface string
	prehash            string
	tests              []SiggenCaseItem
}

struct SiggenCaseItem {
	tcid                 int
	deferred             bool
	sk                   string
	pk                   string
	additionalrandomness string
	message              string
	context              string
	hashalg              string
	signature            string
}
