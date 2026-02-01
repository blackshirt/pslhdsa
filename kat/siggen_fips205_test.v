// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Signature generation test vectors
// NOTE: Its a big test, so be quiet
import pslhdsa
import os
import encoding.hex
import x.json2

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
	for tg in siggen_test.testgroups {
		ctx := pslhdsa.new_context_from_name(tg.parameterset)!
		// get deterministic flag		
		deterministic := tg.deterministic // true or false
		mode := tg.prehash // "pure" or "prehash", "none"
		mut opt := pslhdsa.Options{
			deterministic: deterministic
		}
		for t in tg.tests {
			// we dont support prehash now
			if mode != 'pure' {
				continue
			}
			// set message encoding to prehash if mode == prehash
			// if mode == 'pre' { opt.msg_encoding = .pre }
			opt.testing = !deterministic

			// We only test for signature generation path
			skb := hex.decode(t.sk)!
			addrnd := hex.decode(t.additionalrandomness)!
			message := hex.decode(t.message)!
			cx := hex.decode(t.context)!
			signature := hex.decode(t.signature)!

			// generate signing key
			sk := pslhdsa.slh_keygen_from_bytes(ctx, skb)!

			// get optional randomness
			pkseed := skb[2 * ctx.prm.n..3 * ctx.prm.n]
			opt_rand := if deterministic { pkseed } else { addrnd }
			opt.entropy = opt_rand

			// sign(msg []u8, cx []u8, opt Options) ![]u8
			sigout := sk.sign(message, cx, opt)!
			assert sigout == signature
			// explicitly  releases allocated buffers
			unsafe {
				skb.free()
				message.free()
				cx.free()
				signature.free()
				pkseed.free()
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
