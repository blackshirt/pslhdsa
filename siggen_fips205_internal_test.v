// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Signature internal generation test vectors
// NOTE: Its a big test, so be quiet
module pslhdsa

import os
import encoding.hex
import json

fn test_slhdsa_siggen_fips205_internal_test_vectors() {
	// read the siggen_fips205_internal.json file
	// The test material was taken from SLH-DSA sigGen-FIPS205 test vectors for signature generation
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json
	json_str := os.read_file('./siggen_fips205_internal.json')!
	// parse the json string into a SigGenTest struct
	// BUG: This json.decode fails with `-prod` flag
	siggen_test := json.decode(SigGenTest, json_str)!
	for tg in siggen_test.testgroups {
		ctx := new_context_from_name(tg.parameterset)!
		// we only test internal interface here
		deterministic := tg.deterministic // true or false
		for t in tg.tests {
			// we skip signature verification path
			skb := hex.decode(t.sk)!
			msg := hex.decode(t.message)!
			signature := hex.decode(t.signature)!

			sk := slh_keygen_from_bytes(ctx, skb)!

			// get optional randomness, if deterministic, use SK.pkseed (PK.seed)
			// otherwise use decoded additionalrandomness bytes
			opt_rand := if deterministic { sk.pkseed } else { hex.decode(t.additionalrandomness)! }

			// slh_sign_internal(msg []u8, sk &SigningKey, addrnd []u8) !&SLHSignature
			slh_sig := slh_sign_internal(msg, sk, opt_rand)!
			sigout := slh_sig.bytes()
			assert sigout == signature

			// explicitly  releases allocated buffers
			unsafe {
				skb.free()
				msg.free()
				sigout.free()
				signature.free()
				opt_rand.free()
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
	message              string
	context              string
	additionalrandomness string
	hashalg              string
	signature            string
}
