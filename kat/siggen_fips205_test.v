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

fn test_slhdsa_siggen_fips205_test_vectors() {
	// read the siggen_fips205.json file
	// The test material was taken from SLH-DSA sigGen-FIPS205 test vectors for signature generation
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json
	json_str := os.read_file('./kat/siggen_fips205.json')!
	// parse the json string into a SigGenTest struct
	siggen_test := json2.decode[SigGenTest](json_str)!
	// Test for every test group
	for tg in siggen_test.testgroups {
		ctx := pslhdsa.new_context_from_name(tg.parameterset)!
		mode := tg.signatureinterface // 'internal' or 'external'
		deterministic := tg.deterministic // true or false
		prehash := tg.prehash // "pure" or "prehash"
		for t in tg.tests {
			// we dont support prehash now
			if prehash == 'prehash' {
				continue
			}
			skb := hex.decode(t.sk)!
			pkb := hex.decode(t.pk)!
			message := hex.decode(t.message)!
			cx := hex.decode(t.context)!
			signature := hex.decode(t.signature)!

			sk := pslhdsa.new_signing_key(ctx, skb)!
			pk := pslhdsa.new_pubkey(ctx, pkb)!
			assert sk.pubkey().equal(pk)

			sigout := pslhdsa.slh_sign(message, cx, sk, deterministic: deterministic)!
			assert sigout.len == signature.len
			assert sigout == signature
			unsafe {
				skb.free()
				pkb.free()
				message.free()
				cx.free()
				sigout.free()
				signature.free()
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
	tcid      int
	deferred  bool
	sk        string
	pk        string
	message   string
	context   string
	hashalg   string
	signature string
}
