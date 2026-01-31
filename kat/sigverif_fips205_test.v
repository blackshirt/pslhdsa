// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Signature verification test vectors
// NOTE: Its a big test, so be quiet
import pslhdsa
import os
import encoding.hex
import x.json2

fn test_slhdsa_sigverify_fips205_test_vectors() {
	// read the sigverif_fips205.json file
	// The test material was taken from SLH-DSA sigVer-FIPS205 test vectors for signature verification
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json
	json_str := os.read_file('./kat/sigverif_fips205_mini.json')!
	// parse the json string into a SigVerifTest struct
	sigver_test := json2.decode[SigVerifTest](json_str)!
	// Test for every test group
	for tg in sigver_test.testgroups {
		ctx := pslhdsa.new_context_from_name(tg.parameterset)!
		mode := tg.signatureinterface // 'internal' or 'external'
		prehash := tg.prehash // "pure", "prehash" or "none" (for internal interface)
		//
		mut opt := Options{}
		msg_encoding := if mode == 'external' && prehash == 'pure' { true } else { false }
		for t in tg.tests {
			dump(t.tcid)
			// we dont support prehash now
			if prehash == 'prehash' {
				continue
			}
			skb := hex.decode(t.sk)!
			pkb := hex.decode(t.pk)!
			message := hex.decode(t.message)!
			cx := hex.decode(t.context)!
			signature := hex.decode(t.signature)!
			addrnd := hex.decode(t.additionalrandomness)!

			sk := pslhdsa.new_signing_key(ctx, skb)!
			pk := pslhdsa.new_pubkey(ctx, pkb)!
			assert sk.pubkey().equal(pk)

			verified := pslhdsa.slh_verify(message, signature, cx, pk, opt)!
			assert verified == t.testpassed
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
