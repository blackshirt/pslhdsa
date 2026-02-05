// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Signature internal verification test vectors
// NOTE: Its a big test, so be quiet
module pslhdsa

import os
import encoding.hex
import json

// This test only verifies the internal signature verification test vectors
// from FIPS205 SLH-DSA signature verification test vectors.
fn test_slhdsa_sigverify_fips205_internal_test_vectors() {
	// read the sigverif_fips205_internal.json file
	// The test material was taken from SLH-DSA sigVer-FIPS205 test vectors for signature verification
	// but only taken the internal interfaces
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json
	json_str := os.read_file('./sigverif_fips205_internal.json')!
	// parse the json string into a SigVerif struct
	// BUG: This json.decode fails with `-prod` flag
	sigver_test := json.decode(SigVerif, json_str)!
	// Test for every test group
	for tg in sigver_test.testgroups {
		// creates SLH-DSA context from group parameter set
		ctx := new_context_from_name(tg.parameterset)!
		for t in tg.tests {
			// We only test for internal signature verification, so we ommit
			// the signing key generation and signature generation path
			pkb := hex.decode(t.pk)!
			msg := hex.decode(t.message)!
			sig := hex.decode(t.signature)!

			pk := new_pubkey(ctx, pkb)!
			// some test cases has invalid signature size, with error reason "invalid signature - too large"
			// skip those test cases
			slh_sig := parse_slhsignature(ctx, sig) or {
				assert err == error('signature bytes must correct size for ${ctx.kind}')
				continue
			}
			verified := slh_verify_internal(msg, slh_sig, pk)!
			assert verified == t.testpassed

			// explicitly release resources
			unsafe {
				pkb.free()
				msg.free()
				sig.free()
			}
		}
	}
}

// Test for signature verification
struct SigVerif {
	vsid       int
	algorithm  string
	mode       string
	revision   string
	issample   bool
	testgroups []SigVerifGroup
}

struct SigVerifGroup {
	tgid               int
	testtype           string
	parameterset       string
	signatureinterface string
	prehash            string
	tests              []SigVerifItem
}

struct SigVerifItem {
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
