// Copyright © 2024 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// SLH-DSA Key generation test vectors
// NOTE: Its a big test, so be quiet
import pslhdsa
import os
import encoding.hex
import x.json2

// Test vectors for SLH-DSA key generation
fn test_slhdsa_keygen_fips205_test_vectors() {
	// read the keygen_fips205.json file
	// The test material was taken from SLH-DSA keyGen-FIPS205 test vectors for key generation
	// See https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json
	json_str := os.read_file('./kat/keygen_fips205.json')!
	// parse the json string into a KeygenTest struct
	keygen_test := json2.decode[KeygenTest](json_str)!
	// Test for every test group
	for tg in keygen_test.testgroups {
		ctx := pslhdsa.new_context_from_name(tg.parameterset)!
		for t in tg.tests {
			dump(t.tcid)
			// check if the test case is valid
			if t.deferred {
				continue
			}
			skseed := hex.decode(t.skseed)!
			skprf := hex.decode(t.skprf)!
			pkseed := hex.decode(t.pkseed)!

			skb := hex.decode(t.sk)!
			pkb := hex.decode(t.pk)!
			// check if the generated key is valid
			sk := pslhdsa.slh_keygen_from_seed(ctx, skseed, skprf, pkseed)!
			assert sk.bytes() == skb
			assert sk.pubkey().bytes() == pkb
			// explicitly release the resources
			unsafe {
				skseed.free()
				skprf.free()
				pkseed.free()
				skb.free()
				pkb.free()
			}
		}
	}
}

struct KeygenTest {
	vsid       int
	algorithm  string
	mode       string
	revision   string
	issample   bool
	testgroups []KeygenGroupItem
}

struct KeygenGroupItem {
	tgid         int
	testtype     string
	parameterset string
	tests        []KeygenCaseItem
}

struct KeygenCaseItem {
	tcid     int
	deferred bool
	skseed   string
	skprf    string
	pkseed   string
	sk       string
	pk       string
}
