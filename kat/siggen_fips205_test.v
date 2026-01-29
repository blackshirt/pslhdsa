import pslhdsa
import os
import encoding.hex
import x.json2

fn test_siggen_fips205() {
	// read the siggen_fips205.json file
	// The test material was taken from SLH-DSA keyGen-FIPS205 test vectors for key generation
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
			skb := hex.decode(t.sk)!
			pkb := hex.decode(t.pk)!
			message := hex.decode(t.message)!
			cx := hex.decode(t.context)!
			signature := hex.decode(t.signature)!

			sk := pslhdsa.new_signing_key(ctx, skb)!
			pk := pslhdsa.new_pubkey(ctx, pkb)!
			assert sk.pubkey().equal(pk)

			// skseed := hex.decode(t.skseed)!
			// skprf := hex.decode(t.skprf)!
			// pkseed := hex.decode(t.pkseed)!

			// skb := hex.decode(t.sk)!
			// pkb := hex.decode(t.pk)!
			// check if the generated key is valid
			// sk := pslhdsa.slh_keygen_with_seed(ctx, skseed, skprf, pkseed)!
			// assert sk.bytes() == skb
			// assert sk.pubkey().bytes() == pkb
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
	tcid     int
	deferred bool
	skseed   string
	skprf    string
	pkseed   string
	sk       string
	pk       string
}
