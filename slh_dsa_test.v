module pslhdsa

fn test_basic_signing_verifying() ! {
	ctx := new_context(.sha2_128f)
	sk, pk := slh_keygen(ctx)!
	dump(sk)
	dump(pk)
}
