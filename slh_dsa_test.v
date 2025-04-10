module pslhdsa

fn test_basic_signing_verifying() ! {
	ctx := new_context(.sha2_128f)
	dump(ctx.id.str())
	sk, pk := slh_keygen(ctx)!
	dump(sk)
	dump(pk)

	msg := 'Hello'.bytes()
	cx := []u8{}
	sig := slh_sign(ctx, msg, cx, sk)!
	// dump(sig.hex())

	valid := slh_verify_internal(ctx, msg, sig, pk)!
	dump(valid)
}
