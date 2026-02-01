## pslhdsa
a SLH-DSA implementation in pure V language

`pslhdsa` is an (experimental) quantum resistent cryptographic digital signature standard based on 
Stateless Hash-Based Digital Signature Standard (SLH-DSA) implemented in pure V language.
A SLH-DSA was approved and publicly published by NIST at August, 2024. 
Its availables on NIST FIPS 205. SLH-DSA allow builds relatively big signaturue size with 
small key (16 - 32 bytes key). 
The signatures range from ±8K - ±50K depending on the type chosen.

## Features
- Support signature types defined on the standard
- Support for pure SLH-DSA hash and pre-hash signature generation
- Fully implemented in pure V language, no depends on any external libraries

## Basic 
`pslhdsa` provides a simple interface for generating and verifying signatures.
1. The basic fundamental type that describes SLH-DSA parameter set is a `Context` structure,
defined as
```code
pub struct Context {
	// The kind (type) of this SLH-DSA context, set on context creation
	kind Kind
pub:
	// Underlying SLH-DSA parameter set described in the doc
	prm Param
}
```
where `Kind` is an enum that describes the signature type chosen.
You can create a `Context` opaque by calling `new_context(k Kind)` 
or `new_context_from_name(name string)!` 

2. SLH-DSA Signing key <br>
`pslhdsa` provides a `SigningKey` structure to hold a SLH-DSA signing key where you 
can generate the SLH-DSA signature. `SigningKey` itself embeds public key part 
to verify the signature.

3. SLH-DSA Verifying key <br>
`pslhdsa` provides a `PubKey` structure to hold a SLH-DSA verifying key.
You can use the `PubKey` opaque to verify the SLH-DSA signature.

## Key Generation
You can use several routines to generate keys for SLH-DSA to operate on.
The most common way is to use the `Context` structure to generate keys.
1. ```fn slh_keygen(c &Context) !&SigningKey```
2. ```fn slh_keygen_from_bytes(ctx &Context, bytes []u8, opt Options) !&SigningKey```
3. ```fn slh_keygen_from_seed(ctx &Context, skseed []u8, skprf []u8, pkseed []u8) !&SigningKey```

## Signature generation
- TODO

## Signature verification
- TODO
