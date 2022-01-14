# BIP340 Elliptic Curve Signatures

This library follows the BitCoin BIP340 proposal for implementing
Schnorr signatures for secp256k1.  (See: https://bips.xyz/340)

Much of the code is based upon (stolen from) Aaron Dixon's [gist](https://gist.github.com/atdixon/7d65042f494683a8f855e735ec4e6203), with my thanks.

The api is very simple:

 * `sha-256`
 `([message])`<br>
   Returns the sha256 hash of the message.
   Both the message and the hash are byte-arrays.
 * `num->bytes ([length n])` <br>
    Returns the byte-array representation of the BigInteger n.
    The array will have the specified length.
 * `bytes->num ([bytes])` <br>
    Returns a BigInteger from a byte-array.
 * `bytes->hex-string`
 `([byte-array])` <br>
   Returns a string containing the hexadecimal
   representation of the byte-array. This is the
   inverse of hex-string->bytes.
 * `hex-string->bytes`
 `([hex-string])` <br>
   returns a byte-array containing the bytes described
   by the hex-string.  This is the inverse of bytes->hex-string.
 * `pub-key`
 `([private-key])` <br>
   returns the public-key for a given private key.
   Both are byte-arrays of length 32.
 * `sign`
 `([private-key message])` <br>
   Returns the 64 byte signature of the message
   and the private key.  The message and the
   private key are byte-arrays.
 * `verify`
 `([public-key message signature])` <br>
   Returns true if the public-key proves that the message was
   signed using the private key.  Otherwise returns nil.
   The public-key and the message are byte-arrays of length 32.
   The signature is a byte-array of length 64.

### Notes:
 * The three tag-hash constants `[challenge-tag-hash aux-tag-hash nonce-tag-hash]` 
should probably not be publicly known.  We need a way to initialize
them in a secure way.
 * The algorithms are pretty slow. For high volume relays
they would need a lot of optimization.
