# Vendored cryptographic primitives

AES (ECB block cipher, runtime 128/192/256-bit key) and SHA-256, taken
verbatim from Brad Conte's public-domain reference collection:

  https://github.com/B-Con/crypto-algorithms  (public domain)
    aes.c / aes.h       -> aes_key_setup(), aes_encrypt()  (FIPS-197)
    sha256.c / sha256.h -> sha256_init/update/final        (FIPS-180-4)

Both implementations are verified against the NIST test vectors by their
author. They are used unmodified so the provenance stays auditable.

Usage in OpenRTX:
- M17 AES-CTR stream encryption builds the 128-bit counter block itself
  (112-bit LSF META nonce + 16-bit big-endian frame number) and calls
  aes_encrypt() once per 16-byte voice frame to produce the keystream.
- SHA-256 provides a short, non-reversible key fingerprint for on-screen
  verification (the key itself is never displayed).

## Local changes
The only modification from upstream is `#include <memory.h>` -> `<string.h>`
in aes.c and sha256.c: `<memory.h>` is non-standard and absent from the
arm-none-eabi (newlib) toolchain, whereas `<string.h>` provides the same
memcpy/memset declarations and is portable. The AES/SHA logic is untouched.
