// Base64 harness. Same input handling as fuzz/fuzz_base64.c (encode the bytes, decode them as text), plus
// the strict decoder, which is where the padding and trailing-bit rejection paths live and which the
// in-tree harness never calls, and a decode into an undersized buffer for the insufficient-space paths.
// The encoder's output must decode back to the input.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nng/supplemental/nanolib/nmq_base64.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > 65536) {
		return -1;
	}

	size_t   enc_sz  = BASE64_ENCODE_OUT_SIZE(size);
	size_t   dec_sz  = BASE64_DECODE_OUT_SIZE(size);
	char    *enc_out = (char *) malloc(enc_sz);
	uint8_t *dec_out = (uint8_t *) malloc(dec_sz);
	if (enc_out == NULL || dec_out == NULL) {
		free(enc_out);
		free(dec_out);
		return -1;
	}

	size_t n = nmq_base64_encode(data, size, enc_out, enc_sz);
	if (n != (size_t) -1) {
		size_t   back_sz = BASE64_DECODE_OUT_SIZE(n);
		uint8_t *back    = (uint8_t *) malloc(back_sz);
		if (back != NULL) {
			size_t m = nmq_base64_decode_strict(enc_out, n, back, back_sz);
			if (m != size || memcmp(back, data, size) != 0) {
				__builtin_trap();
			}
			free(back);
		}
	}

	(void) nmq_base64_decode((const char *) data, size, dec_out, dec_sz);
	(void) nmq_base64_decode_strict((const char *) data, size, dec_out, dec_sz);
	(void) nmq_base64_decode((const char *) data, size, dec_out, dec_sz / 2);
	(void) nmq_base64_decode_strict((const char *) data, size, dec_out, dec_sz / 2);

	free(enc_out);
	free(dec_out);
	return 0;
}
