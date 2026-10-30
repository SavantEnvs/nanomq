// URL parser harness. The in-tree fuzz/fuzz_nng_url.c returns early on any byte outside 0x20..0x7e and on
// any input without "://", so most mutations never reach nni_url_parse. This one hands every input to the
// parser (NUL-terminated, as a C string caller would) and, when it parses, also runs the helpers a
// listener/dialer applies to the result: clone, rebuild the address string, and percent-decode the parts.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/nng_impl.h"
#include "core/url.h"
#include "nng/nng.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0 || size > 4096) {
		return -1;
	}

	char *input = (char *) malloc(size + 1);
	if (input == NULL) {
		return -1;
	}
	memcpy(input, data, size);
	input[size] = '\0';

	nni_url *url = NULL;
	if (nni_url_parse(&url, input) == 0 && url != NULL) {
		nni_url *copy = NULL;
		if (nni_url_clone(&copy, url) == 0) {
			nni_url_free(copy);
		}

		char *str = NULL;
		if (nni_url_asprintf(&str, url) == 0) {
			nni_strfree(str);
		}
		str = NULL;
		if (nni_url_asprintf_port(&str, url, 1883) == 0) {
			nni_strfree(str);
		}

		uint8_t out[512];
		if (url->u_path != NULL) {
			(void) nni_url_decode(out, url->u_path, sizeof(out));
		}
		if (url->u_query != NULL) {
			(void) nni_url_decode(out, url->u_query, sizeof(out));
		}
		nni_url_free(url);
	}

	free(input);
	return 0;
}
