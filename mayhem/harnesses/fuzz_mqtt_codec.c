// MQTT packet decoder harness. Same input layout as fuzz/fuzz_mqtt_codec.c (first byte picks v3.1.1 or
// v5, the rest is one packet), but the packet is split the way the transports hand it to the decoder:
// fixed header (type byte + remaining-length varint) in the message header, the rest in the body.
// The in-tree harness appends everything to the body, so the decoder rejects every input at the
// fixed-header step and never reaches the connect/publish/subscribe parsers.
#include <stddef.h>
#include <stdint.h>

#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 3 || size > 65536) {
		return -1;
	}
	int            v5     = data[0] % 2;
	const uint8_t *pkt    = data + 1;
	size_t         pktlen = size - 1;

	size_t hlen = 1;
	while (hlen < pktlen && hlen < 5) {
		if (!(pkt[hlen] & 0x80)) {
			break;
		}
		hlen++;
	}
	hlen++;
	if (hlen > pktlen) {
		return -1;
	}

	nng_msg *msg = NULL;
	if (nng_mqtt_msg_alloc(&msg, 0) != 0) {
		return 0;
	}
	if (nng_msg_header_append(msg, pkt, hlen) != 0 ||
	    nng_msg_append(msg, pkt + hlen, pktlen - hlen) != 0) {
		nng_msg_free(msg);
		return 0;
	}

	if (v5) {
		nng_mqttv5_msg_decode(msg);
	} else {
		nng_mqtt_msg_decode(msg);
	}

	nng_msg_free(msg);
	return 0;
}
