// Known-answer checks over NanoMQ/NanoNNG library code, printed for mayhem/test.sh to diff
// against mayhem/selftest.golden. Prints values, not verdicts, so a neutered program cannot pass.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nng/mqtt/mqtt_client.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/nmq_base64.h"
#include "nng/supplemental/nanolib/topics.h"

static void
b64(const char *in)
{
	char    enc[128];
	uint8_t dec[128];
	size_t  n = nmq_base64_encode((const uint8_t *) in, strlen(in), enc, sizeof(enc));
	size_t  m = nmq_base64_decode(enc, n, dec, sizeof(dec));
	printf("b64 '%s' -> '%s' (%zu) -> %zu bytes '%.*s'\n", in, enc, n, m, (int) m, dec);
}

static void
decode(const char *name, const uint8_t *pkt, size_t len, int v5)
{
	nng_msg *msg = NULL;
	nng_mqtt_msg_alloc(&msg, 0);
	size_t hl = 2;
	while (hl < len && (pkt[hl - 1] & 0x80)) {
		hl++;
	}
	nng_msg_header_append(msg, pkt, hl);
	nng_msg_append(msg, pkt + hl, len - hl);
	int rv = v5 ? nng_mqttv5_msg_decode(msg) : nng_mqtt_msg_decode(msg);
	printf("%s: rv=%d type=%d", name, rv, (int) nng_mqtt_msg_get_packet_type(msg));
	if (rv == 0) {
		switch (nng_mqtt_msg_get_packet_type(msg)) {
		case NNG_MQTT_CONNECT:
			printf(" ver=%d keepalive=%d clean=%d client='%s'",
			    nng_mqtt_msg_get_connect_proto_version(msg),
			    nng_mqtt_msg_get_connect_keep_alive(msg),
			    nng_mqtt_msg_get_connect_clean_session(msg),
			    nng_mqtt_msg_get_connect_client_id(msg));
			break;
		case NNG_MQTT_PUBLISH: {
			uint32_t tl = 0, pl = 0;
			const char *t = nng_mqtt_msg_get_publish_topic(msg, &tl);
			uint8_t    *p = nng_mqtt_msg_get_publish_payload(msg, &pl);
			printf(" qos=%d retain=%d topic='%.*s' payload='%.*s'",
			    nng_mqtt_msg_get_publish_qos(msg),
			    nng_mqtt_msg_get_publish_retain(msg), (int) tl, t, (int) pl, p);
			break;
		}
		default:
			break;
		}
	}
	printf("\n");
	nng_msg_free(msg);
}

static void
repub(const char *local, const char *remote, const char *in)
{
	topics s;
	memset(&s, 0, sizeof(s));
	s.local_topic      = (char *) local;
	s.local_topic_len  = strlen(local);
	s.remote_topic     = (char *) remote;
	s.remote_topic_len = strlen(remote);
	preprocess_topics(&s, true);
	char *res = generate_repub_topic(&s, (char *) in, true);
	printf("repub local='%s' remote='%s' in='%s' -> '%s'\n", local, remote, in, res ? res : "(null)");
	if (res) {
		nng_strfree(res);
	}
}

int
main(void)
{
	b64("");
	b64("f");
	b64("fo");
	b64("foo");
	b64("hello, nanomq");

	static const uint8_t pub4[] = { 0x30, 0x0c, 0x00, 0x05, 'a', '/', 'b', '/', 'c', 'h', 'e', 'l', 'l', 'o' };
	static const uint8_t pub4q1[] = { 0x3b, 0x0f, 0x00, 0x03, 't', '/', 'x', 0x00, 0x2a, 'p', 'a', 'y', 'l', 'o', 'a', 'd', '!' };
	static const uint8_t con4[] = { 0x10, 0x16, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x0a,
		'n', 'a', 'n', 'o', 'c', 'l', 'i', 'e', 'n', 't' };
	static const uint8_t bad4[] = { 0x30, 0x7f, 0x00, 0x05, 'a' };
	decode("publish_qos0", pub4, sizeof(pub4), 0);
	decode("publish_qos1_retain", pub4q1, sizeof(pub4q1), 0);
	decode("connect_v311", con4, sizeof(con4), 0);
	decode("truncated_publish", bad4, sizeof(bad4), 0);

	repub("sensors/+/temp", "cloud/sensors/+/temp", "sensors/7/temp");
	return 0;
}
