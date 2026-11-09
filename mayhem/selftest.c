// Known-answer checks over NanoMQ's PUBLISH decoder, printed for mayhem/test.sh to diff against
// mayhem/selftest.golden. A decoded PUBLISH is also run through rule_engine_insert_sql() into an in-memory
// SQLite table. The stored rows are not printed: df9bc2e rewrote that SQL composition and stopped
// emitting valid INSERTs, so the rows differ between BASE and FIX; the decoded fields do not.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/broker.h"
#include "include/nanomq.h"
#include "include/pub_handler.h"
#include "nng/nng.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/cvector.h"
#include "nng/supplemental/sqlite/sqlite3.h"

/* The authenticated client's CONNECT (clientid "client", username "user", password "pass"), decoded as the broker does. */
static const uint8_t CONNECT_V311[] = { 0x10, 0x1e, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0xc2, 0x00, 0x3c,
	0x00, 0x06, 'c', 'l', 'i', 'e', 'n', 't', 0x00, 0x04, 'u', 's', 'e', 'r', 0x00, 0x04, 'p', 'a', 's', 's' };
static const uint8_t CONNECT_V5[] = { 0x10, 0x1f, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05, 0xc2, 0x00, 0x3c, 0x00,
	0x00, 0x06, 'c', 'l', 'i', 'e', 'n', 't', 0x00, 0x04, 'u', 's', 'e', 'r', 0x00, 0x04, 'p', 'a', 's', 's' };

static int
connect_client(conn_param *cparam, uint8_t proto_ver)
{
	uint8_t buf[sizeof(CONNECT_V5)];
	size_t  n = proto_ver == MQTT_PROTOCOL_VERSION_v5 ? sizeof(CONNECT_V5) : sizeof(CONNECT_V311);
	memcpy(buf, proto_ver == MQTT_PROTOCOL_VERSION_v5 ? CONNECT_V5 : CONNECT_V311, n);
	return conn_handler(buf, cparam, n);
}

static void
publish(const char *name, const uint8_t *pkt, size_t len, uint8_t proto_ver)
{
	size_t hl = 2;
	while (hl < len && (pkt[hl - 1] & 0x80)) {
		hl++;
	}
	nng_msg *msg = NULL;
	nng_msg_alloc(&msg, 0);
	nng_msg_header_append(msg, pkt, hl);
	nng_msg_append(msg, pkt + hl, len - hl);

	nano_work  *work   = nng_zalloc(sizeof(nano_work));
	conf       *config = nng_zalloc(sizeof(conf));
	conn_param *cparam = NULL;
	conn_param_alloc(&cparam);
	if (connect_client(cparam, proto_ver) != 0)
		printf("connect failed\n");
	work->msg        = msg;
	work->proto_ver  = proto_ver;
	work->config     = config;
	work->cparam     = cparam;
	work->flag       = CMD_PUBLISH;
	work->pub_packet = nng_zalloc(sizeof(struct pub_packet_struct));

	int rc = decode_pub_message(work, proto_ver);
	printf("%s: decode=%d", name, rc);
	if (rc == 0) {
		struct pub_packet_struct *pp = work->pub_packet;
		printf(" qos=%d id=%d topic=%s payload=%.*s clientid=%s username=%s", pp->fixed_header.qos,
		    pp->var_header.publish.packet_id, pp->var_header.publish.topic_name.body,
		    (int) pp->payload.len, (const char *) pp->payload.data, conn_param_get_clientid(cparam),
		    conn_param_get_username(cparam));
		sqlite3 *db = NULL;
		sqlite3_open(":memory:", &db);
		sqlite3_exec(db,
		    "CREATE TABLE t (Qos INT, Id INT, Topic TEXT, Clientid TEXT, Username TEXT, "
		    "Password TEXT, Timestamp INT, Payload TEXT);",
		    0, 0, NULL);

		conf_rule *cr = &config->rule_eng;
		char       sql[] = "SELECT qos, id, topic, clientid, username, password, timestamp, payload "
		                   "FROM \"#\"";
		rule_sql_parse(cr, sql);
		for (size_t i = 0; i < cvector_size(cr->rules); i++) {
			cr->rules[i].forword_type = RULE_FORWORD_SQLITE;
			cr->rules[i].sqlite_table = nng_strdup("t");
			cr->rules[i].enabled      = true;
		}
		cr->option = RULE_ENG_SDB;
		cr->rdb[0] = db;
		nng_mtx_alloc(&cr->rule_mutex);

		int ret = rule_engine_insert_sql(work);
		printf(" insert=%d rules=%zu\n", ret, cvector_size(cr->rules));
		sqlite3_close(db);
		nng_mtx_free(cr->rule_mutex);
		for (size_t i = 0; i < cvector_size(cr->rules); i++) {
			rule_free(&cr->rules[i]);
		}
		cvector_free(cr->rules);
	} else {
		printf("\n");
	}
	free_pub_packet(work->pub_packet);
	conn_param_free(cparam);
	nng_free(config, sizeof(conf));
	nng_free(work, sizeof(nano_work));
	nng_msg_free(msg);
}

int
main(void)
{
	static const uint8_t qos0[]  = { 0x30, 0x0c, 0x00, 0x03, 'a', '/', 'b', '{', '"', 'a', '"', ':', '1', '}' };
	static const uint8_t qos1[]  = { 0x32, 0x09, 0x00, 0x03, 't', '/', 'x', 0x00, 0x2a, 'h', 'i' };
	static const uint8_t plain[] = { 0x30, 0x09, 0x00, 0x03, 'a', '/', 'b', 'x', 'y', 'z', 'w' };
	static const uint8_t bad[]   = { 0x30, 0x7f, 0x00, 0x05, 'a' };
	publish("publish_qos0", qos0, sizeof(qos0), MQTT_PROTOCOL_VERSION_v311);
	publish("publish_qos1", qos1, sizeof(qos1), MQTT_PROTOCOL_VERSION_v311);
	publish("publish_plain", plain, sizeof(plain), MQTT_PROTOCOL_VERSION_v311);
	publish("truncated_publish", bad, sizeof(bad), MQTT_PROTOCOL_VERSION_v311);
	return 0;
}
