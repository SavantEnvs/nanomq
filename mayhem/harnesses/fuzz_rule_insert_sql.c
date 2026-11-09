/*
 * Rule engine -> SQLite forwarding of a PUBLISH packet: decode_pub_message() followed by
 * rule_engine_insert_sql(), the sequence nanomq/apps/broker.c runs in its SEND state for
 * work->flag == CMD_PUBLISH when the rule engine is on.
 *
 * Input: byte 0 selects the MQTT protocol version (even: 3.1.1, odd: 5), the rest is one PUBLISH packet
 * exactly as it arrives on the wire (fixed header, remaining length, topic, properties, payload).
 * The rule comes from the configuration file in a real broker, so it is fixed here and parsed by the
 * library's own rule_sql_parse(): it stores every column the rule engine knows about.
 *
 * Nothing is kept across inputs: each gets a fresh in-memory database, work, config and rule.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "include/nanomq.h"
#include "include/broker.h"
#include "include/pub_handler.h"
#include "nng/nng.h"
#include "nng/mqtt/mqtt_client.h"
#include "nng/protocol/mqtt/mqtt_parser.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/cvector.h"
#include "nng/supplemental/sqlite/sqlite3.h"

static const char RULE_SQL[] =
    "SELECT qos, id, topic, clientid, username, password, timestamp, payload FROM \"#\"";
static const char TABLE_SQL[] =
    "CREATE TABLE t (Qos INT, Id INT, Topic TEXT, Clientid TEXT, Username TEXT, Password TEXT, "
    "Timestamp INT, Payload TEXT);";

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

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 3)
		return -1;
	uint8_t proto_ver = (data[0] % 2 == 0) ? MQTT_PROTOCOL_VERSION_v311 : MQTT_PROTOCOL_VERSION_v5;
	const uint8_t *pkt = data + 1;
	size_t         pkt_len = size - 1;

	/* nng splits a received packet into the header (fixed header byte + remaining-length varint) and the body. */
	size_t i = 1;
	while (i < 5 && i < pkt_len && (pkt[i] & 0x80))
		i++;
	size_t hdr_len = i + 1;
	if (hdr_len >= pkt_len)
		return -1;

	nng_msg *msg = NULL;
	if (nng_msg_alloc(&msg, 0) != 0)
		return 0;
	nng_msg_header_append(msg, pkt, hdr_len);
	nng_msg_append(msg, pkt + hdr_len, pkt_len - hdr_len);

	nano_work *work = nng_zalloc(sizeof(nano_work));
	conf      *config = nng_zalloc(sizeof(conf));
	conn_param *cparam = NULL;
	conn_param_alloc(&cparam);
	connect_client(cparam, proto_ver);

	work->msg        = msg;
	work->proto_ver  = proto_ver;
	work->config     = config;
	work->cparam     = cparam;
	work->flag       = CMD_PUBLISH;
	work->pub_packet = nng_zalloc(sizeof(struct pub_packet_struct));

	int ret = 0;
	if (decode_pub_message(work, proto_ver) != SUCCESS ||
	    work->pub_packet->fixed_header.packet_type != PUBLISH ||
	    work->pub_packet->var_header.publish.topic_name.body == NULL) {
		/* broker.c only reaches the rule engine for a PUBLISH that decoded. */
		ret = -1;
	} else {
		sqlite3 *db = NULL;
		sqlite3_open(":memory:", &db);
		sqlite3_exec(db, TABLE_SQL, 0, 0, NULL);

		conf_rule *cr = &config->rule_eng;
		char       sql[sizeof(RULE_SQL)];
		memcpy(sql, RULE_SQL, sizeof(RULE_SQL));
		rule_sql_parse(cr, sql);
		for (size_t i = 0; i < cvector_size(cr->rules); i++) {
			cr->rules[i].forword_type = RULE_FORWORD_SQLITE;
			cr->rules[i].sqlite_table = nng_strdup("t");
			cr->rules[i].enabled      = true;
		}
		cr->option = RULE_ENG_SDB;
		cr->rdb[0] = db;
		nng_mtx_alloc(&cr->rule_mutex);

		/* On a failed statement rule_engine_insert_sql() closes the database itself and returns 1. */
		if (rule_engine_insert_sql(work) == 0)
			sqlite3_close(db);

		nng_mtx_free(cr->rule_mutex);
		for (size_t i = 0; i < cvector_size(cr->rules); i++)
			rule_free(&cr->rules[i]);
		cvector_free(cr->rules);
	}

	if (proto_ver == MQTT_PROTOCOL_VERSION_v5) {
		struct pub_packet_struct *pp = work->pub_packet;
		uint8_t                   type = pp->fixed_header.packet_type;
		if (type == PUBLISH && pp->var_header.publish.properties) {
			mqtt_property_free(pp->var_header.publish.properties);
		} else if ((type == PUBACK || type == PUBREC || type == PUBREL || type == PUBCOMP) &&
		    pp->var_header.pub_arrc.properties) {
			mqtt_property_free(pp->var_header.pub_arrc.properties);
		}
	}
	free_pub_packet(work->pub_packet);
	conn_param_free(cparam);
	nng_free(config, sizeof(conf));
	nng_free(work, sizeof(nano_work));
	nng_msg_free(msg);
	return ret;
}
