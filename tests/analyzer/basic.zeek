# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/dns53.pcap %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid service > conn.log.tmp && mv conn.log.tmp conn.log
# @TEST-EXEC: cat dns.log | zeek-cut -n opcode opcode_name > dns.log.tmp && mv dns.log.tmp dns.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dns.log
#
# @TEST-DOC: Test DNS analyzer with small trace.

# Check the new signature of the event
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
   # Both are the same with our trace.
   assert query == original_query, fmt("%s != %s", query, original_query);
}
