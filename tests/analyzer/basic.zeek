# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

# @TEST-EXEC: zeek -r ${TRACES}/dns53.pcap %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='zeek-cut -m uid service' btest-diff conn.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER='zeek-cut -m -n ts opcode opcode_name' btest-diff dns.log
#
# @TEST-DOC: Test DNS analyzer with small trace.

# Check the new signature of the event
event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
   # Both are the same with our trace.
   assert query == original_query, fmt("%s != %s", query, original_query);
}
