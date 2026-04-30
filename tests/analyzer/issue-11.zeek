# @TEST-EXEC: zeek -r ${TRACES}/issue-11.pcap %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER="zeek-cut -cm uid service" btest-diff conn.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="zeek-cut -cm -n ts opcode opcode_name" btest-diff dns.log
