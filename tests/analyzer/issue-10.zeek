# @TEST-EXEC: zeek -r ${TRACES}/issue-10.pcap %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER="zeek-cut -cm uid service" btest-diff conn.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER="zeek-cut -cm uid service" btest-diff dns.log
