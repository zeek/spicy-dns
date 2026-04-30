# @TEST-EXEC: zeek -r ${TRACES}/issue-11.pcap %INPUT
# @TEST-EXEC: zeek-cut -cm uid service < conn.log > conn
# @TEST-EXEC: zeek-cut -cm -n opcode opcode_name < dns.log > dns
# @TEST-EXEC: btest-diff conn
# @TEST-EXEC: btest-diff dns
