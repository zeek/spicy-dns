# @TEST-EXEC: zeek -r ${TRACES}/dns-svr.pcap %INPUT >output
# Zeek 6.0 prints also includes `AD` and `CD` bits in `dns_msg` which leads to a difference in the baselines.
# @TEST-EXEC: if zeek-version 60000; then btest-diff output; fi
#
# @TEST-DOC: Test the DNS SVR event.

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count)
   {
   print c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, msg, ans, target, priority, weight, p;
   }
