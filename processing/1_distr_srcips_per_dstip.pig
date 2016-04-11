-- ##########################################################
-- Generating the statistics of destination IP addresses (to find the target(s))
-- Output columns: (1) destination IP address and , (2) number of src_ips, (3) total number of packets. SORTED decrescent by the number of unique IPs that sent packets 
-- ##########################################################
DEFINE distr_srcips_per_dstip (pcap) RETURNS distr_srcips_per_dstip {
   $distr_srcips_per_dstip = FOREACH (GROUP $pcap BY ip_dst) {
    distinct_srcips = DISTINCT $pcap.ip_src;
    GENERATE 
        group as ip_dst, 
        COUNT(distinct_srcips) as num_uniq_srcip,
        COUNT(pcap) as packets; 
	};
};