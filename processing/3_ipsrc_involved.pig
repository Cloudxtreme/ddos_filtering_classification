register 'libs/datafu.jar';
DEFINE MEDIAN datafu.pig.stats.StreamingMedian();
DEFINE VARIANCE datafu.pig.stats.VAR();

DEFINE ipsrc_involved (pcap,selected_ip,selected_proto) RETURNS ipsrc_involved {

   pcap_filtered_based_dstip_and_ipproto = FILTER $pcap BY ((ip_dst == $selected_ip) AND (ip_proto == $selected_proto));

   ipsrc_involved_part1 = FOREACH (GROUP pcap_filtered_based_dstip_and_ipproto BY ip_src) {
   		-- GENERAL STATS
	   	total_packets = COUNT(pcap_filtered_based_dstip_and_ipproto);
	    fragmented_packets = FILTER pcap_filtered_based_dstip_and_ipproto BY (ip_more_fragments > 0);
	    packets_fragment_marked = COUNT(fragmented_packets);
	    
	    distinct_sport = DISTINCT pcap_filtered_based_dstip_and_ipproto.sport;	    
	    distinct_dport = DISTINCT pcap_filtered_based_dstip_and_ipproto.dport;
	    distinct_ip_length = DISTINCT pcap_filtered_based_dstip_and_ipproto.ip_total_length;
	    distinct_ttl = DISTINCT pcap_filtered_based_dstip_and_ipproto.ip_ttl;
	    distinct_tcp_flag = DISTINCT pcap_filtered_based_dstip_and_ipproto.tcp_flag;
	    distinct_ip_proto = DISTINCT pcap_filtered_based_dstip_and_ipproto.ip_proto;
	    GENERATE 
	        group AS ip_src, --1
	        --
	        distinct_ip_proto AS ip_proto,
	        COUNT(distinct_ip_proto) AS num_distinct_ip_proto, --5
	        --
	        total_packets as total_packets, --2
	        packets_fragment_marked as packets_fragment_marked, --3
	        -- 
	        distinct_sport AS distinct_sport,
	        COUNT(distinct_sport) AS num_distinct_sport, --5
	        MIN(distinct_sport) AS min_distinct_sport,
	        MAX(distinct_sport) AS max_distinct_sport,
	        -- 
	        distinct_dport AS distinct_dport,
	        COUNT(distinct_dport) AS num_distinct_dport, --5
	        MIN(distinct_dport) AS min_distinct_dport,
	        MAX(distinct_dport) AS max_distinct_dport,
	        --
	        COUNT(distinct_ip_length) AS num_distinct_ip_length,
	        MIN(pcap_filtered_based_dstip_and_ipproto.ip_total_length) AS pkt_length_min, --8
	        MAX(pcap_filtered_based_dstip_and_ipproto.ip_total_length) AS pkt_length_max, --8
	        --
	        COUNT(distinct_ttl) AS num_distinct_ttl_avg,
	        MIN(pcap_filtered_based_dstip_and_ipproto.ip_ttl) AS ttl_min, --13
	        MAX(pcap_filtered_based_dstip_and_ipproto.ip_ttl) AS ttl_max, --14
	        --
	        COUNT(distinct_tcp_flag) AS tcp_flags,--16
	        distinct_tcp_flag AS distinct_tcp_flag;
	        
	};
	sip_mbps_pps = FOREACH (GROUP pcap_filtered_based_dstip_and_ipproto BY (ip_src, (ts / $binsize * $binsize))) GENERATE 
        FLATTEN(group) AS (ip_src,bin),
        (float)(SUM(pcap_filtered_based_dstip_and_ipproto.ip_total_length))*8/1000000 AS mbits_per_bin,
        COUNT(pcap_filtered_based_dstip_and_ipproto) AS pkts_per_bin;


	sip_mbps_pps_part2 = FOREACH (GROUP sip_mbps_pps BY ip_src) GENERATE 
        group AS ip_src,
        AVG(sip_mbps_pps.mbits_per_bin) AS mbits_per_bin_avg,
        AVG(sip_mbps_pps.pkts_per_bin) AS pkts_per_bin_avg;

    STORE sip_mbps_pps_part2 INTO whatever USING PigStorage(',', '-schema');

    -- sh libs/get_ans.sh 'pcap_filter2_sip';

-- pcap_filter2_sip_ans = LOAD '$outputFolder/pcap_filter2_sip/pcap_filter2_sip_ans.txt' USING PigStorage(';') AS (
--         asn:chararray,
--         ip:chararray, 
--         bgp_prefix:chararray, 
--         country:chararray, 
--         as_info:chararray
--     );

    $ipsrc_involved = FOREACH (JOIN ipsrc_involved_part1 BY ip_src LEFT, sip_mbps_pps_part2 BY ip_src) GENERATE 
	    ipsrc_involved_part1::ip_src AS ip_src,
	    ip_proto AS ip_proto,
	    num_distinct_ip_proto AS num_distinct_ip_proto,
	    total_packets AS total_packets,
	    packets_fragment_marked AS packets_fragment_marked,
	    distinct_sport AS distinct_sport,
	    num_distinct_sport AS num_distinct_sport,
		min_distinct_sport AS min_distinct_sport,
		max_distinct_sport AS max_distinct_sport,
		distinct_dport AS distinct_dport,
		num_distinct_dport AS num_distinct_dport,
		min_distinct_dport AS min_distinct_dport,
		num_distinct_ip_length AS num_distinct_ip_length,
		pkt_length_min AS pkt_length_min,
		pkt_length_max AS pkt_length_max,
		num_distinct_ttl_avg AS num_distinct_ttl_avg,
		ttl_min AS ttl_min,
		tcp_flags AS tcp_flags,
		distinct_tcp_flag AS distinct_tcp_flag,
		mbits_per_bin_avg AS mbits_per_bin_avg,
		pkts_per_bin_avg AS pkts_per_bin_avg;
};
