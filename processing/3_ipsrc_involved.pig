register 'libs/datafu.jar';
DEFINE MEDIAN datafu.pig.stats.StreamingMedian();
DEFINE VARIANCE datafu.pig.stats.VAR();

DEFINE ipsrc_involved (pcap,selected_ip,selected_proto) RETURNS ipsrc_involved {

   pcap_filtered_based_dstip_and_ipproto = FILTER $pcap BY ((ip_dst == $selected_ip) AND (ip_proto == $selected_proto));

   $ipsrc_involved = FOREACH (GROUP pcap_filtered_based_dstip_and_ipproto BY ip_src) {
   		-- GENERAL STATS
	   	total_packets = COUNT(pcap_filtered_based_dstip_and_ipproto);
	    fragmented_packets = FILTER pcap_filtered_based_dstip_and_ipproto BY (ip_more_fragments > 0);
	    packets_fragment_marked = COUNT(fragmented_packets);
	    
	    distinct_sport = DISTINCT pcap_filtered_based_dstip_and_ipproto.sport;	    
	    distinct_dport = DISTINCT pcap_filtered_based_dstip_and_ipproto.dport;
	    distinct_ip_length = DISTINCT pcap_filtered_based_dstip_and_ipproto.ip_total_length;
	    distinct_ttl = DISTINCT pcap_filtered_based_dstip_and_ipproto.ip_ttl;

	    GENERATE 
	        group AS src_ip, --1
	        --
	        total_packets as total_packets, --2
	        packets_fragment_marked as packets_fragment_marked, --3
	        -- 
	        --distinct_sport AS distinct_sport,
	        COUNT(distinct_sport) AS num_distinct_sport, --5
	        MIN(distinct_sport),
	        MAX(distinct_sport),
	        -- 
	        --distinct_dport AS distinct_dport,
	        COUNT(distinct_dport) AS num_distinct_dport, --5
	        MIN(distinct_dport),
	        MAX(distinct_dport),
	        --
	        COUNT(distinct_ip_length) AS num_distinct_ip_length,
	        MIN(pcap_filtered_based_dstip_and_ipproto.ip_total_length) AS pkt_length_min, --8
	        MAX(pcap_filtered_based_dstip_and_ipproto.ip_total_length) AS pkt_length_max, --8
	        --
	        COUNT(distinct_ttl) AS num_distinct_ttl_avg,
	        MIN(pcap_filtered_based_dstip_and_ipproto.ip_ttl) AS ttl_min, --13
	        MAX(pcap_filtered_based_dstip_and_ipproto.ip_ttl) AS ttl_max, --14
	        --
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_cwr) AS CWR,--16
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_ece) AS ECE,--17
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_urg) AS URG,--18
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_ack) AS ACK,--19
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_psh) AS PSH,--20
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_rst) AS RST,--21
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_syn) AS SYN,--22
	        -- SUM(pcap_filtered_based_dstip_and_ipproto.tcp_fin) AS FIN;--23
	};
};
