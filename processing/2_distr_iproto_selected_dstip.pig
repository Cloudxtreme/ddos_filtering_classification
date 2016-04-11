-- ##########################################################
-- Generating the statistics of destination IP addresses (to find the target(s))
-- Output columns: (1) destination IP address and , (2) number of src_ips, (3) total number of packets. SORTED decrescent by the number of unique IPs that sent packets 
-- ##########################################################
DEFINE distr_iproto_selected_dstip (pcap,selected_ip) RETURNS distr_iproto_selected_dstip {
   pcap_filtered_based_dstip = FILTER $pcap BY (ip_dst == $selected_ip);

   distr_iproto_selected_dstip_partial = FOREACH (GROUP pcap_filtered_based_dstip BY ip_proto)GENERATE 
        group as ip_proto, 
        COUNT(pcap_filtered_based_dstip) as occurrences;

   ipproto_desc = LOAD 'libs/list_ipprotocol_number_desc.txt' USING PigStorage(',') AS (
            ip_proto_number:int, 
            ip_proto_desc:chararray);

   $distr_iproto_selected_dstip = FOREACH( JOIN distr_iproto_selected_dstip_partial BY ip_proto LEFT, ipproto_desc BY ip_proto_number) GENERATE 
   		ip_proto as ip_proto,
		ip_proto_desc as ip_proto_desc, 
     	occurrences as occurrences; 
};
