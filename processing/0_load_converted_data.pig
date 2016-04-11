-- TO RUN: pig -x local -f pcap_ddos_analysis.pig -p inputfile='../conversion/output/<FILE_NAME>'

-- =========================================================
-- DEFINING CONSTANTS
-- =========================================================
%DEFAULT binsize 1 -- binsize for timeseries in second

-- =========================================================
-- PREPARING THE OUTPUT DIRECTORY
-- =========================================================
%DECLARE filePcap `basename $inputfile`;
%DEFAULT outputFolder 'output_example/TrafficAnalysis_$filePcap';


-- ##########################################################
-- Loading the pcap
-- ##########################################################
pcap = LOAD '$inputfile' using PigStorage(' ') AS (
    ts, -- 1
    ip_version:int, -- 2
    ip_header_length:int, --3
    ip_tos:int, -- 4
    ip_total_length:int, --5
    ip_id:int, --6
    ip_flags:int, --7
    --ip_frag_offset:int, -- 8 This field was substituted (from the packetpig) for the ip_more_fragments (bellow)
    ip_more_fragments:int, --8 
    ip_ttl:int, --9
    ip_proto:int, --10
    ip_checksum:int, --11
    ip_src:chararray, --12
    ip_dst:chararray, --13
    --
    sport:chararray , --14
    dport:chararray , --15
    --
    tcp_seq_id:chararray , --16
    tcp_ack_id:chararray , --17
    tcp_offset:chararray , --18
    tcp_ns:chararray ,-- 19 
    tcp_cwr:chararray , --20
    tcp_ece:chararray , --21
    tcp_urg:chararray , --22
    tcp_ack:chararray , --23
    tcp_psh:chararray , --24
    tcp_rst:chararray , --25
    tcp_syn:chararray , --26
    tcp_fin:chararray , --27
    tcp_window:chararray , --28
    tcp_len:chararray , --29
    --
    udp_len:chararray , --32
    udp_checksum:chararray --33
);

IMPORT '1_distr_srcips_per_dstip.pig';
distr_srcips_per_dstip = distr_srcips_per_dstip (pcap);
-- STORE (ORDER distr_srcips_per_dstip BY packets DESC) INTO '1_distr_srcips_per_dstip' USING PigStorage(',', '-schema');

IMPORT '2_distr_iproto_selected_dstip.pig';
-- FOR A FIRST FLOW WE USE THE TOP 1 DESTINATION IP ADDRESS BUT FOR THE NEXT ONES IT MUST BE DYNAMIC
top1_dstip = LIMIT (ORDER distr_srcips_per_dstip BY packets DESC) 1;
distr_iproto_selected_dstip = distr_iproto_selected_dstip (pcap,'top1_dstip.ip_dst');
-- STORE (ORDER distr_iproto_selected_dstip BY occurrences DESC) INTO '2_distr_iproto_selected_dstip' USING PigStorage(',', '-schema');

IMPORT '3_ipsrc_involved.pig';
top1_ipproto = LIMIT (ORDER distr_iproto_selected_dstip BY occurrences DESC) 1;
ipsrc_involved = ipsrc_involved (pcap,'top1_dstip.ip_dst', 'top1_ipproto.ip_proto');
DUMP ipsrc_involved;
