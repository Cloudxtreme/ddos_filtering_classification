-- TO RUN: pig -x local -f 0_load_converted_data.pig -p inputfile='../conversion/output/BOOTIO-CHARGEN-S-02_2015-03-26_15%3A21%3A36.txt'

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
    tcp_flag:chararray , --20
    tcp_window:chararray , --21
    --
    proto_len:chararray , --22
    --
    udp_checksum:chararray, --23
    --
    dns_answer:chararray, --24
    http_data:chararray --25
    
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
