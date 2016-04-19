# This script extracts fields from pcap or pcapng file to be analysed in terms of DDoS.
# It is inspired on the same fields of packetpig 

# ###### Libraries
import argparse
import dpkt
import socket
import os


# ###### Defining the arguments to run the python script. Note that the while the 'inputfile' is required, the 'output' argument isn't.
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--inputfile',
                    type=argparse.FileType('r'), 
                    help='input file, in pcap format NOT pcapng or others')
parser.add_argument('-o', '--outputfile', 
                    nargs='?', 
                    type=argparse.FileType('w'), 
                    help='output file, in txt format')

####========================================================
#### Reading the arguments and dealing with the 'outputfile'
####========================================================
args = parser.parse_args()
#args = parser.parse_args(['-i', 'prod-anon-001.pcap']) #example to test
inputfile = args.inputfile

if args.outputfile is not None:
    outputfile = args.outputfile 
else:
    outputfile = open(os.path.splitext(inputfile.name)[0]+'.txt','w')


# ###### Loading the 'inputfile' as a pcap file, via dpkt library.

pcapfile = dpkt.pcap.Reader(inputfile)


####========================================================
#### Reading and Printing in the 'outputfile' the 33 information about the pcap file (in the same order as the output of packetpig)
####========================================================

for ts, buf in pcapfile:
    eth = dpkt.ethernet.Ethernet(buf)

    #FILTERING ONLY FOR IP
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data #Loading the content of the ethernet into a variable 'ip'
        if ip.p == 1:
            continue
        
        try: proto = ip.data #Loading the content of the 'ip' into a variable 'protocol' that can be for example ICMP, TCP, and UDP.
        except:
            continue
        
        ts = ts #1
        ip_version = ip.v #2
        ip_header_length = ip.hl #3
        ip_tos = ip.tos #4
        ip_total_length = ip.len #5
        ip_id = ip.id #6
        ip_flags = ip.opts #7
        ip_frag_offset = ip.off & dpkt.ip.IP_OFFMASK #8 this field was removed because the more_fragments are more meaningful
        more_fragments = 1 if (int(ip.off & dpkt.ip.IP_MF)!= 0) else 0  #8 This flag is set to a 1 for all fragments except the last one
        ip_ttl = ip.ttl #9
        ip_proto = ip.p #10
        ip_checksum = ip.sum #11
        ip_src  = socket.inet_ntoa(ip.src) #12
        ip_dst  = socket.inet_ntoa(ip.dst) #13


        try: sport = proto.sport #14
        except: sport = "NONE"
        try: dport = proto.dport #15
        except: dport = "NONE"

        try: proto_len = proto.ulen #32
        except: proto_len = "NONE"
        
        tcp_flag =""
        dns_answer = "NONE"
        http_data = "NONE"

        if ip.p == 6 :
            try:
                tcp_seq_id = (proto.flags if ip.p == 6 else 0) #16
                tcp_ack_id = (proto.ack if ip.p == 6 else 0) #17
                tcp_offset = (proto.off if ip.p == 6 else 0) #18
                tcp_ns = (proto.seq if ip.p == 6 else 0) #19 
                tcp_flag += ("CWR" if (int( proto.flags & dpkt.tcp.TH_CWR ) != 0) else ".") #20
                tcp_flag += ("ECE" if (int( proto.flags & dpkt.tcp.TH_ECE ) != 0) else ".") #21
                tcp_flag += ("URG" if (int( proto.flags & dpkt.tcp.TH_URG ) != 0) else ".") #22
                tcp_flag += ("ACK" if (int( proto.flags & dpkt.tcp.TH_ACK ) != 0) else ".") #23
                tcp_flag += ("PSH" if (int( proto.flags & dpkt.tcp.TH_PUSH) != 0) else ".") #24
                tcp_flag += ("RST" if (int( proto.flags & dpkt.tcp.TH_RST ) != 0) else ".") #25
                tcp_flag += ("SYN" if (int( proto.flags & dpkt.tcp.TH_SYN ) != 0) else ".") #26
                tcp_flag += ("FIN" if (int( proto.flags & dpkt.tcp.TH_FIN ) != 0) else ".") #27
                tcp_window = (proto.win if ip.p == 6 else 0) #28
                tcp_len = (len(proto.data) if ip.p == 6 else 0) #29
                udp_len = "NONE" #32
                udp_checksum = "NONE" #33
            except:
                print "EXCEPTION TCP"

            if proto.dport == 80:
                try: 
                    http = dpkt.http.Request(proto.data)
                    http_data = http.data
                except: continue


        elif ip.p == 17:
            tcp_seq_id = "NONE" #16
            tcp_ack_id = "NONE" #17
            tcp_offset = "NONE" #18
            tcp_ns = "NONE" #19
            tcp_flag = "NONE" #20
            tcp_window = "NONE" #28
            try: udp_checksum = proto.sum #33
            except: udp_checksum = "NONE"
        
            tcp_seq_id = "NONE" #16
            tcp_ack_id = "NONE" #17
            tcp_offset = "NONE" #18
            tcp_ns = "NONE" #19
            tcp_flag = "NONE" #20
            tcp_window = "NONE" #28
            udp_checksum = proto.sum #33

            if proto.sport == 53:
                try:
                    dns = dpkt.dns.DNS(proto.data)
                except:
                    continue
                if dns.qr != dpkt.dns.DNS_R:
                    continue
                if dns.opcode != dpkt.dns.DNS_QUERY:
                    continue
                if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
                    continue
                if len(dns.an) < 1:
                    continue
                for qname in dns.qd:
                    dns_answer = qname.name

        print >> outputfile,ts,ip_version,ip_header_length,ip_tos,ip_total_length,ip_id,ip_flags,more_fragments,ip_ttl,ip_proto,ip_checksum,ip_src,ip_dst,sport,dport,tcp_seq_id,tcp_ack_id,tcp_offset,tcp_ns,tcp_flag,tcp_window,proto_len,udp_checksum,dns_answer,http_data
        

