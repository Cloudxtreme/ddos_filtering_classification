### Attack type pseudocode ###

~~~
input: attack_summary[],upper_threshold, lower_threshold
output: attack_type

1: procedure AttackType(input,output)
2:  if attack_summary[ip_protocol] = “TCP” then
3:    if attack_summary[http_type_top1] != “NONE” then
4:      if attack_summary[http_type_top1%] > upper_threshold then
5:        attack_type := `attack_summary[dport_top1]`
6:      else if attack_summary[http_type_top1%] > lower_threshold then
7:        attack_type := `attack_summary[dport_top1]` “+” 
8:      end if
9:    else if attack_summary[tcp_flag_top1] != “NONE” then
10:      if attack_summary[tcp_flag_top1%] > upper_threshold then
11:       attack_type := attack_summary[ip_proto] attack_summary[tcp_flag_top1]
12:     else 
13:       if attack_summary[tcp_flag_top1%] > lower_threshold then 
14:           attack_type := attack_summary[ip_proto] attack_summary[tcp_flag_top1] "+"
15:       else
16:           attack_type := ip_proto “multiple ports” 
17:       end if
18:     end if
19:   else if attack_summary[ip_protocol] = “UDP” then
20:     if attack_summary[sport_top1%] > upper_threshold then 
21:       attack_type := attack_summary[sport_top1]
22:     else if attack_summary[sport_top1%] > lower_threshold then 
23:       attack_type := attack_summary[sport_top1] "+"
24:     else
25:       attack_type := attack_summary[ip_proto] "multiple ports"
26:     end if
27:   else
28:     attack_type := attack_summary[ip_proto]
29:   end if
30: end procedure
~~~

### IP Fragmentation Attack pseudocode ###

~~~
input: attack_summary[], threshold_#sip_frag 
output: fragmentation?

1: procedure Fragmentation?(input,output)
2:   if #sip_f rag_marked > threshold_#sip_f rag then
3:     fragmentation? := “Y” 
4:     else
5:          fragmentation? := “N” 
6:   end if
7: end procedure
~~~

### IP Spoofing Attack pseudocode ###
~~~
input: attack_summary[], in: threshold_sip_restricted, threshold_ttl_ > 4
output: spoofed?

1: procedure Spoofed?(input,output)
2:   if (#sip_restrict > threshold_sip_restricted) and (#sip_ttl_var>9 > threshold_ttl) then 
3:    spoofed? := “Y”
4:    else
5:      spoofed? := “N” 
6:  end if
7: end procedure
~~~

### Reflection Attack pseudocode ###
~~~
input: attack_summary[], threshold_sport_%, threshold_#dport 
output: reflection?

1: procedure Reflection?(input,output)
2:  if (spoofed? = “N”) and (sport_top1_% >threshold_sport_%) and (#dport_distinct > threshold_#dport) then
3:    reflection? := “Y” 
4:    else
5:      reflection? := “N” 
6:  end if
7: end procedure
~~~
