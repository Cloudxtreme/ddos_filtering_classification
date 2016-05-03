### Attack type pseudocode ###

The **AttackType()** procedure receives as input: (i) an `attack summary table`, (ii) an `upper threshold`, and (iii) a `lower threshold`. Overall, the attack type can be: TCP-based (line 2), UDP-based (line 18), or any other IP protocol based (line 27). It depends on the value of the `attack_summary[ip_protocol]` which is one of the outputs of the `Processing Module`. If it is a TCP-based attack, then it checks if exists a HTTP type (e.g., POST, GET) `attack_summary[http_type_top1]`. If positive then it checks if the percentage of top 1 HTTP type (`attack_summary[http_type_top1%]`) is part of the majority of network records (`upper_threshold`). If positive, it means that it correspond to a HTTP or HTTPS attack (`attack_summary[dport_top1]`). If negative and the percentage of top 1 HTTP type is in between the `lower_threshold` and the `upper_threshold` then it means that the top1

~~~
input: attack_summary[],upper_threshold, lower_threshold
output: attack_type

1: procedure AttackType(input,output)
2:  if attack_summary[ip_protocol] = “TCP” then
3:    if attack_summary[http_type_top1] != “NONE” then
4:      if attack_summary[http_type_top1%] > upper_threshold then
5:        attack_type := `attack_summary[dport_top1]`
6:        else if attack_summary[http_type_top1%] > lower_threshold then
7:                attack_type := `attack_summary[dport_top1]` “+” 
               end if
8:        else if attack_summary[tcp_flag_top1] != “NONE” then
9:                if attack_summary[tcp_flag_top1%] > upper_threshold then
10:                   attack_type := attack_summary[ip_proto] attack_summary[tcp_flag_top1]
11:                   else 
12:                     if attack_summary[tcp_flag_top1%] > lower_threshold then 
13:                       attack_type := attack_summary[ip_proto] attack_summary[tcp_flag_top1] "+"
14:                       else
15:                         attack_type := ip_proto “multiple ports” 
16:       end if
17:     end if
18:     else if attack_summary[ip_protocol] = “UDP” then
19:       if attack_summary[sport_top1%] > upper_threshold then 
20:         attack_type := attack_summary[sport_top1]
21:           else if attack_summary[sport_top1%] > lower_threshold then 
22:                   attack_type := attack_summary[sport_top1] "+"
23:                   else
24:                     attack_type := attack_summary[ip_proto] "multiple ports"
25:                 end if
26:     else
27:         attack_type := attack_summary[ip_proto]
28:  end if
29: end procedure
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
