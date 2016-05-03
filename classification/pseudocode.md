### Attack type pseudocode ###
~~~
input: attack_summary[],upper_threshold, lower_threshold
output: attack_type

procedure AttackType(input,output)
  if ip_protocol = “TCP” then
    if http_type_top1 != “NONE” then
      if http_type_top1% > upper_threshold then
        attack_type := dport_top1
        else if http_type_top1% > lower_threshold then
          attack_type := dport_top1 “+” end if
        else if tcp_flag_top1 != “NONE” then
          if tcp_flag_top1% > upper_threshold then
            attack_type := ip_proto tcp_flag_top1 
            else 
              if tcp_flag_top1% > lower_threshold then 
                attack_type := ip_proto tcp_f lag_top1
                else
                  attack_type := ip_proto “multiple ports” 
        end if
      end if
    else if ip_protocol = “UDP” then
        if sport_top1% > upper_threshold then 
          attack_type := sport_top1
          else if sport_top1% > lower_threshold then 
            attack_type := sport_top1 “+”
          else
            attack_type := ip_proto “multiple ports” end if
      else
        attack_type := ip_proto 
  end if
end procedure
~~~

### IP Fragmentation Attack pseudocode ###

~~~
input: attack_summary[], threshold_#sip_frag 
output: fragmentation?

procedure Fragmentation?(input,output)
  if #sip_f rag_marked > threshold_#sip_f rag then
    fragmentation? := “Y” 
    else
      fragmentation? := “N” 
  end if
end procedure
~~~

### IP Spoofing Attack pseudocode ###
~~~
input: attack_summary[], in: threshold_sip_restricted, threshold_ttl_ > 4
output: spoofed?

procedure Spoofed?(input,output)
  if (#sip_restrict > threshold_sip_restricted) and (#sip_ttl_var>9 > threshold_ttl) then 
    spoofed? := “Y”
    else
      spoofed? := “N” 
  end if
end procedure
~~~

### Reflection Attack pseudocode ###
~~~
input: attack_summary[], threshold_sport_%, threshold_#dport 
output: reflection?

procedure Reflection?(input,output)
  if (spoofed? = “N”) and (sport_top1_% >threshold_sport_%) and (#dport_distinct > threshold_#dport) then
    reflection? := “Y” 
    else
      reflection? := “N” 
  end if
end procedure
~~~
