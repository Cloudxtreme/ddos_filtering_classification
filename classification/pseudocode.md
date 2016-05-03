
~~~
in: attack_summary[]
in: threshold_sip_restricted in: threshold_ttl_ > 4
out: spoofed?

procedure Spoofed?(input,output)
  if (#sip_restrict > threshold_sip_restricted) and (#sip_ttl_var>9 > threshold_ttl) then 
    spoofed? := “Y”
  else
    spoofed? := “N” end if
end procedure
~~~
