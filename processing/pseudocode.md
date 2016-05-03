 \(x_k\) 
~~~
in: attack_summary[]
in: threshold_sip_restricted in: threshold_ttl_ > 4
out: spoofed?

procedure Spoofed?(input,output)
if (#sip_restrict > threshold_sip_restricted) and
(#sip_ttl_var_higer4 > threshold_ttl_ > 4) then spoofed? := “Y”
else
spoofed? := “N” end if
end procedure
~~~
