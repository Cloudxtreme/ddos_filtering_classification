#!/usr/bin/env bash
TIMEFORMAT=%R

set -o monitor # means: run background processes in a separate processes...
trap add_next_job CHLD # execute add_next_job when we receive a child complete signal

index=0
max_jobs=$2

data_path=$1


array_of_flows=($(find $data_path -name "nfcapd*")) 
# array_of_flows=($(find `pwd` -name "nfcapd*" |grep za-avond/sr33 |grep -v .txt)) # TESTING
#za-avond/sr33  = 84 files

function add_next_job {
    if [[ $index -lt ${#array_of_flows[*]} ]] # if still jobs to do then add one
    then
        do_job ${array_of_flows[$index]} & # Calling the main task
        index=$(($index+1))
    fi
}


#FOR LINUX
# function do_job {
#     output=`basename $1`
#     time nfdump -r $1 -q -N -o csv 'ipv4 AND DST NET 145.58.0.0/16 AND NOT SRC NET 145.58.0.0/16 '| awk -F , '{cmd ="date -d  \""$1"\" +\"%s\" " ; cmd | getline var; print var","$3","$8","$4","$5","$6","$7","$12","$13","$9","$11; close(cmd) }' |head
#     # > "$output"_jformat
#     echo "$index processed: $1"
# }


#FOR MAC
function do_job {
    echo "$index processed: $1"
    output=`basename $1`
    time nfdump -r $1 -q -N -o csv  | awk -F , '{cmd ="date -j -f \"%Y-%m-%d %H:%M:%S\"  \""$1"\" +\"%s\" "; cmd | getline var; print var","$3","$8","$4","$5","$6","$7","$12","$13","$9","$11; close(cmd) }' > "$output"_jf.txt
}



# 



# add initial set of jobs
while [[ $index -lt $max_jobs ]]
do
    add_next_job
done

wait # wait for all jobs to complete

echo "done"







# ls |grep hame|while read file; do rm $file; done


