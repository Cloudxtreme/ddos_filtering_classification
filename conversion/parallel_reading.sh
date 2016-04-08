#!/usr/bin/env bash
TIMEFORMAT=%R

set -o monitor # means: run background processes in a separate processes...
trap add_next_job CHLD # execute add_next_job when we receive a child complete signal

array_of_flows=($(find `pwd` -name "nfcapd*" |grep za-avond/sr33 |grep -v .txt)) # places output into an array
#za-avond/sr33  = 84 files

index=0
max_jobs=$1

function add_next_job {
    if [[ $index -lt ${#array_of_flows[*]} ]] # if still jobs to do then add one
    then
        do_job ${array_of_flows[$index]} & # Calling the main task
        index=$(($index+1))
    fi
}

function do_job {
    output=`basename $1`
    time nfdump -r $1 -q -N -o csv| awk '{print $5}' > "$output"_hame
    echo "$index processed: $1"
}

# add initial set of jobs
while [[ $index -lt $max_jobs ]]
do
    add_next_job
done

wait # wait for all jobs to complete

echo "done"



# ls |grep hame|while read file; do rm $file; done



# $flow -q -N -o csv
# find . -name "nfcapd*" |grep za-avond/sr33 |grep -v .txt|grep hame|while read file; do rm $file; done
# nfdump -r $1 | awk '{print $5}' > "$1"_hame
# nfdump -r $1 -q -N -o csv| awk '{print $5}' > /mnt/ramdisk/"$output"_hame