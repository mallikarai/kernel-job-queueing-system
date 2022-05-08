#!/bin/bash
# Test script 2: Submit job for encryption, sleep for 2 seconds and then submit job for decrypt, sleep for 2 seconds and check 
# if both jobs is there in list jobs
# Expected Result: The decrypted file should match encrypted file and both job ids should be in the list
echo "=============================================================="
echo "Test script 10: Reorder job priority"
echo "Expected Result: The last enqueed job should start running before the previous ones"
echo "=============================================================="
# set -x

cd ../
rm *.log
 
echo "making and building module with ADD_DELAY flag"
make clean
make ADD_DELAY=1
rmmod sys_queue
insmod sys_queue.ko
echo "make done"

touch testdir/rm1 testdir/rm2 testdir/rm3
output=$(./xhw3 -j 11 will_fail -f)
output=$(./xhw3 -j 11 README -f)
output=$(./xhw3 -j 11 Makefile -f)
output=$(./xhw3 -j 10 will_fail -f)
output=$(./xhw3 -j 10 testdir/rm1 testdir/rm2 testdir/rm3 -f)
job_id=$(echo $output | cut -d'#' -f 2)
echo $job_id
./xhw3 -j 5
echo "Changing priority of job-$job_id to high"
./xhw3 -j 8 -P 2 -i $job_id >/dev/null
sleep 2
./xhw3 -j 5

# delete log files created
# rm *.log
