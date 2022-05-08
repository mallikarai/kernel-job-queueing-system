#!/bin/bash
# Test script 2: Submit job for encryption, sleep for 2 seconds and then submit job for decrypt, sleep for 2 seconds and check 
# if both jobs is there in list jobs
# Expected Result: The decrypted file should match encrypted file and both job ids should be in the list
echo "=============================================================="
echo "Test script 9: Delete job operation"
echo "Expected Result: The given job ID should be removed from the job list"
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
output=$(./xhw3 -j 10 testdir/rm1 testdir/rm2 testdir/rm3 -f)
job_id=$(echo $output | cut -d'#' -f 2)
echo $job_id
./xhw3 -j 5
echo "Deleting job-$job_id "
./xhw3 -j 7 -i $job_id
sleep 2
./xhw3 -j 5

echo "If the job is already running then delete job will fail"
# delete log files created
# rm testfile*
rm testdir/rm1 testdir/rm2 testdir/rm3
