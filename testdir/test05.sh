#!/bin/bash
# Test script 1: Submit job for encryption and check if the job is there in list jobs
# Expected Result: The job id should be in list job result
echo "=============================================================="
echo "Test script 4: Stat multiple files"
echo "=============================================================="
#set -x
cd ../
rm *.log

rmmod sys_queue
insmod sys_queue.ko

touch testfile1 

## Testing successful renaming with nested file paths. Non-existent input files or output directories should not be renamed
echo "*******************************************************************" 
echo "Case: Stat multiple files, error for non-existent file"
echo "*******************************************************************" 
output=$(./xhw3 -j 11 ./testdir/../testfile1 testfile2 -f)
job_id=$(echo $output | cut -d'#' -f 2)
sleep 2
cat $job_id.log

if grep --quiet "filename:" $job_id.log ;
then
	echo "------------------ TEST CASE 1 PASSED ------------------"
else
	echo "------------------ TEST CASE 1 FAILED ------------------"
fi

if grep --quiet "uid:" $job_id.log ;
then
	echo "------------------ TEST CASE 2 PASSED ------------------"
else
	echo "------------------ TEST CASE 2 FAILED ------------------"
fi

if grep --quiet "Error occured while stat-ing file /usr/src/hw3-cse506g02/CSE-506/testfile2" $job_id.log;
then
	echo "------------------ TEST CASE 3 PASSED ------------------"
else
	echo "------------------ TEST CASE 3 FAILED ------------------"
fi

rm testfile1 $job_id.log