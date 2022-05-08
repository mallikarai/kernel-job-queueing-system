#!/bin/bash
# Test script 1: Submit job for encryption and check if the job is there in list jobs
# Expected Result: The job id should be in list job result
echo "=============================================================="
echo "Test script 8: polling job for status and other results"
echo "=============================================================="
#set -x
cd ../
rm *.log

echo "making and building module with ADD_DELAY flag"
make clean
make ADD_DELAY=1
rmmod sys_queue
insmod sys_queue.ko
echo "make done"

touch testfile1 

## Testing successful renaming with nested file paths. Non-existent input files or output directories should not be renamed
echo "*******************************************************************" 
echo "Case: Deleting multiple files, error for non-existent file"
echo "*******************************************************************" 
output=$(./xhw3 -j 10 ./testdir/../testfile1 testfile2 -f)
job_id=$(echo $output | cut -d'#' -f 2)

./xhw3 -j 9 -i $job_id

rm $job_id.log