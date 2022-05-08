#!/bin/bash
echo "=============================================================="
echo "Test script 3: Test to rename multiple files"
echo "Expected Result: The given input files should be renamed to their corresponding output files (if provided) else error if output file is missing "
echo "=============================================================="
#set -x
cd ../
rm *.log

rmmod sys_queue
insmod sys_queue.ko

touch testfile1 testfile2

## Testing successful renaming with nested file paths. Non-existent input files or output directories should not be renamed
echo "*******************************************************************" 
echo "Case: Renaming multiple files"
echo "*******************************************************************" 
output=$(./xhw3 -j 3 ./testdir/../testfile1 testdir/renamed_testfile1 testfile2 dir_not_present/renamed_testfile2 testfile3 testdir/renamed_testfile3 -f)
job_id=$(echo $output | cut -d'#' -f 2)
sleep 2
cat $job_id.log

if grep --quiet "File renamed successfully to /usr/src/hw3-cse506g02/CSE-506/testdir/renamed_testfile1" $job_id.log;
then
	echo "------------------ TEST CASE 1 PASSED ------------------"
else
	echo "------------------ TEST CASE 1 FAILED ------------------"
fi

if grep --quiet "Error occured while renaming file/usr/src/hw3-cse506g02/CSE-506/testfile2" $job_id.log;
then
	echo "------------------ TEST CASE 2 PASSED ------------------"
else
	echo "------------------ TEST CASE 2 FAILED ------------------"
fi

if grep --quiet "Error occured while renaming file/usr/src/hw3-cse506g02/CSE-506/testfile3" $job_id.log;
then
	echo "------------------ TEST CASE 3 PASSED ------------------"
else
	echo "------------------ TEST CASE 3 FAILED ------------------"
fi

rm testdir/renamed_testfile1 testfile2

echo "*******************************************************************" 
echo "Case: Renaming single file"
echo "*******************************************************************" 
touch testfile1 testfile2
output=$(./xhw3 -j 3 testfile1 testdir/renamed_testfile1 testfile2 -f)
job_id=$(echo $output | cut -d'#' -f 2)
sleep 2
cat $job_id.log

if grep --quiet "Output file corresponding to input file /usr/src/hw3-cse506g02/CSE-506/testfile2" $job_id.log;
then
	echo "------------------ TEST CASE 4 PASSED ------------------"
else
	echo "------------------ TEST CASE 4 FAILED ------------------"
fi

rm testdir/renamed_testfile1 testfile2 $job_id.log
# rm testfile*
