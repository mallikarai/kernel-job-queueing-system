#!/bin/bash
echo "=============================================================="
echo "Test script 2: Concatenate files"
echo "Expected Result: The output file should contain content from both the input files "
echo "=============================================================="
#set -x
cd ../
rm *.log

rmmod sys_queue
insmod sys_queue.ko

touch testfile1 testfile2 expected_file
echo "the quick brown fox" > testfile1
echo "jumps over the lazy dog" > testfile2

echo "*******************************************************************" 
echo "Case: Concatenating files; both files exist"
echo "*******************************************************************" 
output=$(./xhw3 -j 12 testfile1 testfile2 concat_file -f)
job_id=$(echo $output | cut -d'#' -f 2)
sleep 2
cat $job_id.log
cat concat_file

echo "the quick brown fox
jumps over the lazy dog" > expected_file
if cmp concat_file expected_file
then
	echo "------------------ TEST CASE 1 PASSED ------------------"
else
	echo "------------------ TEST CASE 1 FAILED ------------------"
fi

rm $job_id.log

echo "*******************************************************************" 
echo "Case: Concatenating files; One file does not exist"
echo "*******************************************************************" 
output=$(./xhw3 -j 12 testfile3 testfile2 concat_file -f)
job_id=$(echo $output | cut -d'#' -f 2)
sleep 2
cat $job_id.log
if grep --quiet "occurred while opening first file - /usr/src/hw3-cse506g02/CSE-506/testfile3" $job_id.log;
then
	echo "------------------ TEST CASE 2 PASSED ------------------"
else
	echo "------------------ TEST CASE 2 FAILED ------------------"
fi

rm testfile1 testfile2 concat_file expected_file $job_id.log

