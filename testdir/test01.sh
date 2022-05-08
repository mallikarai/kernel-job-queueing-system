#!/bin/bash
# Test script 2: Submit job for encryption, sleep for 2 seconds and then submit job for decrypt, sleep for 2 seconds and check 
# if both jobs is there in list jobs
# Expected Result: The decrypted file should match encrypted file and both job ids should be in the list
echo "=============================================================="
echo "Test script 1: Submit job for encryption, sleep for 2 seconds and then submit job for decrypt, sleep for 2 seconds and check if both jobs is there in list jobs"
echo "Expected Result: The decrypted file should match encrypted file and both job ids should be in the list"
echo "=============================================================="
# set -x

cd ../
rm *.log

make clean
make
rmmod sys_queue
insmod sys_queue.ko

echo "file1" > file1
output=$(./xhw3 -j 1 -e -p password file1 enc_outfile -f)
job_id=$(echo $output | cut -d'#' -f 2)
output=$(./xhw3 -j 5)
count=$(echo $output | grep -a $job_id |  wc -l)

if [ $count -eq "1" ]
then
	echo "Encrypt enqueued successfuly"
	echo "------------------ TEST CASE 1 PASSED ------------------"
else
	echo "------------------ TEST CASE 1 FAILED ------------------"
fi

sleep 2

output=$(./xhw3 -j 2 -d -p password enc_outfile dec_outfile -f)
job_id=$(echo $output | cut -d'#' -f 2)
output=$(./xhw3 -j 5)
count=$(echo $output | grep -a $job_id |  wc -l)

if [ $count -eq "1" ]
then
	echo "decrypt enqueued successfuly"
	echo "------------------ TEST CASE 2 PASSED ------------------"
else
	echo "------------------ TEST CASE 2 FAILED ------------------"
fi

sleep 2

if cmp -s dec_outfile file1; then
    echo "both files match"
    echo "------------------ TEST CASE 3 PASSED ------------------"
else
    echo "------------------ TEST CASE 3 FAILED ------------------"
fi

rm file1 enc_outfile dec_outfile
