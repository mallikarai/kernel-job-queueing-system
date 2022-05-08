#!/bin/bash
# Test script 6: Encrypt a large file and poll for progress
# Expected Result: Progress should be returned
echo "=============================================================="
echo "Test script 7: Encrypt a large file and poll for progress"
echo "=============================================================="

cd ../
rm *.log

echo "making and building module with ADD_PROGRESS flag"
make clean
make ADD_PROGRESS=1
rmmod sys_queue
insmod sys_queue.ko
head -c 512KB /dev/urandom > file1
echo "make done"

./xhw3 -j 1 -e -p password file1 enc_outfile
 rm file1 enc_outfile