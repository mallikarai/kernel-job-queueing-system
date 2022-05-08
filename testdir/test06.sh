#!/bin/bash
echo "=============================================================="
echo "Test script 6: List Jobs"
echo "Expected Result: Listing jobs for root and non-root users"
echo "=============================================================="
#set -x
cd ../
rm *.log

rmmod sys_queue
insmod sys_queue.ko

touch output_file

./xhw3 -j 11 ./testdir/test08.sh -f > /dev/null

echo "**************************************************************"
echo "Case 1: Listing jobs for non-root user"
echo "**************************************************************"
sudo -i -u ubuntu bash << EOF
cd $PWD
touch usero_file
touch dummy
./xhw3 -j 11 dummy -f > /dev/null
./xhw3 -j 5 > usero_file
rm dummy
EOF

echo "------- JOBS LIST -------"
cat usero_file
count=$(cat usero_file |  wc -l)
if [ "$count" -eq "3" ]
then
	echo "NON ROOT user is able to list only one job"
	echo "------------------ TEST CASE 1 PASSED ------------------"
else
	echo "------------------ TEST CASE 1 FAILED ------------------"
fi
rm usero_file

echo "**************************************************************"
echo "Case 2: Listing jobs for root user"
echo "**************************************************************"
./xhw3 -j 5  > output_file
echo "------- JOBS LIST -------"
cat output_file 
count=$(cat output_file |  wc -l)
if [ $count -eq "4" ]
then
	echo "ROOT user is able to list all jobs"
	echo "------------------ TEST CASE 2 PASSED ------------------"
else
	echo "------------------ TEST CASE 2 FAILED ------------------"
fi

rm output_file