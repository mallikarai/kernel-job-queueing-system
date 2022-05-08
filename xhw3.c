#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <openssl/md5.h>
#include "sys_queue.h"
#include <fcntl.h>
#include <pthread.h>

#ifndef __NR_queue
#error cryptocopy system call not defined
#endif

extern volatile int done_flag;
extern int create_socket();
extern void* pthread_callback();

unsigned int set_job_id(){
	static int count = 1;
	return (getpid() + count++);
}

char* get_job_status(int status) {
	switch(status) {
		case 0:
			return "PENDING";
		case 1:
			return "RUNNING";
		case 2:
			return "FAILED";
		case 3:
			return "COMPLETED";
		case 4:
			return "NOT_FOUND";
		default:
			return "UNKNOWN";
	}
}


int main(int argc, char * const argv[])
{
	char *help_msg = "./xhw3 -p password -[e|d] in_file out_file";
	unsigned char hash[MD5_DIGEST_LENGTH];
	int e_flag = 0, d_flag = 0, keylen = 0;
	char *infile = NULL, *outfile = NULL, *password = NULL;
	// char *absolute_infile = NULL, *absolute_outfile = NULL;
	int opt=0, priority = -1;
	int job_id = -1, job_nbr = -1;
	int rc=0;
	int output_to_file = 0; 
	char **file_list;
	pthread_t pthread;

	while((opt = getopt(argc, argv, ":edfp:j:i:P:h"))!=-1)
	{
		switch(opt)
		{
			case 'h':
				printf("%s\n",help_msg);
				break;
			case 'j':
				job_nbr = atoi(optarg);
				break; 
			case 'P':
				priority = atoi(optarg);
				break; 
			case 'i':
				job_id = atoi(optarg);
				break; 
			case 'p':
				if (strlen(optarg) < 6) 
				{
					printf("Password should be at least 6 characters long.\n");	
					exit(-1);
				}
				password = optarg;
				MD5((const unsigned char*)password, strlen(password), hash);
				keylen = 16;
				break;
			case 'e': 
				e_flag =1;
				break;
			case 'd': 
				d_flag = 1;	
				break;
			case 'f': 
				output_to_file = 1;	
				break;
			case ':':
        		printf("Option %c expects argument\n", optopt);
				goto invalid;
        		break;
			case '?':
				printf ("Unknown option character.\n");	
				goto invalid;
		}
	}


	/* Argument checks */

	if ((job_nbr == 1) && (e_flag !=1)){
		printf("-e option is required for job 1\n ");
		goto invalid;
	}

	if ((job_nbr == 2) && (d_flag !=1)){
		printf("-d option is required for job 2\n ");
		goto invalid;
	}


	if ((job_nbr != 1 && job_nbr != 2) && (d_flag ==1 || e_flag ==1)){
		printf("-e and -d flags are only valid for job 1 and job 2 \n");
		goto invalid;
	}


	if((job_nbr==6 || job_nbr==7 || job_nbr==8 || job_nbr==9) && (job_id ==-1)){
		printf("job id is needed\n ");
		goto invalid;
	}

	if ((job_nbr == 8) && (priority == -1)){
		printf("job priority is needed to reorder\n ");
		goto invalid;
	}

	if (priority == -1)
		priority=1;


	int index = optind;
	while(index < argc){
		if (infile == NULL)
			infile= argv[index];
		else if(outfile == NULL)
			outfile= argv[index];
		if (infile!=NULL && outfile!=NULL)
			break;
		index++;
	}
			
			
	// 1. Check if input output file was provided
	if((job_nbr==1 || job_nbr==2 || job_nbr==3) && ((infile ==NULL) || (outfile==NULL)))
    {
        printf("Input file and output file are needed \n");
        exit(1);
    }

	//2. Check if encryption decryption together 
	if ((e_flag==1) && (d_flag ==1))
	{
		printf("Encryption decryption can't be performed together.");
		goto invalid;
	}

	//3. Check if password missing with encrypt decypt
	if ((e_flag==1 && keylen==0) || (d_flag==1 && keylen==0))
	{
		printf("Encryption/decryption requires password.\n");
		goto invalid;
	}

	if((e_flag==1 || d_flag==1) && (hash== NULL || strlen((char* )hash)==0))
	{
		printf("Password generation failed\n");
		exit(-1);
	}

	struct job_args *args;
	args = malloc(sizeof(struct job_args));
	args->keylen = keylen;
	args->key = hash;
	args->priority = priority;
	args->job_nbr = job_nbr;
	args->output_to_file = output_to_file;
	args->data = NULL;
	if (job_id!=-1) {
		args->job_id = job_id;
	} else {
		args->job_id = set_job_id();
	}

	printf("JOB ID IS: #%d#\n", args->job_id);

	args->input_file = NULL;
	args->output_file = NULL;
	
	index = optind;
	int size = argc-index;
	if (size <1  && (job_nbr==10 || job_nbr==11)){
		printf("Min. 1 file required to delete\n");
		rc = -1; 
		goto exit;
	}

	file_list = malloc((size+1)*sizeof(char*));

	while(index < size+optind){
		file_list[index-optind] = argv[index];
		index++;
	}
	file_list[index]=NULL;

	index = 0;
	while(index < size){
		printf("file : %s\n", file_list[index]);
		index++;
	}

	args->file_list = file_list;

	args->data_buffer_size = MAX_FILES * DATASIZE;
	int list[2*MAXWQSIZE];
	memset(list, 0, 2*MAXWQSIZE * sizeof(int));
	int status;
	/* If Job is to LIST_JOBS, alloc memory for result job list */
	if (job_nbr == 5){
		args->job_list = &list;
	} else if(job_nbr == 6 || job_nbr==9) {
		args->job_list = &status;
		args->data = malloc(args->data_buffer_size);
		memset(args->data,'\0', args->data_buffer_size);
	}
	else
		args->job_list = NULL;
	
	//Setting job to get_status (Job number 6) when POLLING 
	if (job_nbr ==9){
		args->job_nbr = 6;
		int prev_status = -1;
		int loop = 0;
		while(loop<5){
			loop++;
			rc = syscall(__NR_queue, (void *)args);
			if (rc!=0){
				printf("Could not get job status (errno=%d)\n", errno);
				goto exit;
			}
			else{
				void *status_ptr = args->job_list;
				int current_status = *((int *)status_ptr);
				if(prev_status!=current_status) {
					printf("Job status has changed \n");
				}
				printf("Job status : %s\n", get_job_status(current_status));
				if (current_status == COMPLETE || current_status == FAILED)
					printf("Received job result : %s\n", args->data);
				prev_status = current_status;
				if(current_status == 2 || current_status == 3) {
					goto exit;
				}
			}
			sleep(3);			
		}
	}
	
	if(!args->output_to_file && (job_nbr==1 || job_nbr==2 || job_nbr==3 ||  job_nbr==10 || job_nbr==11 || job_nbr==12)) {
		create_socket(args->job_id);
		pthread_create(&pthread, NULL, &pthread_callback,(void*)NULL);
	}

	rc = syscall(__NR_queue, (void *)args);

	if(!args->output_to_file && (job_nbr==1 || job_nbr==2 || job_nbr==3 || job_nbr==10 || job_nbr==11 || job_nbr==12)) {
		printf("Job submitted, waiting for response....\n");
		while(done_flag != 1) {
			sleep(1);
		}
		pthread_join(pthread, NULL);
	}

	switch(job_nbr){
		case 5: 
			if (rc==0){
				int count = 0;
				void *itr = args->job_list;
				while(*((int *)itr)!=0 && count <= 2*MAXWQSIZE){
					printf("job id : %d, status : %s\n", *((int *)itr), get_job_status(*((int *)(itr+sizeof(int)))));
					itr+= 2*sizeof(int);
					count+=2;
				}
			}
			else
				printf("List_jobs operation failed (errno=%d)\n", errno);
			break;
		
		case 6: 
			if (rc==0){
				void *status_ptr = args->job_list;
				printf("job status : %s\n", get_job_status(*((int *)status_ptr)));
			}
			else
				printf("Could not get job status (errno=%d)\n", errno);
			break;
		
		case 7: 
			if(rc == 0) {
				printf("job deleted successfully\n");
			} 
			else {
				if(errno == EPERM) {
					printf("cannot delete a running job\n");
				} 
				else if(errno == ESRCH) {
					printf("cannot delete a completed job\n");
				}
				else
					printf("Could not delete job (errno=%d)\n", errno);
			}
			break;
		
		default: 
			if (rc!=0)
				printf("syscall returned %d (errno=%d)\n", rc, errno);
			break;
	} 
	
	printf("syscall returned %d\n", rc);


	exit: 
		if(args->data)
			free(args->data);
		free(args);
		exit(rc);

	invalid:
			printf("The command should be in the format:\n%s\n",help_msg);
			exit(1);

	
}

