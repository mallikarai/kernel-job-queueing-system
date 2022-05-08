struct job_args
{
    char *input_file, *output_file;
    unsigned char *key;
    int keylen;
    int priority, job_nbr, job_id;
    void *job_list;
    char **file_list;
    int output_to_file;
    char cwd[256];
    char *data;
    int data_buffer_size;
};


typedef enum
{
    LOW,
    MEDIUM,
    HIGH
} priority;

typedef enum
{
    ENCRYPT_FILE,
    DECRYPT_FILE,
    RENAME_FILE, 
    HASH_FILE,
    LIST_JOBS,
    GET_STATUS,
    DELETE_JOB,
    REORDER_JOB,
    POLL_JOB, 
    REMOVE_MULTIPLE_FILES,
    STAT_MULTIPLE_FILES,
    CONCATENATE_FILES
} operation;


typedef enum
{
    PENDING, 
    RUNNING, 
    FAILED,
    COMPLETE,
    NOT_FOUND
} job_status;


#define MAXWQSIZE 10
#define DATASIZE 256
#define MAX_FILES 10
#define BUFFER_MAX 256