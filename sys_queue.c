#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/buffer_head.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/module.h>  
#include <linux/proc_fs.h> 
#include <asm/uaccess.h>
#include <linux/list.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include "sys_queue.h"
#include "xcrypt.h"

#define BUFFER_MAX 256

#ifdef ADD_DELAY
    #define DELAY 1
#else
    #define DELAY 0
#endif

#ifdef ADD_PROGRESS
    #define PROGRESS_FLAG 1
#else
    #define PROGRESS_FLAG 0
#endif
struct work_item {
	struct job_args *job_args;
	struct work_struct work;
    struct list_head list;
};

struct jobs{
    int job_id, job_status;
    struct list_head list;
    int priority;
    uid_t user_id;
    struct work_struct *work;
    char *job_result;
};

struct jobs *list_of_jobs;
struct mutex q_mutex;

struct workqueue_struct *low_wq, *med_wq, *high_wq;

void* wt;

struct sock *socket = NULL;
static void send_socket_message(int socket_id, char *buf);

/* XCRYPT CODE START */
long cryptocopy(const char *infile, const char *outfile, char* enc_key, crypt_mode mode, int job_id, int write_to_file);

size_t write_file(struct file *out_filp, void *buf, size_t len, loff_t * position) {   
    return vfs_write(out_filp, buf, len, position);
}

/**
 * THIS METHOD ENCRYPTS/DECRYPTS/COPIES THE SOURCE BUFFER AND PUTS THE OUTPUT IN
 * DESTINATION BUFFER
 */
int crypt_buffer(u8* src_buf, int src_len, u8* dest_buf, int dest_len,
 struct skcipher_request *req, u8 ivec[16], crypt_mode mode) {   
    int ret;
    struct scatterlist sg[2];
    sg_init_one(&sg[0],src_buf,src_len);
	sg_init_one(&sg[1],dest_buf,dest_len);
    if(mode == ENCRYPT) {
        skcipher_request_set_crypt(req, &sg[0], &sg[1], src_len, ivec);
        skcipher_request_set_callback(req,
            CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,crypto_req_done, wt);
        // ENCRYPT
        ret = crypto_wait_req(crypto_skcipher_encrypt(req), wt);
        if (ret) {
            printk("Error encrypting data: %d\n", ret);
            return -1;
        }
    } else if(mode == DECRYPT) {
        skcipher_request_set_crypt(req, &sg[0], &sg[1], src_len, ivec);
        skcipher_request_set_callback(req,
            CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,crypto_req_done, wt);
        // DECRYPT
        ret = crypto_wait_req(crypto_skcipher_decrypt(req), wt);
        if (ret) {
            printk("Error decrypting data: %d\n", ret);
            return -1;
        }
    } else {
        // JUST COPY THE BUFFER
        memcpy(dest_buf, src_buf, src_len);
    }
    return 0;
}

/**
 * THIS METHOD TAKES READS INPUT FILE IN CHUNKS OF PAGE_SIZE AND WRITES PROCESSED OUTPUT
 * TO THE GIVEN OUTPUT FILE. OUTPUT FILE IS CREATED IF NOT ALREADY PRESENT WITH INPUT FILE 
 * PERMISSIONS
 */
int process_file(const char* in_filename, struct file *in_filp, struct file *out_filp, 
struct skcipher_request *req, u8 key[16], crypt_mode mode, int job_id, int write_to_file) {
    size_t page_size = PAGE_SIZE;
    u8 *buf = NULL, *crypt_buf = NULL;
    struct kstat stat;
    size_t fsize, bytes_read = 0;
    mm_segment_t oldfs;
    int ret;
    loff_t position = 0LL, write_pos = 0LL;
    u64 page_num = 0;
    int preamble = 0;
    u8 prb[32];
    u8 prb_key[16];
    int wret;
    int i = 0;
    int bytes_written = 0;
    int progress = 0;

    buf = (u8 *) kmalloc(page_size, GFP_KERNEL);
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    vfs_stat(in_filename, &stat);
    fsize = stat.size;
    // WRITE PREAMBLE TO THE TOP OF OUTPUT FILE
    if(mode == ENCRYPT) {
        u8 iv[16];
        memset(iv,2,16);
        memcpy(iv, &page_num, 8);
        memcpy(iv+8, &(stat.ino), 8);
        memset(prb, 0, 32);
        preamble = 32;
        memcpy(prb, key, 16);
        memcpy(prb+16, iv, 16);
        write_file(out_filp, prb, 32, &write_pos);
    }
    // READ THE PREAMBLE AND MATCH THE PASSKEY
    else if(mode == DECRYPT) {
        memset(prb, 0, 32);
        ret = vfs_read(in_filp, prb, 32, &position);
        memcpy(prb_key, prb, 16);
        // VERIFY IF THE HASH MATCHES
        for(i = 0; i<16; i++) {
            if(prb_key[i] != key[i]) {
                printk("incorrect pass key");
                set_fs(oldfs);
                kfree(buf);
                return -EACCES;
            }
        }
        // printk("password correct!!");
        preamble = -32;
    }
    // READ INPUT FILE IN CHUNKS
    while(bytes_read < fsize) {
        u8 ivc[16];
        write_pos = position + preamble;
        ret = vfs_read(in_filp, buf, page_size, &position);
        if(ret < 0) {
            printk("vfs_read failed");
            set_fs(oldfs);
            kfree(buf);
            if(crypt_buf) {
                kfree(crypt_buf);
            }
            return ret;
        }

        if(crypt_buf) {
            kfree(crypt_buf);
        }
        crypt_buf = (u8 *) kmalloc(ret, GFP_KERNEL);
        // PASS THE RIGHT I-VECTOR WITH PAGE_NUM AND INODE_NUM
        if(mode == ENCRYPT) {
            memset(ivc,2,16);
            memcpy(ivc, &page_num, 8);
            memcpy(ivc+8, &(stat.ino), 8);
        } else if(mode == DECRYPT) {
            memset(ivc,2,16);
            memcpy(ivc, &page_num, 8);
            memcpy(ivc+8, prb+24, 8);
        }
        // memset(ivc,1,16);
        crypt_buffer(buf, ret, crypt_buf, ret, req, ivc, mode);
        wret = write_file(out_filp, crypt_buf, ret, &write_pos);
        if(wret < 0) {
            printk("vfs_write failed");
            set_fs(oldfs);
            kfree(buf);
            kfree(crypt_buf);
            return wret;
        }
        if(!write_to_file && PROGRESS_FLAG){
            bytes_written+= wret;
            if(((100 * bytes_written)/fsize - progress) > 5 || (100 * bytes_written)/fsize == 100){
                progress = (100 * bytes_written)/fsize;;
                snprintf(buf, BUFFER_MAX, "Progress: %d%% \n",progress);
                send_socket_message(job_id, buf);
                msleep(500);
            } 
        }
        bytes_read += page_size;
        page_num++;
    }
    set_fs(oldfs);
    kfree(buf);
    if(crypt_buf) {
        kfree(crypt_buf);
    }
    return 0;
}

/**
 * THIS METHOD INITIALIZES THE REQUIRED CRYPTO SK CIPHER OBJECTS
 */
int custom_crypt(const char *in, const char *out, crypt_mode mode, u8 key[16], int job_id, int write_to_file) {
    int ret;
    const char *out_file = out;
    const char *in_file = in;
    struct file *in_filp, *out_filp;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;

    in_filp = filp_open(in_file, O_RDONLY, 0);
    if (!in_filp || IS_ERR(in_filp)) {
        printk("read_file err %d\n", (int) PTR_ERR(in_filp));
        return PTR_ERR(in_filp);
    }

    // check if input file is regular or not
    if(!S_ISREG(in_filp->f_mode)) {
        printk("input file is not a regular file");
        return -EINVAL;
    }

    out_filp = filp_open(out_file, O_CREAT | O_WRONLY | O_TRUNC, in_filp->f_inode->i_mode);
    if (!out_filp || IS_ERR(out_filp)) {
        printk("write_file err %d\n", (int) PTR_ERR(out_filp));
        filp_close(in_filp, NULL);
        return PTR_ERR(out_filp);
    }

    // check if output file is regular or not
    if(!S_ISREG(out_filp->f_mode)) {
        printk("output file is not a regular file");
        return -EINVAL;
    }

    // check if infile and outfile are same
    if(in_filp->f_inode->i_ino == out_filp->f_inode->i_ino) {
        printk("error: input and output files are the same");
        return -EINVAL;
    }

    // INITIALIZE SYMMETRIC KEY CIPHER TRANSFORM FOR AES CTR
    tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);
    if(!tfm || IS_ERR(tfm)) {
        printk("failed to load cipher transform %ld\n", PTR_ERR(tfm));
        filp_close(in_filp, NULL);
        filp_close(out_filp, NULL);
        return PTR_ERR(tfm);
    }
    
    ret = crypto_skcipher_setkey(tfm, key, 16);
    if(ret) {
        printk("could not set cipher crypto key \n");
        return -EKEYREJECTED;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        printk("could not init cipher request \n");
        filp_close(in_filp, NULL);
        filp_close(out_filp, NULL);
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }
    ret = process_file(in_file, in_filp, out_filp, req, key, mode, job_id, write_to_file);

    filp_close(in_filp, NULL);
    filp_close(out_filp, NULL);
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    return ret;
}

long cryptocopy(const char *infile, const char *outfile, char* enc_key, crypt_mode mode, int job_id, int write_to_file) {
    int ret;
    DECLARE_CRYPTO_WAIT(wait);
    printk("infile %s outfile %s key %s",infile,outfile,enc_key);

    wt = &wait;
    ret = custom_crypt(infile, outfile, mode, enc_key, job_id, write_to_file);
    return ret;
}

/* XCRYPT CODE END */

static int rename_file(char *infile, char *outfile){
    
    int err = 0;
    struct file *in_filp = NULL, *out_filp = NULL; 
    struct dentry *out_dentry = NULL, *in_dentry = NULL ;

    printk("Infile to rename : %s\n", infile);
    in_filp = filp_open(infile, O_RDONLY, 0);
    if (in_filp == NULL || IS_ERR(in_filp)) {
        printk("error occurred while opening user input file\n");
        err =  (int) PTR_ERR(in_filp);
        goto out;
    }

    out_filp = filp_open(outfile, O_WRONLY | O_CREAT , 0775);
    if (out_filp == NULL || IS_ERR(out_filp)) {
        printk("error occurred while opening user output file \n");
        err =  (int) PTR_ERR(out_filp);
        goto out;
    }
    printk("renamed output file : %s\n", outfile);
    
    in_dentry = in_filp->f_path.dentry;
	out_dentry = out_filp->f_path.dentry;

    err = vfs_rename(in_dentry->d_parent->d_inode, in_dentry, out_dentry->d_parent->d_inode, out_dentry, NULL,0);

    out: 
    if(in_filp!=NULL && !IS_ERR(in_filp))
        filp_close(in_filp, NULL);

    if(out_filp!=NULL && !IS_ERR(out_filp))
        filp_close(out_filp, NULL);

    return err;
}

// NEEDS TO BE PASSED WITH out_filp->f_pos initialized to 0
int copy_file(struct file *in_filp, struct file *out_filp) {
    size_t page_size = PAGE_SIZE;
    u8 *buf = NULL, *crypt_buf = NULL;
    size_t bytes_read = 0;
    mm_segment_t oldfs;
    int ret;
    int wret;
    in_filp->f_pos = 0;
    buf = (u8 *) kmalloc(page_size, GFP_KERNEL);
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    // READ INPUT FILE IN CHUNKS
    while(1) {
        bool file_end = 0;
        ret = vfs_read(in_filp, buf, page_size, &(in_filp->f_pos));
        if(ret < 0) {
            printk("vfs_read failed");
            set_fs(oldfs);
            kfree(buf);
            if(crypt_buf) {
                kfree(crypt_buf);
            }
            return ret;
        } else if(ret == 0 || ret < PAGE_SIZE) {
            file_end = 1;
        }

        if(crypt_buf) {
            kfree(crypt_buf);
        }
        crypt_buf = (u8 *) kmalloc(ret, GFP_KERNEL);
        // PASS THE RIGHT I-VECTOR WITH PAGE_NUM AND INODE_NUM
        crypt_buffer(buf, ret, crypt_buf, ret, NULL, NULL, COPY);
        wret = write_file(out_filp, crypt_buf, ret, &(out_filp->f_pos));
        if(wret < 0) {
            printk("vfs_write failed");
            set_fs(oldfs);
            kfree(buf);
            kfree(crypt_buf);
            return wret;
        }
        bytes_read += page_size;
        if(file_end) {
            break;
        }
    }
    set_fs(oldfs);
    kfree(buf);
    if(crypt_buf) {
        kfree(crypt_buf);
    }
    return 0;
}

char * get_absolute_path(char * cwd, char * relative_path){
    char* ret = NULL;
    char *temp = NULL;
    if(!cwd){
        printk("CWD NULL");
        ret = ERR_PTR(-EINVAL);
        goto exit;
    }
    printk("cwd: %s", cwd);
    if(!relative_path){
        printk("relative_path NULL");
        ret = ERR_PTR(-EINVAL);
        goto exit;
    }
    printk("relative_path: %s", relative_path);
    if((relative_path[0])=='/'){
        ret = relative_path;
        goto exit;
    }
    temp = kmalloc(BUFFER_MAX, GFP_KERNEL);
    if(!temp){
        printk("Could not alloc temp file\n");
        ret = ERR_PTR(-EINVAL);
        goto exit;
    }
    memset(temp, '\0', BUFFER_MAX);
    snprintf(temp, BUFFER_MAX-1, "%s/%s",cwd, relative_path);
    strcpy(relative_path, temp);
    ret = relative_path;
    exit:
    printk("converted path: %s", relative_path);
    if(temp) kfree(temp);
    return ret;
}

struct file* init_logging(char *cwd, int job_id){
    int err = 0;
    char *log_file = NULL; 
    struct file *log_filp = NULL;
    log_file = kmalloc(BUFFER_MAX, GFP_KERNEL);
    if(!log_file){
        printk("Could not alloc mem log_file\n");
        err = -ENOMEM;
        goto exit;
    }
    snprintf(log_file, BUFFER_MAX, "%s/%d.log",cwd, job_id);
    printk("logging in file : %s", log_file);
    log_filp = filp_open(log_file, O_WRONLY | O_CREAT | O_TRUNC, 0775);
    if (IS_ERR(log_filp)) {
        printk("error occurred while opening temp file  to be deleted%s",log_file);
        err =  (int) PTR_ERR(log_filp);
        goto exit;
    }
    log_filp->f_pos = 0;
    
    exit:
        if (log_file)
            kfree(log_file);
    return log_filp;
}

void print_to_log(struct file *log_filp, char *log_message){
    int ret = 0;
    printk("logging message %s", log_message);
    if(!log_message){
        printk("NULL log message\n");
        return;
    }
    if(!log_filp || IS_ERR(log_filp)){
        printk("File closed\n");
        return;
    }
    ret = kernel_write(log_filp, log_message, strlen(log_message), &(log_filp->f_pos));
    if (ret <0){
        printk("error occured while writing bytes to log file.\n");
        return;
    }
}

void finish_logging(struct file *log_filp){
    if (log_filp || !IS_ERR(log_filp)) {
            printk("closing log file\n");
            filp_close(log_filp, NULL);
        }
}

static void send_socket_message(int socket_id, char *buf)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int res;

    printk("trying to send to socket_id - %d", socket_id);
    printk("sending message - %s", buf);
	skb_out = nlmsg_new(BUFFER_MAX, 0);
	if (!skb_out) {
		printk("Failed to allocate new skb");
		return;
	}
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, BUFFER_MAX, 0);
    NETLINK_CB(skb_out).dst_group = 0;
	memcpy(nlmsg_data(nlh), buf, BUFFER_MAX);
	res = nlmsg_unicast(socket, skb_out, socket_id);
	if (res < 0)
		printk("Error occured while sending message\n");
}


static void workqueue_func(struct work_struct *work);

asmlinkage extern long (*sysptr)(void *arg);
/**
 * Worker function for the workqueues
 * This method is called for each job submitted to the workqueue
 */
static void workqueue_func(struct work_struct *work)
{
    int  err = 0;
    crypt_mode mode = ENCRYPT;
    struct work_item *worker = container_of(work, struct work_item, work);
    struct list_head *pos = NULL, *q = NULL;
    char *buffer = NULL;
    int found_job = 0;
    struct jobs *tmp=NULL;
    char** temp = worker->job_args->file_list;
    int write_to_log = worker->job_args->output_to_file;
    int data_buffer_size = worker->job_args->data_buffer_size;
    int buffer_offset = 0;
    int unlink_success = 0;
    struct file *log_filp = NULL;
    struct file *temp_filp = NULL;
    int stat_success = 0;
    struct kstat *stat;
    mm_segment_t old_fs;

    if(data_buffer_size > PAGE_SIZE){
        err = -EINVAL;
        goto exit;
    }

     if (write_to_log){
        log_filp = init_logging(worker->job_args->cwd, worker->job_args->job_id);
        if (!log_filp || IS_ERR(log_filp)) {
            printk("Error while init logging\n");
            err = PTR_ERR(log_filp);
            goto exit;
        }
     }
     
    buffer = kmalloc(BUFFER_MAX, GFP_KERNEL);
    if (!buffer) {
        printk("kernel memory allocation failed\n");
        err =  -ENOMEM;
        goto exit;
    }
    memset(buffer, '\0', BUFFER_MAX);
       
    /* Marking job status as RUNNING */
    loop:
    mutex_lock(&q_mutex);
    list_for_each_safe(pos, q,  &(list_of_jobs->list)) {

		tmp = list_entry(pos, struct jobs, list);
        if (tmp->job_id == worker->job_args->job_id){
            tmp->job_status = RUNNING; 
            printk("Job marked as running\n");
            found_job = 1;
            break;
        }
    }
    mutex_unlock(&q_mutex);
    if(found_job == 0){
        goto loop;
    }
        
    printk("starting job %d", worker->job_args->job_nbr);
    if ( worker->job_args->input_file){
        worker->job_args->input_file = get_absolute_path(worker->job_args->cwd, worker->job_args->input_file);
        if(IS_ERR(worker->job_args->input_file)){
            printk("Error in converting file path");
            err = PTR_ERR(worker->job_args->input_file);
            goto exit;
        }
    }

    if ( worker->job_args->output_file){
        worker->job_args->output_file = get_absolute_path(worker->job_args->cwd, worker->job_args->output_file);
        if(IS_ERR(worker->job_args->output_file)){
            printk("Error in converting file path");
            err = PTR_ERR(worker->job_args->output_file);
            goto exit;
        }
    }

    tmp->job_result =  kmalloc(data_buffer_size, GFP_KERNEL);
    if(!tmp->job_result){
        err = -ENOMEM;
        goto exit;
    }

    if(DELAY) {
        printk("add delay is defined");
        msleep(5000);
    }
    switch(worker->job_args->job_nbr){

        case 1:
            if (!worker->job_args->input_file || !worker->job_args->output_file){
                err = -EINVAL;
                goto exit;
            }
            printk("Job : %d . encrypting file\n",worker->job_args->job_nbr);
            buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Encrypting files\n");
            snprintf(buffer, BUFFER_MAX, "Job : %d . encrypting file\n",worker->job_args->job_nbr);
            if(write_to_log){
                print_to_log(log_filp, buffer);
            } else {
                send_socket_message(worker->job_args->job_id, buffer);
            }
            mode = ENCRYPT;
            err = cryptocopy(worker->job_args->input_file, worker->job_args->output_file, worker->job_args->key, mode, worker->job_args->job_id, write_to_log); 
            if (err!=0){
                printk("Error occured while encrypting file%s\n",worker->job_args->input_file);
                buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error occured while encrypting file%s\n",worker->job_args->input_file);
                snprintf(buffer, BUFFER_MAX, "Error occured while encrypting file%s\n",worker->job_args->input_file);
                if(write_to_log){
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
            }
            else{
                printk("File encrypted successfully\n");
                buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "File encrypted successfully\n");
                snprintf(buffer, BUFFER_MAX, "File encrypted successfully\n");
                if(write_to_log){
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
            }
            break;
        
        case 2:
            if (!worker->job_args->input_file || !worker->job_args->output_file){
                err = -EINVAL;
                goto exit;
            }
            printk("Job : %d . decrypting file\n",worker->job_args->job_nbr);
            buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "decrypting files\n");
            snprintf(buffer, BUFFER_MAX, "Job : %d . decrypting file\n",worker->job_args->job_nbr);
            if(write_to_log){
                print_to_log(log_filp, buffer);
            } else {
                send_socket_message(worker->job_args->job_id, buffer);
            }
            mode = DECRYPT;
            err = cryptocopy(worker->job_args->input_file, worker->job_args->output_file, worker->job_args->key, mode, worker->job_args->job_id, write_to_log);
            if (err!=0){
                printk("Error occured while decrypting file%s\n",worker->job_args->input_file);
                buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error occured while decrypting file%s\n",worker->job_args->input_file);
                snprintf(buffer, BUFFER_MAX, "Error occured while decrypting file%s\n",worker->job_args->input_file);
                if(write_to_log){
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
            }
            else{
                printk("File decrypted successfully\n");
                buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "File decrypted successfully\n");
                snprintf(buffer, BUFFER_MAX, "File decrypted successfully\n");
                if(write_to_log){
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
            }
            break; 
        
        case 3:
            if (!worker->job_args->input_file || !worker->job_args->output_file){
                err = -EINVAL;
                goto exit;
            }
            printk("Job : %d . Renaming file\n",worker->job_args->job_nbr);
            buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Renaming files\n");
            snprintf(buffer, BUFFER_MAX, "Job : %d . Renaming file\n",worker->job_args->job_nbr);
            if(write_to_log){
                print_to_log(log_filp, buffer);
            } else {
                send_socket_message(worker->job_args->job_id, buffer);
            }
            while (*temp){
                strcpy(buffer, *(temp)); 
                buffer = get_absolute_path(worker->job_args->cwd, buffer);
                strcpy(worker->job_args->input_file,buffer);
                if(!worker->job_args->input_file || IS_ERR(worker->job_args->input_file)){
                    printk("Error in converting input file path");
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error in converting input file path\n");
                    snprintf(buffer, BUFFER_MAX, "Error in converting input file path\n");
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err = PTR_ERR(worker->job_args->input_file);
                    temp = temp+2;
                    continue;
                }
                if(*(temp+1)){
                    strcpy(buffer, *(temp+1)); 
                    buffer = get_absolute_path(worker->job_args->cwd, buffer);
                    strcpy(worker->job_args->output_file,buffer);
                    worker->job_args->output_file = get_absolute_path(worker->job_args->cwd, *(temp+1));
                    if(!worker->job_args->output_file || IS_ERR(worker->job_args->output_file)){
                        printk("Error in converting output file path");
                        buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error in converting ouput file path\n");
                        snprintf(buffer, BUFFER_MAX, "Error in converting output file path\n");
                        if(write_to_log){ 
                            print_to_log(log_filp, buffer);
                        } else {
                            send_socket_message(worker->job_args->job_id, buffer);
                        }
                        err = PTR_ERR(worker->job_args->output_file);
                        temp = temp+2;
                        continue;
                    }
                }    
                else{
                    printk("Output file corresponding to input file %s not found\n",worker->job_args->input_file);
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Output file corresponding to input file %s not found\n",worker->job_args->input_file);
                    snprintf(buffer, BUFFER_MAX, "Output file corresponding to input file %s not found\n",worker->job_args->input_file);
                    if(write_to_log){
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err = PTR_ERR(worker->job_args->output_file);
                    goto exit;
                }

                err = rename_file(worker->job_args->input_file, worker->job_args->output_file);
                if (err!=0){
                    printk("Error occured while renaming file%s\n",worker->job_args->input_file);
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error occured while renaming file%s\n",worker->job_args->input_file);
                    snprintf(buffer, BUFFER_MAX, "Error occured while renaming file%s\n",worker->job_args->input_file);
                    if(write_to_log){
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    } 
                }
                else{
                    printk("File renamed successfully to %s\n",worker->job_args->output_file);
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "File renamed successfully to %s\n",worker->job_args->output_file);
                    snprintf(buffer, BUFFER_MAX, "File renamed successfully to %s\n",worker->job_args->output_file);
                    if(write_to_log){
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                } 
                temp = temp + 2; 
            }
            break;
        case 10:
            printk("Deleting multiple files\n");
            buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Deleting Multiple files\n");
            snprintf(buffer, BUFFER_MAX, "Deleting Multiple files\n");
            if(write_to_log){ 
                print_to_log(log_filp, buffer);
            } else {
                send_socket_message(worker->job_args->job_id, buffer);
            }
    
            while (*temp){
                memset(buffer,'\0', BUFFER_MAX);
                strcpy(buffer, *temp);
                buffer = get_absolute_path(worker->job_args->cwd, buffer);

                if(IS_ERR(buffer)){
                    printk("Error in converting file path");
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error in converting file path\n");
                    snprintf(buffer, BUFFER_MAX, "Error in converting file path\n");
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err = PTR_ERR(buffer);
                    temp = temp+1;
                    continue;
                }

                temp_filp = filp_open(buffer, O_WRONLY, 0);
                if (IS_ERR(temp_filp)) {
                    printk("error occurred while opening temp file  to be deleted:%s",*temp);
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "error occurred while opening temp file  to be deleted%s\n",*temp);
                    snprintf(buffer, BUFFER_MAX, "error occurred while opening temp file  to be deleted:%s\n",*temp);
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err =  (int) PTR_ERR(temp_filp);
                    temp = temp + 1;
                    continue;
                }
                unlink_success = vfs_unlink(temp_filp->f_path.dentry->d_parent->d_inode, temp_filp->f_path.dentry, NULL);
                if(unlink_success!=0){
                    printk("Error occured while unlinking file %s.\n", buffer);
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error occured while unlinking file %s.\n", *temp);
                    snprintf(buffer, BUFFER_MAX, "Error occured while unlinking file %s\n",*temp);
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err = unlink_success;
                    temp = temp + 1;
                    continue;
                }
                printk("successfully deleted file %s",buffer);
                buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "successfully deleted file %s\n",*temp);
                snprintf(buffer, BUFFER_MAX, "successfully deleted file %s\n",*temp);
                if(write_to_log){
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
                temp = temp + 1;
            }
            break;
        case 11:
            buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Stat-ing Multiple files\n");
            stat = kmalloc(sizeof(struct kstat), GFP_KERNEL);
            while (*temp){
                memset(stat, 0, sizeof(struct kstat));
                memset(buffer,'\0', BUFFER_MAX);
                strcpy(buffer, *temp);
                buffer = get_absolute_path(worker->job_args->cwd, buffer);

                if(IS_ERR(buffer)){
                    printk("Error in converting file path");
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error in converting file path\n");
                    snprintf(buffer, BUFFER_MAX,  "Error in converting file path\n");
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err = PTR_ERR(buffer);
                    temp = temp+1;
                    continue;
                }

                old_fs = get_fs();
                set_fs(KERNEL_DS);
                stat_success = vfs_stat(buffer, stat);
                set_fs(old_fs);
                
                if(stat_success!=0){
                    printk("Error occured while Stat-ing file %s.\n", buffer);
                    buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "Error occured while stat-ing file %s.\n", *temp);
                    snprintf(buffer, BUFFER_MAX, "Error occured while stat-ing file %s\n",*temp); 
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err = stat_success;
                    temp = temp + 1;
                    continue;
                }
                printk("successfully stat-ed file %s",buffer);
                buffer_offset += snprintf(tmp->job_result + buffer_offset, BUFFER_MAX, "successfully stat-ed file %s\n",*temp);
                snprintf(buffer, BUFFER_MAX, "\nfilename: %s\nmode: %u\nnlink: %u\natime: %lld\nctime: %lld\nmtime: %lld\ninode: %llu\nuid: %u\n", *temp, stat->mode, stat->nlink, 
                stat->atime.tv_sec, stat->ctime.tv_sec, stat->mtime.tv_sec, stat->ino, stat->uid.val);
                if(write_to_log){ 
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
                temp = temp + 1;
            }
            kfree(stat);
            break;
        case 12:
            snprintf(buffer, BUFFER_MAX, "Started concatenating files\n");
            if(write_to_log){ 
                print_to_log(log_filp, buffer);
            } else {
                send_socket_message(worker->job_args->job_id, buffer);
            }
            if(*temp && *(temp+1) && *(temp+2)) {
                struct file *file1, *file2, *outfile;
                strcpy(buffer, *temp);
                buffer = get_absolute_path(worker->job_args->cwd, buffer);

                file1 = filp_open(buffer, O_RDONLY, 0);;
                if (IS_ERR(file1)) {
                    printk("error occurred while opening first file - %s",buffer);
                    snprintf(buffer, BUFFER_MAX, "error occurred while opening first file - %s\n", *temp);
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err =  (int) PTR_ERR(file1);
                    goto exit;
                }
                file1->f_pos = 0;

                strcpy(buffer, *(temp+1));
                buffer = get_absolute_path(worker->job_args->cwd, buffer);

                file2 = filp_open(buffer, O_RDONLY, 0);;
                if (IS_ERR(file2)) {
                    printk("error occurred while opening second file - %s",buffer);
                    snprintf(buffer, BUFFER_MAX, "error occurred while opening second file - %s\n",*(temp+1));
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err =  (int) PTR_ERR(file2);
                    goto exit;
                }
                file2->f_pos = 0;

                strcpy(buffer, *(temp+2));
                buffer = get_absolute_path(worker->job_args->cwd, buffer);

                outfile = filp_open(buffer, O_WRONLY | O_CREAT | O_TRUNC, 0);
                if (IS_ERR(outfile)) {
                    printk("error occurred while opening output file - %s\n",buffer);
                    snprintf(buffer, BUFFER_MAX, "error occurred while opening output file - %s\n", *(temp+2));
                    if(write_to_log){ 
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    }
                    err =  (int) PTR_ERR(outfile);
                    goto exit;
                }
                outfile->f_pos = 0;
                err = copy_file(file1, outfile);
                if(err!=0) {
                    printk("concatenating failed with first file\n");
                    snprintf(buffer, BUFFER_MAX, "concatenating failed with first file\n");
                    if(write_to_log){
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    } 
                    goto exit;
                }
                err = copy_file(file2, outfile);
                if(err!=0) {
                   printk("concatenating failed with second file\n");
                    snprintf(buffer, BUFFER_MAX, "concatenating failed with second file\n");
                    if(write_to_log){
                        print_to_log(log_filp, buffer);
                    } else {
                        send_socket_message(worker->job_args->job_id, buffer);
                    } 
                    goto exit;
                }
                printk("concatenating successfully done\n");
                snprintf(buffer, BUFFER_MAX, "concatenating successfully done\n");
                if(write_to_log){
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
                break;
            } else {
                printk("Atleast 3 files are required for this job\n");
                snprintf(buffer, BUFFER_MAX, "Atleast 3 files are required for this job\n");
                if(write_to_log){
                    print_to_log(log_filp, buffer);
                } else {
                    send_socket_message(worker->job_args->job_id, buffer);
                }
            }
            break;
        default : 
            err =0; 
            break;
    }


    exit:
    memset(buffer, 0, BUFFER_MAX);
    send_socket_message(worker->job_args->job_id, buffer);
    mutex_lock(&q_mutex);
    if (err==0){
        tmp->job_status = COMPLETE;
        printk("Marking job as completed\n");
    }
    else{
        tmp->job_status = FAILED;
        printk("Marking job as failed\n");
    }
    tmp->work = NULL;
    mutex_unlock(&q_mutex);
    if(worker->job_args->file_list) {
        char** temp = worker->job_args->file_list;
        while(*temp) {
            kfree(*temp);
            temp = temp + 1;
        }
        kfree(worker->job_args->file_list);
    }
    if(worker->job_args->key) {
        kfree(worker->job_args->key);
    }
    kfree(worker->job_args);
    kfree(worker);
    if (buffer)
        kfree(buffer);
    if(write_to_log)
        finish_logging(log_filp);
    return;
}

/* LIST_JOBS API for user to get status of all jobs belonging to the user */
static int list_jobs(void *job_list){
    int err =0, idx = 0, ret = 0;
    int list_of_ids[2*MAXWQSIZE];
    struct list_head *pos = NULL;
    struct jobs *tmp;
    mutex_lock(&q_mutex);
    list_for_each(pos, &(list_of_jobs->list)){
        printk("Listing jobs in ll\n");
        tmp = list_entry(pos, struct jobs, list);
        if (tmp){
            if ((current_uid().val!=0) && (tmp->user_id != current_uid().val)){ 
                continue;
            }
            list_of_ids[idx] = tmp->job_id;
            list_of_ids[idx+1] = tmp->job_status;
            printk("job id:  %d, job_status : %d, job_priority : %d\n", tmp->job_id, tmp->job_status, tmp->priority);
            idx+=2;   
        }   
	}
    mutex_unlock(&q_mutex);
    ret = copy_to_user(job_list, (void *)list_of_ids, sizeof(int) * idx);
    if (ret!=0) {
		printk("could not copy to user space %d\n", ret);
		err =  -ENOMEM;
	}
    return err;
}

static int get_status(int job_id, void *dest, char* data_dest) {
    int err =0, ret = 0;
    struct list_head *pos = NULL;
    struct jobs *tmp;
    int status = NOT_FOUND;
    char *result = NULL;
    mutex_lock(&q_mutex);
    list_for_each(pos, &(list_of_jobs->list)){
        printk("finding job status ll\n");
        tmp = list_entry(pos, struct jobs, list);
        if (tmp){
            printk("passed_id : %d job id:  %d, user_id : %d curr_usr_id : %d\n", job_id, tmp->job_id, tmp->user_id,current_uid().val);
            if (((current_uid().val == 0) || (tmp->user_id == current_uid().val)) && (tmp->job_id==job_id)){ 
                status = tmp->job_status;
                result = tmp->job_result;
                printk("job result is: %s\n", tmp->job_result);
                printk("job id:  %d, job_status : %d\n", tmp->job_id, tmp->job_status);
                break;
            }
        }   
	}
    mutex_unlock(&q_mutex);
    ret = copy_to_user(dest, &status, sizeof(int));
    if (ret!=0) {
		printk("could not copy to user space %d\n", ret);
		err =  -ENOMEM;
	}

    if(result){
        printk("result get stat is: %s\n", result);
        ret = copy_to_user(data_dest, result,  MAX_FILES * DATASIZE);
        if (ret!=0) {
            printk("could not copy to user space %d\n", ret);
            err =  -ENOMEM;
        }
    }
   
    return err;
}

int enqueue_job_list(struct jobs *job){
    int err =0;
    int total_entries = 0;
    struct list_head *pos = NULL, *q = NULL;
    
    printk("Purging jobs\n");
    loop: // Purge old entries
    mutex_lock(&q_mutex);
    // Maintain size of queue using global variable before deleting job
    total_entries = 0;
    list_for_each_safe(pos, q,  &(list_of_jobs->list)) {
        total_entries++;
    }
    if(total_entries >= MAXWQSIZE){
        list_for_each_safe(pos, q,  &(list_of_jobs->list)) {
            struct jobs *tmp;
            tmp = list_entry(pos, struct jobs, list);
            if(tmp->job_status == COMPLETE || tmp->job_status == FAILED){
                list_del_init(pos);
                if(tmp->job_result){
                    kfree(tmp->job_result);
                } 
                kfree(tmp);
                total_entries--;
            }
            if(total_entries < MAXWQSIZE){
                break;
            }
        }
    }
    mutex_unlock(&q_mutex);
    if(total_entries >= MAXWQSIZE){
        // Wait for jobs to be completed;
        goto loop;
    }
    printk("Purging jobs ended\n");
    mutex_lock(&q_mutex);
    list_add_tail(&(job->list), &(list_of_jobs->list));
    mutex_unlock(&q_mutex);
    return err; 
}


int delete_job(int job_id, bool delete_from_job_list){
    int err = 0;
    bool ret; 
    struct work_struct *work = NULL; 
    struct list_head *pos = NULL;
    struct jobs *tmp;

    mutex_lock(&q_mutex);
    list_for_each(pos, &(list_of_jobs->list)){
        printk("finding job to delete in ll\n");
        tmp = list_entry(pos, struct jobs, list);
        if (tmp){
            if (((current_uid().val == 0) || (tmp->user_id == current_uid().val)) && (tmp->job_id==job_id)){ 
                work = tmp->work;
                printk("Found job to delete");
                break;
            }
        }   
	}
    mutex_unlock(&q_mutex);

    if (!work){
        printk("Cannot delete completed/failed job");
        return -ESRCH;
    }
        
    ret = cancel_work_sync(work);
    if (!ret){
        printk("Cannot delete running job");
        return -EPERM;
    }
    
    if(delete_from_job_list) {
        mutex_lock(&q_mutex);
        list_del_init(pos);
        if(tmp->job_result){
            kfree(tmp->job_result);
        }
        kfree(tmp);
        mutex_unlock(&q_mutex);
    }

    return err; 
}


int reorder_job(int job_id, int priority){
    int err = 0; 
    int found = 0;
    struct list_head *pos = NULL;
    struct jobs *tmp;
    struct workqueue_struct *wq;
    wq = med_wq;

    mutex_lock(&q_mutex);
    list_for_each(pos, &(list_of_jobs->list)){
        printk("finding job to reorder in ll\n");
        tmp = list_entry(pos, struct jobs, list);
        if (tmp){
            if (((current_uid().val == 0) || (tmp->user_id == current_uid().val)) && (tmp->job_id==job_id) && (tmp->priority!=priority)){ 
                printk("Deleted job to be reordered");
                mutex_unlock(&q_mutex);
                err = delete_job(job_id, 0);
                mutex_lock(&q_mutex);
                found = 1;
                break;
            }
        }   
	}
    mutex_unlock(&q_mutex);

    if (err == 0 && found == 1){
        if (priority == 2)
            wq = high_wq;
        if (!queue_work(wq, tmp->work)) {
            tmp->job_status = 2;
            // CANNOT THROTTLE ANYMORE PRODUCERS
            err = -ENOMEM;
            return err;
        }
        else{
            printk("Reoordering job. \n ");
            tmp->priority = priority;
        }
    }

    return err;
}

asmlinkage long queue(void *arg){	
	
	int err=0, ret=0, size = 0;
	struct job_args *args = NULL;
	unsigned char *key = NULL;
	crypt_mode mode = ENCRYPT;
    struct work_item *worker;
    struct jobs *job = NULL; 
    struct workqueue_struct *wq;
    int itr = 0;
    char **temp = NULL;
    char **filenames = NULL;
    struct path pwd;
    char *cwd, *buf;
    wq = med_wq;

	printk("Hello from the other side\n");
	if (arg == NULL){
		printk("Input arguments are null %p\n", arg);
		return -EINVAL;
	}

	//1. Check if user memory addr is valid
	if (!access_ok(arg, sizeof(struct job_args))) {
		printk("Invalid user space address\n");
		err =  -EFAULT;
		goto end;
	}

	//2. Allocate kernel memory
	args = kmalloc(sizeof(struct job_args), GFP_KERNEL);
	if (!args) {
		printk("kernel memory allocation failed\n");
		err =  -ENOMEM;
		goto end;
	}
	
	//3. Copy data from user to kernel space
	ret = copy_from_user(args, (struct job_args *) arg, sizeof(struct job_args));
	if (ret!=0) {
		printk("Copying data from User land failed.\n");
		err = -EFAULT;	
		goto end;
	}

    //Commands to managing jobs in WQ
    switch(args->job_nbr){
        case 5: 
            err = list_jobs(args->job_list);
            goto end;
        case 6 : 
            err = get_status(args->job_id, args->job_list, args->data);
            goto end;
        case 7 : 
            err = delete_job(args->job_id, 1);
            goto end;
        case 8 : 
            err = reorder_job(args->job_id, args->priority);
            goto end;
    }

    args->input_file = NULL;
    args->output_file = NULL;

    pwd = current->fs->pwd;
    path_get(&pwd);
    buf = kmalloc(PATH_MAX,GFP_KERNEL);
    cwd = d_path(&pwd,buf,PATH_MAX);
    strncpy(args->cwd, cwd, 256);
    printk("Hello,the current working directory is %s\n",cwd);

	printk("job number id %d\n", args->job_nbr);
	printk("printing params\n");
	printk("keylen %d\n", args->keylen); 
	printk("priority %d\n", args->priority); 
	printk("job_id %d\n", args->job_id); 
	printk("job_nbr %d\n", args->job_nbr); 
    printk("cwd : %s ", args->cwd); 
    printk("write to log : %d", args->output_to_file); 

    temp = args->file_list;
    while (*temp){
        size++;
        temp = temp + 1;
    }
    printk("file ist size is %d",size);

    filenames = kmalloc((size+1)*sizeof(char*), GFP_KERNEL);
    for(itr = 0; itr < size; itr++) {
        struct filename *f = getname(args->file_list[itr]);
        if(!f || IS_ERR(f)) {
            printk("failed get file name");
            err = -PTR_ERR(f);
            goto end;
        }
        filenames[itr] = kmalloc(BUFFER_MAX, GFP_KERNEL);
        strcpy(filenames[itr], f->name);
        putname(f);

        if (args->input_file == NULL) 
            args->input_file = filenames[itr];
        else if (args->output_file == NULL) 
            args->output_file = filenames[itr];
    }

    filenames[itr] = NULL;
    args->file_list = filenames;
    temp = args->file_list;

	// COPY THE KEY
    if(args->job_nbr == 1 || args->job_nbr == 2) {
		if(args->job_nbr == 1) {
			mode = ENCRYPT;
		} else {
			mode = DECRYPT;
		}
        key = kmalloc(17, GFP_KERNEL);
        ret = copy_from_user(key, args->key, args->keylen);
        if(ret!=0) {
            printk("could not copy the key from user space");
            err =  -EFAULT;
			goto end;
        }
        args->key = key;
        key[16] = '\0';
    } else {
        args->key = NULL;
    }
	printk("the key is %s\n", key);
	printk("priority is %d\n", args->priority);

    worker = kmalloc(sizeof(struct work_item), GFP_KERNEL);
    worker->job_args = args;

    job = kmalloc(sizeof(struct jobs), GFP_KERNEL);
    if(!job){
        printk("Could not alloc mem to jobs\n");
        err = -ENOMEM;
        goto end;
    }
    job->job_id = worker->job_args->job_id;
    job->priority = worker->job_args->priority;
    job->job_status = PENDING; 
    job->user_id = current_uid().val;
    job->work = &worker->work;
    job->job_result = NULL;
    printk("Job id in queue method ; %d\n", job->job_id);
    printk("Job status ; %d\n", job->job_status);
    printk("Job user_id ; %d\n", job->user_id);

    INIT_WORK(&worker->work, workqueue_func);

    if (worker->job_args->priority == 2)
        wq = high_wq;
    
    if (!queue_work(wq, &worker->work)) {
		kfree(worker);
        kfree(job);
        // CANNOT THROTTLE ANYMORE PRODUCERS
		err = -ENOMEM;
        goto end; 
	}
    else{
        printk("Enqueing job. \n ");
        err = enqueue_job_list(job);
        if (err!=0) {
            printk("Could not enqueue job\n");
            goto end;
        }
    }

	end: 	
		return err;
}

static int __init init_sys_queue(void)
{
    struct netlink_kernel_cfg cfg = {
        .flags  = NL_CFG_F_NONROOT_RECV,
    };
	printk("installing new sys_queue module\n");

	if (sysptr == NULL)
		sysptr = queue;
    
    // CREATE NETLINK CONNECTION
    socket = netlink_kernel_create(&init_net, 31, &cfg);

    if (!socket) {
        printk("Error creating socket.\n");
        return -1;
    }

    list_of_jobs= kzalloc(sizeof(struct jobs), GFP_KERNEL);
    if (!list_of_jobs) {
		return -ENOMEM;
	}
    INIT_LIST_HEAD(&(list_of_jobs->list));
    mutex_init(&q_mutex);
    
    // low_wq = alloc_workqueue("custom_queue_low", WQ_MEM_RECLAIM | WQ_LOWPRI, 0);
    if(DELAY) {
        printk("add delay is defined");
        med_wq = alloc_workqueue("custom_queue_default", WQ_MEM_RECLAIM, 1);
        high_wq = alloc_workqueue("custom_queue_high", WQ_MEM_RECLAIM | WQ_HIGHPRI, 1);
    } else {
        printk("add delay not defined");
        med_wq = alloc_workqueue("custom_queue_default", WQ_MEM_RECLAIM, 30);
        high_wq = alloc_workqueue("custom_queue_high", WQ_MEM_RECLAIM | WQ_HIGHPRI, 20);
    }
    
	return 0;
}
static void  __exit exit_sys_queue(void)
{
    struct list_head *pos = NULL, *q = NULL;
	if (sysptr != NULL)
		sysptr = NULL;
    // destroy_workqueue(low_wq);
    mutex_lock(&q_mutex);
    list_for_each_safe(pos, q,  &(list_of_jobs->list)) {
		struct jobs *tmp;
		tmp = list_entry(pos, struct jobs, list);
		list_del_init(pos);
        if(tmp->job_result){
            kfree(tmp->job_result);
        }
		kfree(tmp);
    }
    mutex_unlock(&q_mutex);
    mutex_destroy(&q_mutex);
    destroy_workqueue(med_wq);
    destroy_workqueue(high_wq);
    if(socket) {
        netlink_kernel_release(socket);
    }
	printk("removed sys_queue module\n");
}

module_init(init_sys_queue);
module_exit(exit_sys_queue);
MODULE_LICENSE("GPL");
