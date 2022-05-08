struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
	struct crypto_wait wait;
};


static int encypt_decrypt_func(char *key, char *data, int bytes, int flag, char *ivdata){
	int err = 0; 
	struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;

	skcipher = crypto_alloc_skcipher("ctr(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
        printk("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        printk("could not allocate skcipher request\n");
        err = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
						crypto_req_done,&sk.wait);


    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        printk("key could not be set\n");
        err = -EAGAIN;
        goto out;
    }

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, data, bytes);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, bytes, ivdata);
    crypto_init_wait(&sk.wait);

    /* encrypt data */
    if (flag ==1){
    	err = crypto_wait_req(crypto_skcipher_encrypt(sk.req), &sk.wait);
		printk("Encryption triggered successfully\n");
    }
    else if (flag ==2){
		err  = crypto_wait_req(crypto_skcipher_decrypt(sk.req), &sk.wait);
		printk("Decryption triggered successfully\n");
	}
     

    if (err){
		goto out;
    }  
    

	out:
		if (skcipher)
			crypto_free_skcipher(skcipher);
		if (req)
			skcipher_request_free(req);
		return err;

}



// static int read_write_file(struct Input_data *input, int flag){
// 	int err = 0, unlink_success = 0, parital_op_flag = 0;
// 	struct file *in_filp = NULL, *out_filp = NULL, *temp_filp = NULL;
// 	ssize_t read_bytes = 0, write_bytes = 0;
// 	int bytes_left=0;
// 	char *hash_buf = NULL, *buf= NULL, *ivdata= NULL;
// 	unsigned long page_count = 0; 
// 	struct filename *in_file=NULL, *out_file=NULL;
// 	char * temp_file = input->output_file;
// 	struct dentry *out_dentry = NULL, *temp_dentry = NULL ;

// 	// Get input output files in kernel mem 
// 	in_file = getname(input->input_file);
// 	if (IS_ERR(in_file)){
// 		err = -ENOENT;
// 		printk("Invalid input file path.\n");
// 		goto end;
// 	} 
// 	printk("obtained infile at %s\n",  in_file->name);

// 	out_file = getname(input->output_file);
// 	if (IS_ERR(out_file)){
// 		err = -ENOENT;
// 		printk("Invalid output file path.\n");
// 		goto end;
// 	} 
// 	printk("obtained outfile at %s\n",  out_file->name);

// 	/* Opening input file */
// 	printk("Opening input file\n");
// 	in_filp = filp_open(in_file->name, O_RDONLY, 0);
//     if (in_filp ==NULL || IS_ERR(in_filp)) {
// 		printk("error occurred while opening user input file %s",in_file->name);
// 		err = (int) PTR_ERR(in_filp);
// 		goto end;
//     }

// 	//Check if input files is regular
// 	if ((!S_ISREG(in_filp->f_inode->i_mode))) {
// 		printk(KERN_INFO "Input File is not regular.\n");
// 		err = -ENOENT;
// 		goto end; 
// 	}

// 	/* Opening input file */
// 	printk("Opening output file\n");
// 	out_filp = filp_open(out_file->name, O_WRONLY | O_CREAT | O_TRUNC, 0);
//     if (IS_ERR(out_filp)) {
// 		printk("error occurred while opening user output file %s\n",out_file->name);
// 		err =  (int) PTR_ERR(out_filp);
// 		goto end;
//     }

// 	//Check if output file is regular
// 	if ((!S_ISREG(out_filp->f_inode->i_mode))) {
// 		printk(KERN_INFO "Output File is not regular.\n");
// 		err = -ENOENT;
// 		goto end; 
// 	}

// 	out_filp->f_inode->i_mode  = in_filp->f_inode->i_mode; 

// 	// Check if input and output files are the same 
// 	if(out_filp->f_inode->i_ino == in_filp->f_inode->i_ino){
// 		err = -EPERM;
// 		printk(" Input and output file are the same.\n");
// 		goto end;
// 	}
	
// 	in_filp->f_pos = 0;
// 	bytes_left = in_filp->f_inode->i_size;
	
// 	//Allocating buffer for reading hash bytes from given encrypted file for decryption
// 	hash_buf = kmalloc(32, GFP_KERNEL);
// 	if (hash_buf == NULL) { 
// 		err = -ENOMEM;
// 		goto end;
//  	}
	
// 	if (flag == 2){  //DECRYPTION : Retrieving hash from file header
// 		read_bytes = kernel_read(in_filp, hash_buf, 32 , &in_filp->f_pos);
// 		if (read_bytes <0){
// 			printk("unable to read hash bytes.\n");
// 			err  = -EIO;
// 			goto end;
// 		}
	
// 		if (memcmp(input->keybuf, hash_buf, 32) != 0) {
// 			printk("Password didn't match\n");
// 			err = -EACCES;
// 			goto end;
// 		}
// 		bytes_left = bytes_left - read_bytes;
// 	}

// 	//Creating temp file for writing ecrypted/decypted bytes
// 	strcat(temp_file, ".tmp");
// 	temp_filp = filp_open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0);
// 	temp_filp->f_inode->i_mode  = in_filp->f_inode->i_mode; 
//     if (IS_ERR(temp_filp)) {
// 		printk("error occurred while opening temp file %s",temp_file);
// 		err =  (int) PTR_ERR(temp_filp);
// 		goto end;
//     }

// 	temp_filp->f_pos = 0;

	
// 	if (flag == 1){  //ENCRYPTION : Writing hash to file header
// 		write_bytes = kernel_write(temp_filp, input->keybuf, strlen(input->keybuf) , &temp_filp->f_pos);
// 		if (write_bytes <0){
// 			printk("unable to write hash bytes.\n");
// 			parital_op_flag = 1;
// 			err  = -EIO;
// 			goto end;
// 		}
// 	}

// 	//Allocating buffer for reading writing data between files
// 	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
//   	if (buf == NULL) { 
// 		parital_op_flag = 1;
// 		err = -ENOMEM;
// 		goto end;
//  	}


// 	//Allocating ivdata for iv in files
// 	ivdata = kmalloc(16, GFP_KERNEL);
//     if (!ivdata) {
// 		parital_op_flag = 1;
//         printk("could not allocate ivdata\n");
//         goto end;
//     }
// // #ifndef EXTRA_CREDIT
// // 	memcpy(ivdata,"mallikaraiOSbyte", 16);
// // 	printk("fixed ivdata : %s\n", ivdata);
// // #endif

// 	while(bytes_left > 0)
// 	{
// 		printk("Looping through files and copying/ecrypting/decrypting buffers\n");
// 		//Encryption : Writing random ivdata to outfile
// 		if (flag==1){
// 		#ifdef EXTRA_CREDIT
// 			get_random_bytes(ivdata, 16);
// 			printk("randomly iv generated : %s\n", ivdata);
// 		#endif
// 			printk("Writing iv to ecryption file\n");
// 			write_bytes = kernel_write(temp_filp, ivdata, 16 , &temp_filp->f_pos);
// 			if (write_bytes <0){
// 				printk("error occured while writing bytes to temp file.\n");
// 				parital_op_flag = 1;
// 				err  = -EIO;
// 				goto end;
// 			}
// 		}
// 		//Decryption : Reading ivdata from infile
// 		else if (flag ==2){
// 			read_bytes = kernel_read(in_filp, ivdata, 16 , &in_filp->f_pos);
// 			if (read_bytes <0){
// 				printk("unable to read ivdata bytes.\n");
// 				parital_op_flag = 1;
// 				err  = -EIO;
// 				goto end;
// 			}
// 			bytes_left = bytes_left - read_bytes;
// 		}

// 		//Read block of clear text (Encryption) or cipher text (Decryption)
// 		read_bytes = kernel_read(in_filp, buf, PAGE_SIZE, &in_filp->f_pos);
// 		if (read_bytes <0){
// 			printk("unable to read bytes.\n");
// 			parital_op_flag = 1;
// 			err  = -EIO;
// 			goto end;
// 		}
// 		bytes_left = bytes_left-read_bytes;

// 		//Encrypting/decrypting block of data
// 		if (flag!=4){
// 			printk("Attempting to encrypt/decrypt file.\n");
// 			err = encypt_decrypt_func(input->keybuf, buf, read_bytes, flag, ivdata);
// 			if (err!=0){
// 				parital_op_flag = 1;
// 				printk("Error occured while performing file encryption/decryption.\n");
// 				goto end;
// 			}
// 		}
		
// 		//write bytes to temp output file
// 		write_bytes = kernel_write(temp_filp, buf, read_bytes, &temp_filp->f_pos);
// 		if (write_bytes <0){
// 			printk("error occured while writing bytes to temp file.\n");
// 			parital_op_flag = 1;
// 			err  = -EIO;
// 			goto end;
// 		}

// 		printk("bytes_left: %d\n",bytes_left);
// 		page_count++;
// 		printk("Page no: %ld", page_count);
// 	}
	
// 	//Storing reference to dentry for file rename and unlinking
// 	temp_dentry = temp_filp->f_path.dentry;
// 	out_dentry = out_filp->f_path.dentry;

// 	if (bytes_left>0){
// 		parital_op_flag = 1;
// 		printk("Error occured during file encryption/decryption/copy.\n");
// 		err = -ENOSYS;
// 		goto end;
// 	}
// 	else{
// 		printk("Renaming temp file to output file\n");
// 		err = vfs_rename(temp_dentry->d_parent->d_inode, temp_dentry, out_dentry->d_parent->d_inode, out_dentry, NULL,0);
// 		printk("error : %d\n",  err);
// 		if(err!=0){
// 			printk("Error occured while renaming file.\n");
// 			parital_op_flag = 1; 
// 			goto end;
// 		}
// 		printk("Successfully performed file encryption/decryption/copy.\n");
// 	}

// 	end:
// 		printk("Error: %d\n",err);
// 		if (parital_op_flag ==1){
// 			printk("Deleting partial temp output file\n");
// 			unlink_success = vfs_unlink(temp_dentry->d_parent->d_inode, temp_dentry, NULL);
// 			if(unlink_success!=0){
// 				printk("Error occured while unlinking partial output file.\n");
// 				err = unlink_success;
// 			}
// 		}

// 		if(ivdata!=NULL)
// 			kfree(ivdata);

// 		if(hash_buf!=NULL)
// 			kfree(hash_buf); 
	
// 		if (buf!=NULL)
// 			kfree(buf);
		
// 		if (in_file!=NULL && !IS_ERR(in_file))
// 			putname(in_file);
			
// 		if (out_file!=NULL && !IS_ERR(out_file))
// 			putname(out_file);	
		
// 		if(in_filp!=NULL && !IS_ERR(in_filp))
// 			filp_close(in_filp, NULL);
		
// 		if(out_filp!=NULL && !IS_ERR(out_filp))
// 			filp_close(out_filp, NULL);

// 		if(temp_filp!=NULL && !IS_ERR(temp_filp))
// 			filp_close(temp_filp, NULL);
			

// 		return err;
// }



static int param_validation(struct job_args *args){
	int err = 0;

	//4. Check for NULL arguments
	if ((args->input_file == NULL) || (args->output_file==NULL)){
		err = -EINVAL;
		printk("Invalid input.\n");
		goto end;
	}

	// //5. Flag checks  
	// if (input->flags!=1 && input->flags!=2 && input->flags!=4){
	// 	err = -EINVAL;
	// 	printk("Invalid operation flag.\n");
	// 	goto end;
	// }

	// if ((input->flags==4) && (input->keylen>0)){
	// 	err = -EINVAL; 
	// 	printk("Copy does not require password.\n");
	// 	goto end;
	// }

	if (input->flags!=4 && (input->keylen < 6 ||input->keybuf == NULL)) {
		printk("Invalid password. Password should be at least 6 chars long\n");
		err = -EINVAL;
		goto end;
	}


	end:
		return err;
}
