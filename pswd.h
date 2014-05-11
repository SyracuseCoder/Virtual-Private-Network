//////////////////////////////////////////////////////////////////////
//	Virtual Private Network Project		 							//
//									By: Yiming Xiao, May 2014		//												
//	File name: pswd.h												//
//////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define HASH_SIZE 32

void my_print(unsigned char* str, int size){
	int i;
	for(i=0; i<size; i++){
		printf("%x", str[i]);
	}
}

int my_strcmp(unsigned char* str1, unsigned char* str2, int size){
	int i=0; 
	int ret = 1;	// all same return 1
	for(i=0; i<size; i++){
		if(str1[i]!=str2[i]){
			ret = 0;
			break;
		}
	}
	return ret;
}

int hash(char* msg,char* hash_name, unsigned char* ret, int* retlen){
	EVP_MD_CTX* mdctx;
	const EVP_MD* md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	int md_len;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hash_name);
	if(!md){
		printf("unknown message digest %s\n", hash_name);
		return -1;
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, strlen(msg));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	*retlen = md_len;
	EVP_MD_CTX_destroy(mdctx);
	int i=0;
	for(i=0; i<md_len; i++)
		ret[i] = md_value[i];	
	return 0;
}

typedef struct passwd{
	char filename[20];
	char hashname[20];
	int fd;
} pswd_t; 

int init_pswd(pswd_t* pswd, char* filename){
	strcpy(pswd->filename, filename);
	strcpy(pswd->hashname, "sha256");
	pswd->fd = open(pswd->filename, O_RDWR|O_APPEND|O_CREAT, S_IRUSR|S_IWUSR);
	if(pswd->fd==-1)
		return -1;
	else
		return 0;
}		

int destroy_pswd(pswd_t* pswd){
	return close(pswd->fd);
}

int add_entry(pswd_t* pswd, char* username, char* passwd){
	int existed = 0;
	unsigned char buf[1024];
	unsigned char ret[1024];
	int retlen;
	hash(username, "sha256", ret, &retlen);
	//my_print(ret, retlen);
	if(lseek(pswd->fd, 0, SEEK_SET)==-1){
		perror("lseek");
		exit(1);
	}
	while(1){
		int nread = read(pswd->fd, buf, HASH_SIZE*2);
		if(nread==-1){
			perror("read");
			return -1;
		}else if(nread==0){
			break;
		}else if(my_strcmp((unsigned char*)ret,(unsigned char*) buf, HASH_SIZE)==1){
			existed = 1;
			break;
		}
	}
	if(existed){
		printf("username existed!\n");
		return -1;
	}
	if(lseek(pswd->fd, 0, SEEK_END)==-1){
		perror("lseek");
		exit(1);
	}
	//write(pswd->fd, ret, retlen);
	char buf1[retlen];
	memcpy(buf1, ret, retlen);
	write(pswd->fd, buf1, retlen);
	char tmp[1024];
	strcpy(tmp, username);
	strcat(tmp, passwd);
	hash(tmp, "sha256", ret, &retlen);
	//write(pswd->fd, ret, retlen);
	char buf2[retlen];
	memcpy(buf2, ret, retlen);
	write(pswd->fd, buf2, retlen);
	//printf("%s\n", buf2);
	return 0;
}

int authenticate(pswd_t* pswd, char* username, char* passwd){
	char buf[1024];
	unsigned char buf2[1024];
	unsigned char ret1[1024];
	unsigned char ret2[1024];
	int retlen1;
	int retlen2;
	hash(username, "sha256", ret1, &retlen1);
	char tmp[1024];
	strcpy(tmp, username);
	strcat(tmp, passwd);
	hash(tmp, "sha256", ret2, &retlen2);
	int found = 0;
	if(lseek(pswd->fd, 0, SEEK_SET)==-1){
                perror("lseek");
                exit(1);
        }

	while(1){	
		int nread = read(pswd->fd, buf, HASH_SIZE*2);
		//memcpy(buf2, buf, nread);	
		if(nread==-1){
			perror("read from password file");
			exit(1);
		}else if(nread==0)
			break;	
		else{	
			memcpy(buf2, buf, nread);
			if(my_strcmp(ret1, buf2, HASH_SIZE)==1 && my_strcmp(ret2, buf2+HASH_SIZE, HASH_SIZE)==1){
				found = 1;
				break;
			}
		}
	}
	return found;		// return 1 means valid
}












