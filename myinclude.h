//////////////////////////////////////////////////////////////////////
//	Virtual Private Network Project		 							//
//									By: Yiming Xiao, May 2014		//												
//	File name: myinclude.h											//	
//	This file defines some message used as flags in the socket 		//										
//	connections as well as some functions shared by struct client   //
//	and struct server.											    //
//////////////////////////////////////////////////////////////////////
#ifndef _MYINCLUDE_H
#define _MYINCLUDE_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <pthread.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <signal.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// define some global parameters
#define KEY_SIZE	16
#define BUFSIZE	30720
#define SHA256_LEN 32

// hard-code the location of some certificates, this is easy for debugging
#define CACERT		"./ca.crt"
#define SER_CERT	"./server.crt"
#define SER_KEY		"./server.key"
#define COMMON_NAME 	"PKILabServer.com"

// define some message flags used in the socket connection
#define SERVER_GOT_SESSION_KEY	"server|got|session|key!!!"
#define USER_AUTHENTICATE_SUCCESS	"user|authenticate|success!!!"
#define USER_AUTHENTICATE_START		"user|autehnticate|start!!!"
#define VERIFIED_USER			"verified|user!!!"
#define UNVERIFIED_USER			"unverifed|user!!!"
#define CLIENT_SHUTDOWN			"client|shut|down!!!"

// define some micros to handle library call and system call error
#define PERROR(x) do { perror(x);exit(1);} while(0)
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

// define my own IP_header, there's one thing special:
// when analysing the packets after unpacking in the kernel, I found the first
// 16bytes are not used, thus, the source IP and dest IP will be 16 bytes behind the 
// normal address.
// In my case, ip_dst will be the source ip and sdst will be the dest ip.
struct IP_Header{
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
	struct  in_addr sdst;
};

void encrypt_hash(char* buf, int nread, int* len, unsigned char* key, unsigned char* iv);

void errExit(char* msg){
	perror(msg);
	exit(EXIT_FAILURE);
}

int getRand(){
        unsigned int seed;
        FILE* urandom = fopen("/dev/urandom", "r");
        fread(&seed, sizeof(int), 1, urandom);
        fclose(urandom);
        srand(seed);
        return rand();
}

// this function is used to generate a true randomized sequence of bytes.
// this function is less efficient and will be updated later...
void rand_key(unsigned char* key, int size){
        int i=0;
        for(i=0; i<size; i++){
                key[i] = (unsigned char)(getRand()%255);
        }
}

// get_tun_fd is used to set up a virtual network interface
int get_tun_fd(){
	int fd;
    struct ifreq ifr;
    if ( (fd = open("/dev/net/tun",O_RDWR)) < 0)
		errExit("opne tun");
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;
    strncpy(ifr.ifr_name, "toto%d", IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
		errExit("ioctl");
    printf("Allocated interface %s. Configure and use it\n", ifr.ifr_name);
	system("sh config.sh");
	return fd;
}

int start_channel(int tfd, int fd, int s, int* pfd,  unsigned char* key, unsigned char* iv,
                                struct sockaddr_in* from, int* fromlen   ){
        struct sockaddr_in sout;
        int soutlen = sizeof(sout);
        fd_set fdset;
		while (1) {
                FD_ZERO(&fdset);
                FD_SET(fd, &fdset);
                FD_SET(s, &fdset);
                int maxfd = fd > s ? fd:s;
                if (select(maxfd+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
                if (FD_ISSET(fd, &fdset)) {
                        char buffer[BUFSIZE];
                        int nread = 0;
                        int buf_len = 0;
                        if((nread = read(fd, buffer, BUFSIZE))==-1)
                                PERROR("read fd");
                        encrypt_hash( buffer, nread, &buf_len, key, iv);
                        if (sendto(s, buffer, buf_len, 0, (struct sockaddr *)from, *fromlen) < 0)
                                PERROR("sendto");
                        
                } else if(FD_ISSET(s, &fdset)) {
                        char buffer[BUFSIZE];
                        int nrecv = 0, buf_len = 0;
                        nrecv = recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr *)&sout, &soutlen);
                        if(decrypt_hash(buffer, nrecv,&buf_len, key)==-1){
                                printf("start1: receiving unauthenticated message!\n");
                                continue;
                        }
                        if (write(tfd, buffer, buf_len) < 0) PERROR("write");
                        
                }
        }
        return 0;
}

void encrypt_hash(char* buf, int nread, int* len, unsigned char* key, unsigned char* iv){
        char* plain_txt = buf;
        int plain_len = nread;
        char ebuf[BUFSIZE];
        int elen = 0;
        int plen = 0;
        int len1 = 0;
        int len2 = 0;

        rand_key(iv, KEY_SIZE);

        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(&ctx, ebuf, &elen, plain_txt, plain_len);
        EVP_EncryptFinal(&ctx, ebuf + elen, &plen);
        EVP_CIPHER_CTX_cleanup(&ctx);

        len1 = elen + plen;
        char* buf1 = malloc(len1+KEY_SIZE);
        memcpy(buf1+KEY_SIZE, ebuf, len1);
        memcpy(buf1, iv, KEY_SIZE);
        len1 = len1+KEY_SIZE;

        char* buf2 = malloc(SHA256_LEN);
        int md_len;
	    HMAC_CTX mdctx;
        HMAC_CTX_init(&mdctx);
        HMAC_Init_ex(&mdctx, key, 16, EVP_sha256(), NULL);
        HMAC_Update(&mdctx, buf1, len1);
        HMAC_Final(&mdctx, buf2, &md_len);
        HMAC_CTX_cleanup(&mdctx);

        memcpy(buf, buf1, len1);
        memcpy(buf+len1, buf2, SHA256_LEN);
        *len = len1 + SHA256_LEN;
}

int decrypt_hash(char* buf, int nrecv, int* len, unsigned char* key){
        unsigned char iv2[KEY_SIZE];
        char* buf2 = malloc(SHA256_LEN);
        int md_len;
        HMAC_CTX mdctx;
        HMAC_CTX_init(&mdctx);
        HMAC_Init_ex(&mdctx, key, 16, EVP_sha256(), NULL);
        HMAC_Update(&mdctx, buf, nrecv-SHA256_LEN);
        HMAC_Final(&mdctx, buf2, &md_len);
        HMAC_CTX_cleanup(&mdctx);

        int i=0;
        int same = 1;
        for(i=0; i<SHA256_LEN; i++){
                if(buf2[i]!=buf[nrecv-SHA256_LEN+i]){
                        same = 0;
                        break;
                }
        }
        if(same==0)
                return -1;
        memcpy(iv2,buf, KEY_SIZE);
        int plen, len1;
        char pbuf[BUFSIZE];
        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv2);
        EVP_DecryptUpdate(&ctx, pbuf, &len1, buf+KEY_SIZE, nrecv-SHA256_LEN-KEY_SIZE);
        plen = len1;
        EVP_DecryptFinal_ex(&ctx, pbuf+plen, &len1);
        plen+=len1;
        EVP_CIPHER_CTX_cleanup(&ctx);
        *len = plen;
        memcpy(buf, pbuf, plen);
        return 0;
}
#endif






