//////////////////////////////////////////////////////////////////////
//	Virtual Private Network Project		 							//
//									By: Yiming Xiao, May 2014		//												
//	File name: server.h												//
//////////////////////////////////////////////////////////////////////
#ifndef _SERVER_H
#define _SERVER_H

#include "myinclude.h"
#include "pswd.h"

struct client_info{
	int valid;
	int fd[2];
	struct in_addr addr;
};

typedef struct server{
	int listen_sd;
	int port;
	int cur_udp_port;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	SSL_CTX* ctx;	
	int tfd;
	pswd_t* passwd;
	SSL* ssl[1024];	

	struct client_info arr[1024];	
	int arr_size;
	
}server_t;

int start_channel2(server_t* server, int tfd, int fd, int s, int* pfd,  unsigned char* key, unsigned char* iv,
                                struct sockaddr_in* from, int* fromlen   );

int init_server(server_t* server, int port, char* cacert, char* sercert, char* serkey){
	int i=0;
	for(i=0; i<1024; i++)
		server->arr[i].valid = 0;	
	server->arr_size  = 0;
	server->tfd = get_tun_fd();
	server->passwd = malloc(sizeof(pswd_t));
	init_pswd(server->passwd, "./password");
	server->port = port;
	server->cur_udp_port = port+1;
	//const SSL_METHOD* meth;
	SSL_load_error_strings();
  	SSLeay_add_ssl_algorithms();
	const SSL_METHOD* meth = SSLv23_server_method();
  	server->ctx = SSL_CTX_new (meth);
  	if (!server->ctx) {
	    ERR_print_errors_fp(stderr);
	    exit(2);
	}

  	SSL_CTX_set_verify(server->ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
	if(cacert==NULL){
		SSL_CTX_load_verify_locations(server->ctx,CACERT,NULL);
  		if (SSL_CTX_use_certificate_file(server->ctx, SER_CERT, SSL_FILETYPE_PEM) <= 0) {
    			ERR_print_errors_fp(stderr);
    			exit(3);
  		}
  		if (SSL_CTX_use_PrivateKey_file(server->ctx, SER_KEY, SSL_FILETYPE_PEM) <= 0) {
    			ERR_print_errors_fp(stderr);
    			exit(4);
  		}
  		if (!SSL_CTX_check_private_key(server->ctx)) {
    			fprintf(stderr,"Private key does not match the certificate public key\n");
    			exit(5);
  		}
	}else{
		SSL_CTX_load_verify_locations(server->ctx,cacert,NULL);

	        if (SSL_CTX_use_certificate_file(server->ctx, sercert, SSL_FILETYPE_PEM) <= 0) {
       		         ERR_print_errors_fp(stderr);
               		 exit(3);
        	}
	        if (SSL_CTX_use_PrivateKey_file(server->ctx, serkey, SSL_FILETYPE_PEM) <= 0) {
       		         ERR_print_errors_fp(stderr);
               		 exit(4);
        	}
	        if (!SSL_CTX_check_private_key(server->ctx)) {
       		         fprintf(stderr,"Private key does not match the certificate public key\n");
               		 exit(5);
        	}
	}
}

struct arg{
	server_t* server;
	int sd;
	struct sockaddr_in client;
};

struct arg2{
	server_t* server;
	SSL* ssl;
	int ind;
};

void* listen_shutdown(void* var){
	sleep(1);
	struct arg2* arg = (struct arg2*)var;
	SSL* ssl = arg->ssl;
	server_t* server = arg->server;
	int ind = arg->ind;
	while(1){
		char buf[1024];
		int nread;
		if(ssl!=NULL)
			nread = SSL_read(ssl, buf, 1023);
		if(nread==-1)
			errExit("SSL read in shutdown");	
		buf[nread] = '\0';
		if(strcmp(buf, CLIENT_SHUTDOWN)==0){
			server->arr[ind].valid = 0;
			free(arg);
			break;
		}
		sleep(1);
	}
	return NULL;
}

void* produce_udp_server(void* var){
	struct arg* args = (struct arg*)var;
	server_t* server = args->server;
	struct sockaddr_in* client = &(args->client);
	int sd = args->sd;
	SSL* ssl = server->ssl[server->arr_size];
	ssl = SSL_new(server->ctx);	CHK_NULL(ssl);
	SSL_set_fd(ssl, sd);
	int err = SSL_accept(ssl); 	CHK_SSL(err);
	char username[1024];
	char password[1024];
	memset(username, 0, 1024);
	memset(password, 0, 1024);
	int nread1, nread2;
	nread1 = SSL_read(ssl, username, 1024);
	nread2 = SSL_read(ssl, password, 1024);
	if(authenticate(server->passwd, username, password)==1){
		char reply[1024] = VERIFIED_USER;
		SSL_write(ssl, reply, 1024);
	}
	else{
		char reply[1024] = UNVERIFIED_USER;
		SSL_write(ssl, reply, 1024); 
		return NULL;
	}
	memset(username, 0, 1024);
	memset(password, 0, 1024);	
	char buf[20];
	memset(buf, 0, 20);
	sprintf(buf, "%d", server->cur_udp_port);
	SSL_write(ssl, buf, 20);
	printf("produce a udp server...\n");	
	
	char skey[KEY_SIZE];
	SSL_read(ssl, skey, 1024);
	unsigned char key[KEY_SIZE];
	memcpy(key, skey, KEY_SIZE);
	struct sockaddr_in sin, sout;	
	sout.sin_family = AF_INET;
	sout.sin_port = htons(server->cur_udp_port);
	memcpy(&sout.sin_addr, &client->sin_addr, sizeof(client->sin_addr));	
	
	int *pfd1;
	if(pipe(server->arr[server->arr_size].fd)==-1)
		errExit("pipe in server");
	pfd1 = server->arr[server->arr_size].fd;
	
	int s = socket(PF_INET, SOCK_DGRAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	printf("Latest UDP connection port number: %d\n", server->cur_udp_port);
	sin.sin_port = htons(server->cur_udp_port);
	if(bind(s, (struct sockaddr*)&sin, sizeof(sin))==-1){
		printf("cur udp port: %d", server->cur_udp_port);
		errExit("bind server udp local");	
	}
	unsigned char iv[KEY_SIZE];
	int fromlen = sizeof(sout);
	server->cur_udp_port = server->cur_udp_port + 1 ;

	pthread_t t_shd;
	struct arg2* arg_shd = malloc(sizeof(struct arg2));
	arg_shd->ssl = ssl;
	arg_shd->ind = server->arr_size;
	arg_shd->server = server;

	if(pthread_create(&t_shd, NULL, listen_shutdown, arg_shd)==-1)
		errExit("listen shutdown pthread create");
	start_channel2(server, server->tfd, pfd1[0] , s, &s,key ,iv,&sout, &fromlen);
	return NULL;
}

void* dispatch(void* arg){
	server_t* server = (server_t*)arg;
	fd_set fdset;
	while(1){
	FD_ZERO(&fdset);
	FD_SET(server->tfd, &fdset);
	if(select(server->tfd+1, &fdset, NULL, NULL, NULL)==-1)
		errExit("select in dispather");
	if(FD_ISSET(server->tfd, &fdset)){
		char buffer[BUFSIZE];
                int nread = 0;
                if((nread = read(server->tfd, buffer, BUFSIZE))==-1)
                        PERROR("read fd");
                const struct IP_Header* ip;
                ip = (struct IP_Header*)buffer;
				int i=0;
                for(i=0; i<server->arr_size; i++){
                        if( memcmp(&server->arr[i].addr, &ip->sdst, sizeof(struct in_addr))==0){
                                if(write(server->arr[i].fd[1], buffer, nread)==-1)
                                        errExit("write before found");
                        }
                }

	    }
	}
	return NULL;
}

void* cmdline(void* arg){
	server_t* server = (server_t*)arg;
	for(;;){
                char cmd[50];
                printf("> input your command here:\n");
                scanf("%s",cmd);
                if(strcmp(cmd, "stop")==0){
                        printf("> Client Stopped!\n");
                }else if(strcmp(cmd,"resume")==0){

                }else if(strcmp(cmd, "exit")==0){
			int i=0;
			for(i=0; i<server->arr_size; i++)
				if(server->ssl[i] != NULL)
					SSL_shutdown(server->ssl[i]);
			close(server->listen_sd);
			for(i=0; i<server->arr_size; i++)
				if(server->ssl[i]!=NULL)
					SSL_free(server->ssl[i]);
			SSL_CTX_free(server->ctx);	
                        raise(SIGKILL);
                }else if(strcmp(cmd, "AddPassword")==0){
			char buf1[100];
			char buf2[100];
			printf("==> username:\n");
			scanf("%s", buf1);
			printf("==> password:\n");
			scanf("%s", buf2);
			if(add_entry(server->passwd, buf1, buf2)==0)
				printf("username and password added successfully!");
			else
				printf("cannot add this entry!");
			memset(buf1, 0, 100);
			memset(buf2, 0, 100);
		}

        }
	return NULL;
}

int listen_server(server_t* server){
	server->listen_sd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(server->listen_sd, "socket");
	memset(&server->sa_serv, '\0', sizeof(server->sa_serv));
	server->sa_serv.sin_family = AF_INET;
	server->sa_serv.sin_addr.s_addr = INADDR_ANY;
	server->sa_serv.sin_port = htons(server->port);
	
	if(bind(server->listen_sd, (struct sockaddr*)(&server->sa_serv), sizeof(server->sa_serv))==-1)
		errExit("bind before server listen");
	if(listen(server->listen_sd, 5)==-1)
		errExit("listen");
	int len = sizeof(struct sockaddr_in);
	int sd;

	pthread_t t;
	if(pthread_create(&t, NULL, dispatch, server)==-1)
		errExit("pthread create dispath");
	pthread_t cmd_t;
	if(pthread_create(&t, NULL, cmdline, server)==-1)
		errExit("pthread create cmdline");
		
	while(1){
		sd = accept(server->listen_sd, (struct sockaddr*)(&server->sa_cli), (socklen_t*)&len);
		puts("Connection accepted\n");
		pthread_t t1;
		struct arg* var = malloc(sizeof(struct arg));
		var->server = server;
		var->sd = sd;
		memcpy(&var->client, &server->sa_cli, sizeof(server->sa_cli));
		if(pthread_create(&t1, NULL, produce_udp_server, var)==-1)
			errExit("pthread create");
	}
}

int start_channel2(server_t* server, int tfd, int fd, int s, int* pfd,  unsigned char* key, unsigned char* iv,
                                struct sockaddr_in* from, int* fromlen   ){
        struct sockaddr_in sout;
        int soutlen = sizeof(sout);
        fd_set fdset;
        int status = 0;
        while (1) {
                FD_ZERO(&fdset);
                FD_SET(fd, &fdset);
                FD_SET(s, &fdset);
                int maxfd = fd > s ? fd:s;
                if (select(maxfd+1, &fdset,NULL,NULL,NULL) < 0) PERROR("select");
                if (FD_ISSET(fd, &fdset)/* && status==1*/) {
                        char buffer[BUFSIZE];
                        int nread = 0;
                        int buf_len = 0;
                        if((nread = read(fd, buffer, BUFSIZE))==-1)
                                PERROR("read fd");
                        encrypt_hash( buffer, nread, &buf_len, key, iv);
                        if (sendto(s, buffer, buf_len, 0, (struct sockaddr *)from, *fromlen) < 0)
                                PERROR("sendto");
                } else if(FD_ISSET(s, &fdset)/* && status==1*/) {
                        char buffer[BUFSIZE];
                        int nrecv = 0, buf_len = 0;
                        nrecv = recvfrom(s, buffer, sizeof(buffer), 0, (struct sockaddr *)&sout, &soutlen);
                        if(decrypt_hash(buffer, nrecv,&buf_len, key)==-1){
							printf("start2: receiving unauthenticated message!\n");
                                continue;
                        }
						const struct IP_Header* ip = (struct IP_Header*)buffer;
						int i=0;
						int isExisted = 0;
						for(i=0; i<server->arr_size; i++){
							if(server->arr[i].valid==1 &&
								memcmp(&(server->arr[i].addr), &(ip->ip_dst), sizeof(ip->ip_dst))==0){
								isExisted = 1;
								break;
							}
						}
						if(isExisted==0){	
							memcpy(&(server->arr[server->arr_size].addr), &(ip->ip_dst), sizeof(ip->ip_dst));   
							server->arr[server->arr_size].valid = 1;
							if(server->arr[server->arr_size].fd[0]==0 || 
								server->arr[server->arr_size].fd[1]==0)
							if(pipe(server->arr[server->arr_size].fd)==-1)
								errExit("pipe in the end");
							server->arr_size++;			
						}	
						if (write(tfd, buffer, buf_len) < 0) PERROR("write");
				}
        }
        return 0;
}
#endif






