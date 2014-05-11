//////////////////////////////////////////////////////////////////////
//	Virtual Private Network Project		 							//
//									By: Yiming Xiao, May 2014		//												
//	File name: client.h												//
//////////////////////////////////////////////////////////////////////
#ifndef _CLIENT_H
#define _CLIENT_H

#include "myinclude.h"

#define CLI_CERT	"./client.crt"
#define CLI_KEY		"./client.key"

typedef struct client{
	int cport;
	char sip[20];
	int sport;
	int status;			// 0 normal, 1 get sessionkey, 2 cannot authenticate
	struct sockaddr_in tcp_addr_c, tcp_addr_s;
	unsigned char session_key[KEY_SIZE];
	
	int sd_tcp;	
	int sd_udp;
	struct sockaddr_in sin, sout;

	SSL_CTX* ctx;
	SSL* ssl;
	SSL_METHOD* meth;
	int pfd[2];
	int tfd;
} client_t;

int init_client(client_t* client, int cport, char* sip, int sport, char* cacert, char* clicert, char* clikey){
	client->tfd = get_tun_fd();
	client->cport = cport;
	strcpy(client->sip, sip);
	client->sport = sport;
	client->status = 0;
	SSLeay_add_ssl_algorithms();
	const SSL_METHOD* meth = SSLv23_client_method();
	SSL_load_error_strings();
	client->ctx = SSL_CTX_new(meth);	
	CHK_NULL(client->ctx);
	SSL_CTX_set_verify(client->ctx, SSL_VERIFY_PEER, NULL);
	if(cacert==NULL || clicert==NULL || clikey==NULL){
		SSL_CTX_load_verify_locations(client->ctx, CACERT, NULL);
		SSL_CTX_use_certificate_file(client->ctx, CLI_CERT, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(client->ctx, CLI_KEY, SSL_FILETYPE_PEM);
	}else{
		SSL_CTX_load_verify_locations(client->ctx, cacert, NULL);
	        SSL_CTX_use_certificate_file(client->ctx, clicert, SSL_FILETYPE_PEM);
	        SSL_CTX_use_PrivateKey_file(client->ctx, clikey, SSL_FILETYPE_PEM);
	}
	SSL_CTX_check_private_key(client->ctx);
	client->sd_tcp = socket(AF_INET, SOCK_STREAM, 0);
	memset(&client->tcp_addr_s, 0, sizeof(client->tcp_addr_s));	
	client->tcp_addr_s.sin_family = AF_INET;
	client->tcp_addr_s.sin_addr.s_addr = inet_addr(sip);
	client->tcp_addr_s.sin_port = htons(sport);
	printf("Finding Server ...\n");
	while(1){	
		int ret;
		ret = connect(client->sd_tcp, (struct sockaddr*)&(client->tcp_addr_s), sizeof(client->tcp_addr_s)); 
		//printf("connecting...");
		if(ret==0)
			break;
	}
	printf("Server Found!\n");	
	client->ssl = SSL_new(client->ctx);
	CHK_NULL(client->ssl);
	SSL_set_fd(client->ssl,client->sd_tcp);
	SSL_connect(client->ssl);
	X509* server_cert = SSL_get_peer_certificate(client->ssl);
	char cn[1024];
	X509_NAME* name  = X509_get_subject_name(server_cert);
  	X509_NAME_get_text_by_NID(name, NID_commonName, cn, 1024);
	printf("> input the Common Name of certificate:\n");
	char buf_cn[1024];
	scanf("%s",buf_cn); 
  	if(strcmp(cn , buf_cn)!=0){
        	printf("common name error\n");
        	exit(1);
  	}
	printf("common name authenticated!\n");
	X509_free(server_cert);	
	return 0;
}


int send_session_key_client(client_t* client){
	rand_key(client->session_key, KEY_SIZE);
	char buf1[KEY_SIZE];
	memcpy(buf1, client->session_key, KEY_SIZE);
	SSL_write(client->ssl, buf1, KEY_SIZE);
	char buf[1024];
	int len;
	len = SSL_read(client->ssl, buf, 1023);
	if(strcmp(buf, SERVER_GOT_SESSION_KEY)==0)
		return 0;
	else
		return -1;
}	

int authenticate_client(client_t* client){
	char username[1024];
	char password[1024];
	memset(username, 0, 1024);
	memset(password, 0, 1024);
	printf("please input your username:\n");
	scanf("%s", username);
	printf("please input your password:\n");	
	scanf("%s", password);
	SSL_write(client->ssl, username, 1024);
	memset(username, 0, 1024);
	SSL_write(client->ssl, password, 1024);
	memset(password, 0, 1024);	
	char reply[1024];
	SSL_read(client->ssl, reply, 1024);
	
	if(strcmp(reply, UNVERIFIED_USER)==0){
		printf("Invalid username or password!\n");
		exit(1);
	}
	else if(strcmp(reply, VERIFIED_USER)==0){
	memset(reply, 0, 1024);
	SSL_read(client->ssl, reply, 1024);	
	printf("Server establish a UDP connection with a port number:%s \n", reply);
	rand_key(client->session_key, KEY_SIZE);
	char skey[KEY_SIZE];
	memcpy(skey, client->session_key, KEY_SIZE);
	SSL_write(client->ssl, skey, 1024);
	client->sd_udp = socket(PF_INET, SOCK_DGRAM, 0);
	client->sin.sin_family = AF_INET;
        client->sin.sin_addr.s_addr = htonl(INADDR_ANY);
        client->sin.sin_port = htons(atoi(reply));
	if(bind(client->sd_udp, (struct sockaddr*)&client->sin, sizeof(client->sin))==-1)
		errExit("bind client udp");
	client->sout.sin_family = AF_INET;
	client->sout.sin_port = htons(atoi(reply));
	inet_aton(client->sip , &client->sout.sin_addr);		
	
			
	return 0;
	}
} 

void* work(void* arg){
	client_t* client = (client_t*)arg;
	unsigned char iv[KEY_SIZE];
	int fromlen = sizeof(client->sout);
	start_channel(client->tfd, client->tfd, client->sd_udp,&client->tfd,client->session_key, iv, &client->sout, &fromlen);
	return NULL;
}

int work_client(client_t* client){
	pthread_t t1;
	pthread_create(&t1, NULL, work, client);
	for(;;){
		char cmd[50];
		printf("> input your command here:\n");
		scanf("%s",cmd);
		if(strcmp(cmd, "stop")==0){
			printf("> Client Stopped!\n");
		}else if(strcmp(cmd,"resume")==0){
		
		}else if(strcmp(cmd, "exit")==0){
			SSL_write(client->ssl, CLIENT_SHUTDOWN, strlen(CLIENT_SHUTDOWN));
			SSL_shutdown(client->ssl);
			close(client->sd_tcp);
			SSL_free(client->ssl);
			SSL_CTX_free(client->ctx);
			raise(SIGKILL);
		}

	}
	pthread_join(t1, NULL);
}






#endif
