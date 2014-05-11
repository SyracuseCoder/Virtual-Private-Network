///////////////////////////////////////////////////////////////////////////
//	Virtual Private Network Project		 		         //
//	By: Yiming Xiao, May 2014		                         //												
//	File name: main.c					         //
//	This file implements some basic command line parameters parsing	 //												
//	and utilize the functions defined in client.c and server.c       //
///////////////////////////////////////////////////////////////////////////
#include "client.h"
#include "server.h"

void print_usage(){
	printf("help\n");
}

int main(int argc, char** argv){
	char c;
	int port;
	char *ip, *p;
	char cacert[200];
	char clicert[200];
	char clikey[200];
	char sercert[200];
	char serkey[200];

	int mode = -1;
	int files = -1;
	while ((c = getopt(argc, argv, "s:c:ha:r:k:")) != -1) {
                switch (c) {
                case 'h':
			print_usage();
			return 0;
                case 's':
			mode = 1;
                        port = atoi(optarg);
                        break;
                case 'c':
                        mode = 2;
                        p = memchr(optarg,':',16);
                        if (!p) printf("invalid argument : [%s]\n",optarg);
                        *p = 0;
                        ip = optarg;
                        port = atoi(p+1);
                        break;
		case 'a':		// CA certificate
			strcpy(cacert, optarg);
			files = 1;
			break;
		case 'r':		// certificate 
			if(mode==1)
				strcpy(sercert, optarg);
			else if(mode==2)
				strcpy(clicert, optarg);
			files = 1;
			break;
		case 'k':		//private key
			if(mode==1)
				strcpy(serkey, optarg);
			else if(mode==2)
				strcpy(clikey, optarg);
			files = 1;
			break;	
                default:
                        print_usage();
                }
        }

	if(mode==1){
		server_t* server = malloc(sizeof(server_t));
		if(files==1)
			init_server(server,  port, cacert, sercert, serkey);
		else
			init_server(server, port, NULL, NULL, NULL);	
		listen_server(server);	

	}else if(mode==2){
		client_t* client = malloc(sizeof(client_t));
		if(files ==1)
			init_client(client, 0, ip, port, cacert, clicert, clikey);
		else
			init_client(client, 0, ip, port, NULL, NULL, NULL);
		authenticate_client(client);
		work_client(client);

	}else{
		
	}
	return 0;
}
