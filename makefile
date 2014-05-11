INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -I$(INC) -L$(LIB) -o vpn main.c -lssl -lcrypto -ldl -pthread
test:
	gcc -I$(INC) -L$(LIB) test.c -lssl -lcrypto -ldl -pthread 
clean:
	rm vpn 
