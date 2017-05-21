all: server.cpp client.cpp Makefile
	gcc -fPIC -c queue.c -g
	gcc -shared -g -o libqueue.so queue.o 
	g++ server.cpp tools.cpp -g -o server -L. -lqueue -lcrypto #/usr/lib/i386-linux-gnu/libcrypto.so.1.0.0
	g++ client.cpp tools.cpp -g -o client -L. -lqueue -lcrypto #/usr/lib/i386-linux-gnu/libcrypto.so.1.0.0
