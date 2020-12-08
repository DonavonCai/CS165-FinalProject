/*
 * Copyright (c) 2008 Bob Beck <beck@obtuse.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* server.c  - the "classic" example of a socket server */

/*
 * compile with gcc -o server server.c
 * or if you are on a crappy version of linux without strlcpy
 * thanks to the bozos who do glibc, do
 * gcc -c strlcpy.c
 * gcc -o server server.c strlcpy.o
 *
 */

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>
<<<<<<< HEAD
#include <netdb.h>
=======
#include "../murmur3/murmur3.h"
>>>>>>> 137aefb8baf82f77c2dc15839ef53e4e99738bec

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s proxyportnumber serverportnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

<<<<<<< HEAD
u_long getPort(char *argPort) {
    u_long p;
    char *ep;
    p = strtoul(argPort, &ep, 10);
    if (*argPort == '\0' || *ep != '\0') {
		// parameter wasn't a number, or was empty
		fprintf(stderr, "%s - not a number\n", argPort);
		usage();
	}
    if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
        /* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argPort);
		usage();
	}
	// now safe to do this
	return p;
}

void getIp(char **ip) {
    char hostbuffer[256];
    struct hostent *host_entry;
    char *temp;
    int hostname;
    hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
    host_entry = gethostbyname(hostbuffer);
    *ip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));
}
=======
unsigned char isWhiteSpace(const char *s)
{
    while (*s) {
        if (!isspace(*s))
            return 0;
        s++;
    }
    return 1;
}

void insert_BF(unsigned char *bloomFilter, char* object, int BF_SIZE); //insert object into bloom filter
int check_BF(unsigned char *bloomFilter, char* object, int BF_SIZE); //check if object is in bloom filter
>>>>>>> 137aefb8baf82f77c2dc15839ef53e4e99738bec

int main(int argc,  char *argv[])
{
	struct sockaddr_in sockname, client, server_sa;
	char writebuf[80], readbuf[80];
	struct sigaction sa;
	int csd;
	socklen_t clientlen;
	u_short server_port, port;
	pid_t pid;
    int i;

    struct tls_config *config, *s_config = NULL;
    struct tls *ctx, *c_ctx, *s_ctx = NULL;
    int clientsd, serversd;
    char *ip;
    int readlen, writelen;

    int proxyNum;

	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 3)
		usage();

    // read port numbers from argv
    port = getPort(argv[1]);
    server_port = getPort(argv[2]);

    // Initialize tls
    if (tls_init() != 0) 
        err(1, "tls_init:");

    printf("TLS initialized.\n");

    // Configure as proxy ---------------------------------
    // proxy context
    ctx = tls_server();
    if (ctx == NULL)
        err(1, "tls_client:");

    // proxy config
    config = tls_config_new();
    if (config == NULL)
        err(1, "tls_config_new:");

    // set root certificate
    if (tls_config_set_ca_file(config, "../../certificates/root.pem") != 0)
        err(1, "tls_config_set_ca_mem:");

    // set server certificate
    if (tls_config_set_cert_file(config, "../../certificates/server.crt") != 0)
        err(1, "tls_config_set_cert_file:");

    // set server private key
    if (tls_config_set_key_file(config, "../../certificates/server.key") != 0)
        err(1, "tls_config_set_key_file:");

    // apply config to context
    if (tls_configure(ctx, config) != 0)
        err(1, "tls_configure:");

    // Configure as client ------------------------------------------
    s_ctx = tls_client();
    if (s_ctx == NULL)
        err(1, "tls_client: %s", tls_error(s_ctx));

    s_config = tls_config_new();
    if (s_config == NULL)
        err(1, "tls_config_new(s_config):");

    if (tls_config_set_ca_file(s_config, "../../certificates/root.pem") != 0)
        err(1, "tls_config_set_ca_file:");

    if (tls_configure(s_ctx, s_config) != 0)
        err(1, "tls_configure(sctx): %s", tls_error(s_ctx));
    
    // get IP
    getIp(&ip);
    printf("got ip\n");

    // set "server_sa" to be location of the server
    memset(&server_sa, 0, sizeof(server_sa));
    server_sa.sin_family = AF_INET;
    server_sa.sin_port = htons(server_port);
    server_sa.sin_addr.s_addr = inet_addr(ip);
    if (server_sa.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid IP address %s\n", ip);
        usage();
    }

    /* 
     * Create 4 more proxy servers listening on consecutive ports
     * for a total of 5 servers
     */

    proxyNum = 1;
    for (i = 1; i < 5; i++) {
        pid = fork();
        if (pid == 0) {
            proxyNum += i;
            port += i;
            break;
        }
        else if (pid < 0) {
            fprintf(stderr, "Fork failed.\n");
        }
    }

    // get a socket
    if ((serversd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        err(1, "socket failed");

    // connect to server
    if (connect(serversd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
        err(1, "connect failed");
 
    // upgrade to tls
    if (tls_connect_socket(s_ctx, serversd, "localhost") != 0)
        err(1, "tls_connect_socket: %s", tls_error(s_ctx));

    // make csd listen for connections
	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	csd=socket(AF_INET,SOCK_STREAM,0);
	if ( csd == -1)
		err(1, "socket failed");

	if (bind(csd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(csd,3) == -1)
		err(1, "listen failed");

	/*
	 * we're now bound, and listening for connections on "csd" -
	 * each call to "accept" will return us a descriptor talking to
	 * a connected client
	 */

	/*
	 * first, let's make sure we can have children without leaving
	 * zombies around when they die - we can do this by catching
	 * SIGCHLD.
	 */
	sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
	/*
	 * we want to allow system calls like accept to be restarted if they
	 * get interrupted by a SIGCHLD
	 */
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
            err(1, "sigaction failed");

	//Open black list
	FILE *fptr;
	if ((fptr= fopen("../../src/inputFiles/blacklistedObjects.txt", "r")) == NULL)
		err(1, "fopen:");
	
	//Create Bloom Filter
	const int BLOOM_FILTER_SIZE = 7500;
	unsigned char* bloomFilter;
	bloomFilter = (unsigned char*) malloc(BLOOM_FILTER_SIZE);
	for (int i = 0; i < BLOOM_FILTER_SIZE; ++i) {//Initialize bloom filter to all zeros
		bloomFilter[i] = 0;
	}
	const int MAX_OBJLEN = 100;
	char object[MAX_OBJLEN];
	int ourProxy = (port % 5); //this is one proxy out of 5, should call ./proxy portnumber with appropriate port numbers
	
	//Read black list and only insert objects that hash into our proxy
	while (fgets(object, sizeof(object), fptr)) {
		// ignore if whitespace
		if (isWhiteSpace(object)) {
			memset(object, '\0', sizeof(object));
			break;
		}
		// null-terminate at last non-whitespace character
		char *c;
		c = object + strlen(object) - 1;
		while (c > object && isspace(*c))
			c = c - 1;
		*(c+1) = '\0';
		
		char proxyNames[5][10] = { "p1", "p2", "p3", "p4", "p5" };//Assuming 5 proxies
		int proxyChoice;//proxyChoice will contain the index for the proxy to use for object
		char namesToHash[5][100];
		uint32_t hashes[5];
		uint32_t largestHashVal = 0;
		int largestHashIndex = 0;
		for (int i = 0; i < 5; ++i) {
			strcpy(namesToHash[i], object);
			strcat(namesToHash[i], proxyNames[i]);//Append proxy name to object name
			MurmurHash3_x86_32 (namesToHash[i], strlen(namesToHash[i]), 0, hashes + i);//hash the resulting string
			if (hashes[i] > largestHashVal) {
				largestHashVal = hashes[i];//keep track of the largest hash
				largestHashIndex = i;
			}
		}
		proxyChoice = largestHashIndex;
		
		if (proxyChoice != ourProxy)//If this object does not hash into our proxy then ignore it
			continue;

		insert_BF(bloomFilter, object, BLOOM_FILTER_SIZE);
	}
	
	
	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
	printf("Proxy %d connected to main server, now listening for connections on port %u\n", proxyNum, port);
    for(;;) {
		clientlen = sizeof(&client);
		clientsd = accept(csd, (struct sockaddr *)&client, &clientlen);
		if (clientsd == -1)
			err(1, "accept failed");
    
		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
            // convert socket to tls
            if (tls_accept_socket(ctx, &c_ctx, clientsd) != 0)
                err(1, "tls_accept_socket %s", tls_error(ctx));

            // handshake with client
            int status;
            status = tls_handshake(c_ctx);
            if (status != 0)
                err(1, "tls_handshake(c_ctx): %s", tls_error(c_ctx));
            
            printf("Proxy %d: Client handshake completed\n", proxyNum);

            // handshake with server
            status = tls_handshake(s_ctx);
            if (status != 0)
                err(1, "tls_handshake(s_ctx), Proxy %d: %s", tls_error(s_ctx), proxyNum);

            printf("Proxy %d: Server handshake completed\n", proxyNum);
            
            // handle all of this client's requests
            while (1) {
                // wait to receive filename
                readlen = tls_read(c_ctx, readbuf, sizeof(readbuf));
                if (readlen < 0)
                    err(1, "tls_read: %s", tls_error(c_ctx));

                readbuf[readlen] = '\0';
                printf("Proxy %d : client wrote: %s\n", proxyNum, readbuf);

                // if client says done, exit
                if (strncmp(readbuf, "__DONE__", 8) == 0) {
                    if (tls_close(c_ctx) != 0)
                    err(1, "Proxy %d : tls_close: %s", proxyNum, tls_error(c_ctx));

                    tls_free(c_ctx);
                    tls_free(ctx);
                    tls_config_free(config);
                    close(clientsd);
			        exit(0);                
                }

                // TODO: check if file is blacklisted using bloom filter, deny if blacklisted

                // TODO: otherwise, check local cache for file

                /* TODO: if not in cache, set up TLS for server, request filename, 
                 * store in cache, then read file and send to client */

                // FIXME: proxy 4 is not successfully sending
                // maybe breaking due to multiple iterations?

                // forward the request to the main server
                writelen = tls_write(s_ctx, readbuf, sizeof(readbuf));
                if (writelen < 0)
                    err(1, "tls_write: %s", tls_error(s_ctx));

                // read the reply
                readlen = tls_read(s_ctx, readbuf, sizeof(readbuf));
                if (readlen < 0)
                    err(1, "tls_read: %s", tls_error(s_ctx));

                // then send forward the reply back to the client
                writelen = tls_write(c_ctx, readbuf, sizeof(readbuf));
                if (writelen < 0)
                    err(1, "tls_write: %s", tls_error(c_ctx));
            }                
		}
        close(clientsd);
	}
    return 0;
}

void insert_BF(unsigned char *bloomFilter, char* object, int BF_SIZE) {
	uint32_t hashes[5];
	int indexA, indexB;
	for (int i = 0; i < 5; ++i) {
		MurmurHash3_x86_32 (object, strlen(object), i, hashes + i);
		indexA = (hashes[i] % (BF_SIZE * 8)) / 8;
		indexB = (hashes[i] % (BF_SIZE * 8)) % 8;
		bloomFilter[indexA] |= (1 << indexB);
	}
	
}

int check_BF(unsigned char *bloomFilter, char* object, int BF_SIZE) {
	uint32_t hashes[5];
	int indexA, indexB;
	for (int i = 0; i < 5; ++i) {
		MurmurHash3_x86_32 (object, strlen(object), i, hashes + i);
		indexA = (hashes[i] % (BF_SIZE * 8)) / 8;
		indexB = (hashes[i] % (BF_SIZE * 8)) % 8;
		if ((bloomFilter[indexA] & (1 << indexB)) == 0) {
			return 0;
		}
	}
	return 1;
}
