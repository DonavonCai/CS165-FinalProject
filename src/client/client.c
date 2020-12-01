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

/* client.c  - the "classic" example of a socket client */
#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>

#include <netdb.h>
#include "../murmur3/murmur3.h"

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s proxyportnumber filename\n", __progname);
	exit(1);
}

void getIP(char* IPbuffer) {

}

int main(int argc, char *argv[])
{
    // socket reading and writing
	struct sockaddr_in server_sa;
	char buffer[80], *ep;
	size_t maxread;
	u_short port;
	u_long p;
	int sd;
    int readlen, writelen;

    // tls
    struct tls_config *config = NULL;
    struct tls *ctx = NULL;
    uint8_t *mem;
    size_t mem_len;

    // ip, port, proxyport, filename
    char hostbuffer[256];
    char *ip;
    struct hostent *host_entry; 
    int hostname;

    char *proxyport;
    char *filename;

    if (argc != 3)
		usage();

    // get IP address
    hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
    host_entry = gethostbyname(hostbuffer);  
    ip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));

    // get port
    p = strtoul(argv[1], &ep, 10);
    if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "port: %s - not a number\n", argv[1]);
	}
    if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		fprintf(stderr, "port: %s - value out of range\n", argv[1]);
		usage();
	}
	/* now safe to do this */
	port = p;

    // Setup tls
    if (tls_init() != 0) 
        err(1, "tls_init:");

    printf("TLS initialized.\n");
    
    // set config
    config = tls_config_new();
    if (config == NULL)
        err(1, "tls_config_new:");

    printf("Created new tls_config.\n");

    // set root certificate
    if (tls_config_set_ca_file(config, "../../certificates/root.pem") != 0)
        err(1, "tls_config_set_ca_file:");

    printf("Root certificate set.\n");

    // client context
    ctx = tls_client();
    if (ctx == NULL)
        err(1, "tls_client:");

    printf("Created client context.\n");

    // apply config to context
    if (tls_configure(ctx, config) != 0)
        err(1, "tls_configure: %s", tls_error(ctx));

    printf("Applied config to context.\n");	

	// set up "server_sa" to be the location of the server
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(ip);
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", ip);
		usage();
	}

	// ok now get a socket. we don't care where... 
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed");

	// connect the socket to the server described in "server_sa" 
	if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa))
	    == -1)
		err(1, "connect failed");

    printf("Connected socket to a proxy.\n");

    // Upgrade socket to tls
    if (tls_connect_socket(ctx, sd, "localhost") != 0)
        err(1, "tls_connect_socket: %s", tls_error(ctx));

    printf("Socket upgraded to tls connection.\n");


    //read object names from file
	char objectNames[100][100];
	for (int i = 0; i < 100; ++i) {
		objectNames[i][0] = 0;
	}
	FILE* objectFile;
	objectFile = fopen(argv[2], "r");
	if (objectFile == 0) {
		err(1, "Error opening file");
	}
	for (int i = 0; fgets(objectNames[i], 100, objectFile) != 0; ++i) {}
	fclose(objectFile);
	

    //determine which proxy to ask for each object using Rendezvous hashing
	char proxyNames[5][10] = { "p1", "p2", "p3", "p4", "p5" };//Assuming 5 proxies
	int proxyChoices[100];//proxyChoice[i] will contain the index for the proxy to use for objectName[i]
	for (int i = 0; objectNames[i][0]; ++i) {
		char namesToHash[5][100];
		uint32_t hashes[5];
		uint32_t largestHashVal = 0;
		unsigned char largestHashIndex = 0;
		for (int j = 0; j < 5; ++j) {
			strcpy(namesToHash[j], objectNames[i]);
			strcat(namesToHash[j], proxyNames[j]);//Append proxy name to object name
			MurmurHash3_x86_32 (namesToHash[j], sizeof(namesToHash[j]), 0, hashes + j);//hash the resulting string
			if (hashes[j] > largestHashVal) {
				largestHashVal = hashes[j];//keep track of the largest hash
				largestHashIndex = j;
			}
		}
		proxyChoices[i] = largestHashIndex;//choose the proxy that resulted in the largest hash value
		printf("Object: %s, will be retrieved from proxy %d \n", objectNames[i], proxyChoices[i] + 1);
	}
	
    // TODO: tls_handshake()

    // TODO: send filename to proxy
	/*
	 * finally, we are connected. find out what magnificent wisdom
	 * our server is going to send to us - since we really don't know
	 * how much data the server could send to us, we have decided
	 * we'll stop reading when either our buffer is full, or when
	 * we get an end of file condition from the read when we read
	 * 0 bytes - which means that we pretty much assume the server
	 * is going to send us an entire message, then close the connection
	 * to us, so that we see an end-of-file condition on the read.
	 *
	 * we also make sure we handle EINTR in case we got interrupted
	 * by a signal.
	 */
    
    // Read from server
    readlen = tls_read(ctx, buffer, sizeof(buffer));
    if (readlen < 0)
        err(1, "tls_read: %s", tls_error(ctx));
	/*
	 * we must make absolutely sure buffer has a terminating 0 byte
	 * if we are to use it as a C string
	 */

	buffer[readlen] = '\0';

    // TODO: display contents of requested file

	printf("Server sent:  %s",buffer);

    if (tls_close(ctx) != 0)
        err(1, "tls_close: %s", tls_error(ctx));
    tls_free(ctx);
    tls_config_free(config);

    printf("Memory freed, exiting.\n");
	close(sd);
	return(0);
}
