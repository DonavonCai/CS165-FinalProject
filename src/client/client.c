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

unsigned char isWhiteSpace(const char *s)
{
    while (*s) {
        if (!isspace(*s))
            return 0;
        s++;
    }
    return 1;
}

void getIp(char **ip) {
    printf("get ip called\n");
    char hostbuffer[256];
    struct hostent *host_entry;
    char *temp;
    int hostname;
    hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
    host_entry = gethostbyname(hostbuffer);
    printf("setting ip...\n");
    *ip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));
    printf("ip set\n");
}

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

int main(int argc, char *argv[])
{
    // socket reading and writing
	struct sockaddr_in server_sa;
    struct sockaddr_in servers[5];
	char buffer[500];
	size_t maxread;
	int sd;
    ssize_t w, r;
    int sockets[5];

    // tls
    struct tls_config *config = NULL;
    struct tls *proxies[5];
    unsigned char completedHandshakes[5];

    // ip, port
    char *ip;
	u_short port;
    unsigned long int ports[5];


    // Objects from file
    const int MAX_OBJLEN = 500;
    char object[MAX_OBJLEN];
    memset(object, '\0', sizeof(object));

    // Hashing
    char proxyNames[5][10] = { "p1", "p2", "p3", "p4", "p5" };//Assuming 5 proxies
    int proxyChoice;//proxyChoice will contain the index for the proxy to use for object
    char namesToHash[5][MAX_OBJLEN];
    uint32_t hashes[5];
    uint32_t largestHashVal = 0;
    int largestHashIndex = 0;
    int i;
    
    if (argc != 3)
    	usage(); 

    // get ip
    getIp(&ip);

    // get port
    port = getPort(argv[1]);

    // NOTE: client expects each proxy's port to be 1 more than the last
    // get 5 ports
    for (i = 0; i < 5; i++) {
        ports[i] = port + i;
    }

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
    for (i = 0; i < 5; i++) {
        proxies[i] = tls_client();
        if (proxies[i] == NULL)
            err(1, "tls_client:");

        // apply config to context
        if (tls_configure(proxies[i], config) != 0)
            err(1, "tls_configure: %s", tls_error(proxies[i]));

        completedHandshakes[i] = 0;
     }

    printf("Created 5 client contexts.\n");
    
    // 5 proxies
    for (i = 0; i < 5; i++) {
        memset(&servers[i], 0, sizeof(servers[i]));
        servers[i].sin_family = AF_INET;
        servers[i].sin_port = htons(ports[i]);
        servers[i].sin_addr.s_addr = inet_addr(ip);
        if (servers[i].sin_addr.s_addr == INADDR_NONE) {
		    fprintf(stderr, "Invalid IP address %s\n", ip);
		    usage();
	    }
    }

    // get 5 sockets, upgrade to tls
    for (i = 0; i < 5; i++) {
        if ((sockets[i]=socket(AF_INET,SOCK_STREAM,0)) == -1)
            err(1, "socket failed");

        // connect the socket to the server described in "server_sa" 
        if (connect(sockets[i], (struct sockaddr *)&servers[i], sizeof(servers[i]))
            == -1)
            err(1, "connect failed");

        // Upgrade socket to tls
        if (tls_connect_socket(proxies[i], sockets[i], "localhost") != 0)
            err(1, "tls_connect_socket: %s", tls_error(proxies[i]));

        // handshake
        int status;
        status = tls_handshake(proxies[i]);
        if (status != 0)
            err(1, "tls_handshake: %s", tls_error(proxies[i]));
    }

    // Open file
    FILE *fptr;
    if ((fptr= fopen(argv[2], "r")) == NULL)
        err(1, "fopen:");

    // Main loop: read line from file
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
        
        //determine which proxy to ask for each object using Rendezvous hashing 
		largestHashVal = 0;
		largestHashIndex = 0;
        for (i = 0; i < 5; ++i) {
            strcpy(namesToHash[i], object);
            strcat(namesToHash[i], proxyNames[i]);//Append proxy name to object name
            MurmurHash3_x86_32 (namesToHash[i], strlen(namesToHash[i]), 0, hashes + i);//hash the resulting string
            if (hashes[i] > largestHashVal) {
                largestHashVal = hashes[i];//keep track of the largest hash
                largestHashIndex = i;
            }
            proxyChoice = largestHashIndex;//choose the proxy that resulted in the largest hash value
        }
		printf("Get Object: %s, From Proxy: %d \n", object, proxyChoice + 1);

        // send filename to proxy
        w = tls_write(proxies[proxyChoice], object, strlen(object));
        if (w < 0)
            err(1, "tls_write: %s", tls_error(proxies[proxyChoice])); 

        // display contents of requested file
        maxread = sizeof(buffer) - 1;
        memset(buffer, '\0', sizeof(buffer));
        
        r = -1;
        while (r <= 1) {
            r = tls_read(proxies[proxyChoice], buffer, maxread);   

            if (r < 0)
                err(1, "tls_read: %s", tls_error(proxies[proxyChoice]));
            //printf("R IS: %d\n", r);
        }

        buffer[r] = '\0';

        if(strncmp(buffer, "__DENY__", 8) == 0)
            printf("Object %s is forbidden\n", object);
        else
            printf("Reply for %s: %s\n", object, buffer);
    }
    
    char done[9] = "__DONE__";
    for (i = 0; i < 5; i++) {
        w = tls_write(proxies[i], done, sizeof(done));
        if (w < 0)
            err(1, "tls_write(done): %s", tls_error(proxies[i]));
    
        if (tls_close(proxies[i]) != 0)
            err(1, "tls_close: %s", tls_error(proxies[i]));

        close(sockets[i]);
    }
	return 0;
}
