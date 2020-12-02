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

int main(int argc, char *argv[])
{
    // socket reading and writing
	struct sockaddr_in server_sa;
	char buffer[80], *ep;
	size_t maxread;
	int sd;
    ssize_t w, r;

    // tls
    struct tls_config *config = NULL;
    struct tls *ctx = NULL;

    // ip, port
    char hostbuffer[256];
    char *ip;
    struct hostent *host_entry; 
    int hostname;
	u_short port;
	u_long p;

    // Objects from file
    const int MAX_OBJLEN = 100;
    char object[MAX_OBJLEN];
    memset(object, '\0', sizeof(object));

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

	/* ok now get a socket. we don't care where... */
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed");

	/* connect the socket to the server described in "server_sa" */
	if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa))
	    == -1)
		err(1, "connect failed");

    printf("Connected socket to a proxy.\n");

    // Upgrade socket to tls
    if (tls_connect_socket(ctx, sd, "localhost") != 0)
        err(1, "tls_connect_socket: %s", tls_error(ctx));

    printf("Socket upgraded to tls connection.\n");

    // TODO: tls_handshake()

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
     
     
        // TODO: determine which proxy to ask for each object using Rendezvous hashing

        // send filename to proxy
        w = tls_write(ctx, object, strlen(object));
        if (w < 0)
            err(1, "tls_write: %s", tls_error(ctx)); 

        // display contents of requested file
        maxread = sizeof(buffer) - 1;
        r = tls_read(ctx, buffer, maxread);   
    
        if (r < 0)
            err(1, "tls_read: %s", tls_error(ctx));

        buffer[r] = '\0';
        printf("Server sent:  %s\n",buffer);
    }

    char done[9] = "__DONE__";
    w = tls_write(ctx, done, sizeof(done));
    if (w < 0)
        err(1, "tls_write(done): %s", tls_error(ctx));

    if (tls_close(ctx) != 0)
        err(1, "tls_close: %s", tls_error(ctx));
    tls_free(ctx);
    tls_config_free(config);

    printf("Memory freed, exiting.\n");
	close(sd);

	return 0;
}
