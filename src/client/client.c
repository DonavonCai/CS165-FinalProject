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


static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s ipaddress portnumber\n", __progname);
	exit(1);
}

int main(int argc, char *argv[])
{
    struct tls_config *config = NULL;
    struct tls *ctx = NULL;

    uint8_t *mem;
    size_t mem_len;

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
    /*
    // client certificate
    if (tls_config_set_cert_file(config, "../../certificates/client.crt") != 0)
        err(1, "tls_config_set_cert_file:");
    
    printf("Client certificate set.\n");

    if (tls_config_set_key_file(config, "../../certificates/client.key") != 0)
        err(1, "tls_config_set_key_file:");

    printf("Client private key set.\n");
    */
    // client context
    ctx = tls_client();
    if (ctx == NULL)
        err(1, "tls_client:");

    printf("Created client context.\n");

    // apply config to context
    if (tls_configure(ctx, config) != 0)
        err(1, "tls_configure: %s", tls_error(ctx));

    printf("Applied config to context.\n");

// ----------------------------------------------------------------
	struct sockaddr_in server_sa;
	char buffer[80], *ep;
	size_t maxread;
	ssize_t r, rc;
	u_short port;
	u_long p;
	int sd;
    int readlen, writelen;

	if (argc != 3)
		usage();

        p = strtoul(argv[2], &ep, 10);
        if (*argv[2] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	/* now safe to do this */
	port = p;

	/*
	 * first set up "server_sa" to be the location of the server
	 */
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(argv[1]);
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
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

	printf("Server sent:  %s",buffer);

    if (tls_close(ctx) != 0)
        err(1, "tls_close: %s", tls_error(ctx));
    tls_free(ctx);
    tls_config_free(config);

    printf("Memory freed, exiting.\n");
	close(sd);
	return(0);
}
