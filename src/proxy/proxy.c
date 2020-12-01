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

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s portnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}


int main(int argc,  char *argv[])
{
    struct tls_config *config = NULL;
    struct tls *ctx, *cctx = NULL;

    uint8_t *mem;
    size_t memlen;

    if (tls_init() != 0) 
        err(1, "tls_init:");

    printf("TLS initialized.\n");
    
    // set config
    config = tls_config_new();
    if (config == NULL)
        err(1, "tls_config_new:");

    printf("Created new tls_config.\n");

    // set root certificate
    mem = tls_load_file("../../certificates/root.pem", &memlen, NULL);
    if (mem == NULL)
        err(1, "tls_load_file(root):");

    if (tls_config_set_ca_mem(config, mem, memlen) != 0)
        err(1, "tls_config_set_ca_mem:");

    printf("Root certificate set.\n");

    // set server certificate
    mem = tls_load_file("../../certificates/server.crt", &memlen, NULL);
    if (mem == NULL)
        err(1, "tls_load_file(server_cert):");

    if (tls_config_set_cert_mem(config, mem, memlen) != 0)
        err(1, "tls_config_set_cert_mem:");

    printf("Proxy certificate set.\n");

    // set server private key
    // specify password = 'proxy-server-pass' because we load a private key instead of a certificate
    mem = tls_load_file("../../certificates/server.key", &memlen, "proxy-server-pass");
    if (mem == NULL)
        err(1, "tls_load_file(server_key):");

    if (tls_config_set_key_mem(config, mem, memlen) != 0)
        err(1, "tls_config_set_key_mem:");

    printf("Proxy private key set.\n");

    // proxy context
    ctx = tls_server();
    if (ctx == NULL)
        err(1, "tls_client:");

    printf("Created client context.\n");

    // apply config to context
    if (tls_configure(ctx, config) != 0)
        err(1, "tls_configure:");

    printf("Applied config to context.\n");

// -------------------------------------------------------------------

	struct sockaddr_in sockname, client;
	char writebuf[80], readbuf[80], *ep;
	struct sigaction sa;
	int sd;
	socklen_t clientlen;
	u_short port;
	pid_t pid;
	u_long p;
    int readlen, writelen;

	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 2)
		usage();
		errno = 0;
        p = strtoul(argv[1], &ep, 10);
        if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[1]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[1]);
		usage();
	}
	/* now safe to do this */
	port = p;

	/* the message we send the client */
	strlcpy(writebuf,
	    "What is the air speed velocity of a coconut laden swallow?\n",
	    sizeof(writebuf));

	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	sd=socket(AF_INET,SOCK_STREAM,0);
	if ( sd == -1)
		err(1, "socket failed");

	if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(sd,3) == -1)
		err(1, "listen failed");

	/*
	 * we're now bound, and listening for connections on "sd" -
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

	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
	printf("Server up and listening for connections on port %u\n", port);
	for(;;) {
		int clientsd;
		clientlen = sizeof(&client);
		clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
		if (clientsd == -1)
			err(1, "accept failed");

        // convert socket to tls
        if (tls_accept_socket(ctx, &cctx, clientsd) != 0)
            err(1, "tls_accept_socket %s", tls_error(ctx));

        printf("Socket is now tls.\n");

		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		 */

		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
            writelen = tls_write(cctx, writebuf, sizeof(writebuf));
            if (readlen < 0)
                err(1, "tls_read: %s", tls_error(cctx));

            if (tls_close(cctx) != 0)
                err(1, "tls_close: %s", tls_error(cctx));
            
            tls_free(cctx);
            tls_free(ctx);
            tls_config_free(config);
			close(clientsd);

            printf("Memory freed, exiting.\n");
			exit(0);
		}
		close(clientsd);
	}
}