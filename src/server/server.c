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

#include <tls.h>

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

int main(int argc,  char *argv[])
{
	struct sockaddr_in sockname, client;
	char writebuf[1024], readbuf[1024], *ep;	
    size_t maxread;
    struct sigaction sa;
	int sd;
	socklen_t clientlen;
	u_short port;
	pid_t pid;
	u_long p;

    struct tls_config *config = NULL;
    struct tls *ctx, *cctx = NULL;

	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 2)
		usage();

    errno = 0;
    port = getPort(argv[1]);

    // Initialize tls
    if (tls_init() != 0) 
        err(1, "tls_init:");

    printf("TLS initialized.\n");
    
    // set config
    config = tls_config_new();
    if (config == NULL)
        err(1, "tls_config_new:");

    // set root certificate
    if (tls_config_set_ca_file(config, "../../certificates/root.pem") != 0)
        err(1, "tls_config_set_ca_file:");

    // set server certificate
    if (tls_config_set_cert_file(config, "../../certificates/server.crt") != 0)
        err(1, "tls_config_set_cert_file:");

    // set server private key
    if (tls_config_set_key_file(config, "../../certificates/server.key") != 0)
        err(1, "tls_config_set_key_file:");

    // server context
    ctx = tls_server();
    if (ctx == NULL)
        err(1, "tls_client:");

    // apply config to context
    if (tls_configure(ctx, config) != 0)
        err(1, "tls_configure:");

    printf("TLS configured.\n");

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

		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		 */

		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
            // convert socket to tls
            if (tls_accept_socket(ctx, &cctx, clientsd) != 0)
                err(1, "tls_accept_socket %s", tls_error(ctx));
            
            // Wait for handshake from proxy
            int status;
            status = tls_handshake(cctx);
            if (status != 0)
                err(1, "tls_handshake(cctx): %s", tls_error(cctx));
            
            printf("Handshake completed\n");

            ssize_t w, r;
            while (1) {
                // Read filename from proxy.
                maxread = sizeof(readbuf) - 1;
                memset(readbuf, '\0', sizeof(readbuf));
                r = tls_read(cctx, readbuf, maxread);
                
                if (r < 0)
                    err(1, "tls_read: %s", tls_error(cctx));
               
                // null terminate buffer
                readbuf[r] = '\0'; 
                // Filename now in readbuf

                // if proxy says done, exit child process
                if (strncmp(readbuf, "__DONE__", 8) == 0) {
                    // clean up
                    if (tls_close(cctx) != 0)
                        err(1, "tls_close: %s", tls_error(cctx));

                    tls_free(cctx);
                    tls_free(ctx);
                    tls_config_free(config);
                    close(clientsd);
			        exit(0);                
                }

                printf("request: %s\n", readbuf);

                 // Send contents of file to proxy.
                memset(writebuf, '\0', sizeof(writebuf));
                strcpy(writebuf, "contents of ");
                strncat(writebuf, readbuf, sizeof(readbuf));

                printf("writebuf: %s\n", writebuf);
                w = tls_write(cctx, writebuf, strlen(writebuf));
                
                if (w < 0)
                    err(1, "tls_write: %s", tls_error(cctx));
            }
        }
        close(clientsd);
    }
}
