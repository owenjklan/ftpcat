/* FTPcat - stream data over an FTP connetion to a remote server.
 * 
 * Written by Owen Klan  -  18th June, 2003
 */

/* UPDATES:
 * 28th June 2003  - Removed password entry from command line (with -P
 *                   option to allow specifying password on cmd. line)
 *                 - Added option to stream from FTP server to stdout
 *                 - Fixed directory traversal issues
 *                 - Added '-k' option to keep data retrieved from a
 *                   server during a server-to-stdout transfer
 * 2nd July 2003   - Fixed '-k' option
 *                 - Added '-p' option to specify server port number
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/utsname.h>	       /* For uname() */
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>		       /* For umask() */
#include <libgen.h>		       /* For dirname() */

/* Function prototypes */
void usage();
unsigned short resolve_port(char *pstr);
unsigned long resolve_ip(char *ipstr);
void empty_response(int s);
int setup_transfer(int s, struct sockaddr_in *a,
		   char *uname, char *pass, char *rname);
int get_reply_code();
unsigned short get_next_port(int s);
void parse_args(int argc, char *argv[]);
char *my_basename(char *path);


#define get_server_reply(s)     memset(server_reply, 0x00, BUFFER_MAX); \
                                recv(s, server_reply, BUFFER_MAX-1, 0); \
                                empty_response(s);                      \
                                if (show_replies)                       \
                                  fprintf(stderr, "<< %s", server_reply);

#define BUFFER_MAX   1024

/* Error return codes */
#define SYSTEM_ERROR -1		       /* System failure occurred */
#define SERVER_ERROR -2		       /* Server failure occurred */

/* This buffer will hold the last server reply */
char server_reply[BUFFER_MAX];
unsigned long myip = 0;
unsigned short server_port = 21;
int show_replies = 0;		       /* Show server replies */
int direct_send = 1;		       /* 0 = retrieve file */
char *pw = NULL;		       /* Password, if given on cmd. line */
int keeper_fd = 0;		       /* If this is non-zero then it is a
					* file descriptor to save to when using
					* the '-k' option. If required, this
					* will be opened in parse_args(). */

int main(int argc, char *argv[])
{
    unsigned char readbuff[BUFFER_MAX];
    int bytes_read;
    int total_bytes = 0;
    struct sockaddr_in addr;
    int sock;
    int acptsock = 0;
    int datasock = 0;
    int addrlen = sizeof(struct sockaddr_in);
    int retval;
    
    if (argc < 4) {
	usage();
	return 1;
    }
    if (argc > 4) {
	parse_args(argc, argv);
    }
    
    memset(server_reply, 0x00, BUFFER_MAX);
    
    /* Setup the address structure */
    addr.sin_port = htons(server_port);
    addr.sin_family = AF_INET;
    if((addr.sin_addr.s_addr = resolve_ip(argv[1])) == 0) {
	fprintf(stderr, "Failed determining IP address for %s! %s\n",
		argv[1], strerror(errno));
	return 1;
    }
    
    /* If the source address wasn't specified on the command line,
     * try to determine it using hostname as returned by uname()
     * syscall. */
    if (myip == 0) {
	struct utsname un;
	
	uname(&un);
	if ((myip = resolve_ip(un.nodename)) == 0) {
	    fprintf(stderr, "Unable to determine local IP address!\n");
	    return 1;
	}
	myip = ntohl(myip);
    }
    
    /* Get a file descriptor to send on */
    if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
	fprintf(stderr, "Failed obtaining socket for connection! %s\n",
		strerror(errno));
	return 1;
    }
    
    /* Setup the transfer, this includes everything but actual
     * send/receive of data */
    if ((retval = setup_transfer(sock, &addr, argv[3],
				 pw, argv[2])) < 0) {
	if (retval == SERVER_ERROR)
	    fprintf(stderr, "Transfer setup failed! Server returned:\n%s\n",
		    server_reply);
	else if (retval == SYSTEM_ERROR)
	    fprintf(stderr, "Transfer setup failed! System error:\n%s\n",
		    strerror(errno));
	close(sock);
	exit(1);
    } else {
	acptsock = retval;	       /* We have a valid connetion socket */
    }
    
    /* Now, accept the connection from the server */
    datasock = accept(acptsock, (struct sockaddr *)&addr, &addrlen);
    
    /* Now read data from stdin and stream it to stdout *OR* if
     * direct_send is == 0, retrieve data and write it to stdout */
    if (direct_send) {		       /* Send data */
	while ((bytes_read = read(STDIN_FILENO, readbuff, BUFFER_MAX)) > 0) {
	    if (send(datasock, readbuff, bytes_read, 0) < bytes_read) {
		fprintf(stderr, "Failed sending data! %s\n", strerror(errno));
		break;	
	    }
	    total_bytes += bytes_read;
	};
	if (bytes_read < 0) {	       /* < 0 indicates error */
	    fprintf(stderr, "Read from stdin failed! %s\n", strerror(errno));
	} else {
	    /* Verify that all was sent okay */
	    close(datasock);	       /* close data connection */
	    get_server_reply(sock);
	    if (get_reply_code() == 226)
		fprintf(stderr, "%d bytes sent to server\n", total_bytes);
	}
    } else {			       /* Retrieve data */
	while ((bytes_read = recv(datasock, readbuff, BUFFER_MAX, 0)) > 0) {
	    if (write(STDOUT_FILENO, readbuff, bytes_read) < bytes_read) {
		fprintf(stderr, "Failed writing to stdout! %s\n",
			strerror(errno));
		break;
	    }
	    
	    /* If the global 'keeper_fd' is non-zero then we are to save
	     * retrieved data to a disk file as we get it. If for some
	     * reason an error occurs while saving to the keeper file,
	     * we will close it an keep receiving anyway. */
	    if (keeper_fd > 0) {
		int bw = 0;
		int bytes_to_write = bytes_read;
		
		while (bytes_to_write) {
		    if ((bw = write(keeper_fd, readbuff, bytes_to_write)) < 0) {
			fprintf(stderr, "Failed writing to local save file! "
				"%s\n", strerror(errno));
			fprintf(stderr, "Save to file has been aborted but "
				"data transfer is continuing...\n");
			close(keeper_fd);
			keeper_fd = 0;     /* Don't save to file anymore */
			break;
		    }
		    bytes_to_write -= bw;
		    fsync(keeper_fd);
		}
	    }
	    total_bytes += bytes_read;
	};
	if (bytes_read < 0) {	       /* < 0 indicates error */
	    fprintf(stderr, "Receive from %s failed! %s\n", argv[1],
		    strerror(errno));
	} else {		       /* Verify all was received okay */
	    close(datasock);	       /* Close data connection */
	    get_server_reply(sock);
	    if (get_reply_code() == 226)
		fprintf(stderr, "%d bytes received from server\n", total_bytes);
	}
    }
    
    /* Cleanup */
    if (keeper_fd)
	close(keeper_fd);
    
    close(sock);
    
    if (datasock)
	close(datasock);
    
    return 0;
}

/* This procedure makes the connection to the remote server. It logs us
 * in and changes to the necessary directory, determines what port we
 * will listen on, sends the PORT command and if all goes well, will
 * return the socket descriptor to use for the upcoming server connection.
 * A negative return value indicates failure.
 */
int setup_transfer(int s, struct sockaddr_in *a,
		   char *uname, char *pass, char *rname)
{
#define show_request()         if (show_replies)			\
	fprintf(stderr, ">> %s", buff);
    char buff[BUFFER_MAX];
    unsigned short port = 1024;
    int lsock;
    int temp_reply;
    char *pw = NULL;
    char *rname_copy = NULL;
    
    /* Try to get a local socket before anything else */
    if ((lsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	return SYSTEM_ERROR;
    
    /* Perform connect */
    if (connect(s, (struct sockaddr *)a, sizeof(struct sockaddr_in)) < 0)
	return SYSTEM_ERROR;
    
    get_server_reply(s);
    if (get_reply_code() != 220)
	return SERVER_ERROR;
    
    /* Now login, send user command first */
    snprintf(buff, BUFFER_MAX, "USER %s\r\n", uname);
    show_request();
    if (send(s, buff, strlen(buff), 0) < strlen(buff))
	return SYSTEM_ERROR;
    
    get_server_reply(s);
    if (get_reply_code() != 331)       /* 331 is okay */
	return SERVER_ERROR;
    
    /* Get password if one wasn't passed in */
    if (pass == NULL)
	pw = getpass("Password: ");
    else
	pw = pass;
    
    /* Send password command */
    snprintf(buff, BUFFER_MAX, "PASS %s\r\n", pw);
    if (show_replies)
	fprintf(stderr, ">> PASS ***\n");
    if (send(s, buff, strlen(buff), 0) < strlen(buff))
	return SYSTEM_ERROR;
    
    /* Zero the password quickly now */
    memset(pw, 0x00, strlen(pw));
    
    get_server_reply(s);
    if (get_reply_code() != 230)       /* 230 means "login successful" */
	return SERVER_ERROR;
    
    /* Set binary transfer type */
    snprintf(buff, BUFFER_MAX, "TYPE I\r\n");
    show_request();
    if (send(s, buff, strlen(buff), 0) < strlen(buff))
	return SYSTEM_ERROR;
    /* Check that the type was set correctly */
    get_server_reply(s);
    if (get_reply_code() != 200)
	return SERVER_ERROR;
    
    /* Now try to change to the remote directory */
    rname_copy = strdup(rname);
    snprintf(buff, BUFFER_MAX, "CWD %s\r\n", dirname(rname_copy));
    if (rname_copy) free(rname_copy);
    
    show_request();
    
    if (send(s, buff, strlen(buff), 0) < strlen(buff))
	return SYSTEM_ERROR;    
    
    get_server_reply(s);
    if (get_reply_code() != 250)
	return SERVER_ERROR;
    
    /* Now try to bind a local port for the server to connect to */
    /* Get the next available port */
    if ((port = get_next_port(lsock)) == 0) {
	close(lsock);
	return SYSTEM_ERROR;
    }
    
    /* Now send the port command */
    snprintf(buff, BUFFER_MAX, "PORT %d,%d,%d,%d,%d,%d\r\n",
	     (unsigned int)(myip & 0xFF000000) >> 24,
	     (int)(myip & 0xFF0000) >> 16, (int)(myip & 0xFF00) >> 8,
	     (int)(myip & 0xFF), (port & 0xFF00) >> 8, port & 0xFF);
    show_request();
    if (send(s, buff, strlen(buff), 0) < strlen(buff)) {
	close(lsock);
	return SYSTEM_ERROR;
    }
    
    get_server_reply(s);
    temp_reply = get_reply_code();
    
    if (temp_reply > 500 && temp_reply < 600) {
	close(lsock);
	return SERVER_ERROR;
    };
    
    //	if (get_reply_code() != 200) {
    //		close(lsock);
    //		return SERVER_ERROR;
    //  }
    
    /* Now, let's ask to store or retrieve as necessary... */
    if (direct_send)
	snprintf(buff, BUFFER_MAX, "STOR %s\r\n", my_basename(rname));
    else
	snprintf(buff, BUFFER_MAX, "RETR %s\r\n", my_basename(rname));
    show_request();
    if (send(s, buff, strlen(buff), 0) < strlen(buff)) {
	close(lsock);
	return SYSTEM_ERROR;
    }
    
    /* Finally, check how the server responded to our request */
    get_server_reply(s);
    if (get_reply_code() >= 500) {
	close(lsock);
	return SERVER_ERROR;
    }
    
    /* All things are good. Now we return the local socket ready to
     * call accept on and start sending data to the server from stdin.
     */
    
    return lsock;
#undef show_request
}

/* My own version of basename(). It is important to note that this function
 * does not allocate any memory and simply returns a value which is
 * path + the offset to the last '/' character. DO NOT FREE THE RETURNED
 * POINTER!!! */
char *my_basename(char *path)
{
    int offset;
    char *p = path;
    if (!path) return NULL;
    
    offset = strlen(path);
    
    p += offset;
    
    while (p > path) {
	if (*p-- == '/') {
	    p += 2;
	    break;
	}
    }
    
    return p;
}

/* Procedure that reads the beginning of the server reply buffer for the
 * return code */
int get_reply_code()
{
    int code;
    int rmml = 0;
    
    if (server_reply[3] == '-') {
	server_reply[3] = ' ';
	rmml = 1;
    }
    sscanf(server_reply, "%3d", &code);
    
    if (rmml)
	server_reply[3] = '-';
    return code;
}

/* Function that keeps trying bind and listen on a port until we find
 * one that's not in use. Returns zero on failure */
unsigned short get_next_port(int s)
{
    struct sockaddr_in laddr;
    unsigned short port = 1024;	       /* Start here */
    
    laddr.sin_addr.s_addr = 0;
    laddr.sin_family      = AF_INET;
    
    errno = 0;
    for (; port < 65535; port++) {
	laddr.sin_port        = htons(port);

	if (bind(s, (struct sockaddr *)&laddr,
		 sizeof(struct sockaddr_in)) < 0) {
	    if (errno == EADDRINUSE)       /* In use */
		continue;
	    return 0;
	}
	if (listen(s, 1) < 0) {
	    if (errno == EADDRINUSE)
		continue;
	    return 0;
	} else {
	    return port;
	}
    }
    
    return 0;
}

/* Procedure that will continue receiving data until the terminating <CRLF>
 * has been received. */
void empty_response(int s)
{
    char temp_buffer[1024];
    
    while (recv(s, temp_buffer, 1024, MSG_DONTWAIT) > 0
	   && errno == EAGAIN);
}

/* Procedure that parses additional command line arguments */
void parse_args(int argc, char *argv[])
{
    int cur_arg = 4;
    
    for (; cur_arg < argc; cur_arg++) {
	if (strncmp(argv[cur_arg], "-a", 2) == 0) {
	    if (cur_arg == argc - 1) {
		fprintf(stderr, "Expected address after \"-a\" flag!\n");
	    } else  {
		myip = ntohl(resolve_ip(argv[cur_arg + 1]));
		cur_arg++;
		continue;
	    }
	}
	if (strncmp(argv[cur_arg], "-k", 2) == 0) {
	    if (cur_arg == argc - 1) {
		fprintf(stderr, "Expected file name after \"-k\" flag!\n");
	    } else {
		/* Try and open the "keeper file" */
		umask(0);
		if ((keeper_fd = open(argv[cur_arg + 1],
				      O_RDWR | O_TRUNC | O_CREAT,
				      0644)) <= 0) {
		    fprintf(stderr, "Could not open %s! %s\n",
			    argv[cur_arg + 1], strerror(errno));
		    exit(1);
		}
	    }
	    continue;
	}
	if (strncmp(argv[cur_arg], "-i", 2) == 0) {
	    show_replies = 1;
	    continue;
	}
	if (strncmp(argv[cur_arg], "-P", 2) == 0) {
	    if (cur_arg == argc - 1) {
		fprintf(stderr, "Expected value for password on "
			"command line!\n");
		pw = NULL;	       /* Will prompt for password then */
	    } else {
		pw = argv[cur_arg + 1];
		cur_arg++;
		continue;
	    }
	}
	if (strncmp(argv[cur_arg], "-p", 2) == 0) {
	    if (cur_arg == argc - 1) {
		fprintf(stderr, "Expected value for port on "
			"command line!\n");
	    } else {
		server_port = resolve_port(argv[cur_arg + 1]);
		cur_arg++;
		continue;
	    }
	}
	if (strncmp(argv[cur_arg], "-r", 2) == 0) {
	    direct_send = 0;
	    continue;
	}
	if (strncmp(argv[cur_arg], "-s", 2) == 0) {
	    direct_send = 1;
	    continue;
	}
    }
}

/* Function that takes a string and attempts to convert it to a port
 * value. Tries to resolve it as a service name first. Returns port in
 * host byte order. */
unsigned short resolve_port(char *pstr)
{
    struct servent *srv;
    unsigned short port = 0;
    
    if (!pstr)  return 0;
    
    /* If the first character's a digit, don't bother with getservbyname() */
    if (isdigit(*pstr)) {
	port = strtoul(pstr, NULL, 0);
    } else {
	if ((srv = getservbyname(pstr, "tcp")) == NULL) {
	    return 0;
	}
	port = ntohs((unsigned short)srv->s_port);
    }
    
    return port;
}

/* Function that takes a string and attempts to convert it to an IP
 * address. */
unsigned long resolve_ip(char *ipstr)
{
    struct hostent *host;
    
    if ((host = gethostbyname(ipstr)) == NULL) {
	return 0;
    }
    
    return *(unsigned long *)(host->h_addr);
}

/* Display usage information */
void usage()
{
    fprintf(stdout, "USAGE:  ftpcat server rname uname [options ...]\n");
    fprintf(stdout, "Valid options are:\n");
    fprintf(stdout, "  -a address         Use address as the source address"
	    " for this connection.\n");
    fprintf(stdout, "                     Suitable for multihomed hosts.\n");
    fprintf(stdout, "  -k file            Save data received with '-r' "
	    "option into the file given.\n");
    fprintf(stdout, "  -i                 Show server replies.\n");
    fprintf(stdout, "  -p port            Use the given port number for "
	    "the remote server.\n");
    fprintf(stdout, "  -P password        Provide password on command line."
	    " Use of this option is not"
	    "                     recommended!\n");
    fprintf(stdout, "  -r                 Retrieve file from server and write"
	    " to stdout.\n");
    fprintf(stdout, "  -s                 Send data from stdin to server"
	    " (default).\n");
}
