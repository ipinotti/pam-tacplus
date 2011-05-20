/* connect.c - Open connection to server.
 * 
 * Copyright (C) 2010, Pawel Krawczyk <kravietz@ceti.pl> and
 * Jeroen Nijhof <jeroen@nijhofnet.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _AIX
  #include <sys/socket.h>
#endif

#ifndef __linux__
  #include <strings.h>
#endif

#include "tacplus.h"
#include "libtac.h"


/* Pointer to TACACS+ connection timeout */
int tac_timeout = 5;

/* Returns file descriptor of open connection
   to the first available server from list passed
   in server table.
*/
#ifdef CONFIG_PD3
int tac_connect(u_long *server, int *timeout, int servers) {
#else
int tac_connect(u_long *server, int servers) {
#endif
	struct sockaddr_in serv_addr;
	struct servent *s;
	int tries = 0;
	int fd, flags, retval;
	fd_set readfds, writefds;
	struct timeval tv;

	if(!servers) {
		syslog(LOG_ERR, "%s: no TACACS+ servers defined", __FUNCTION__);
		return(-1);
	}

	while(tries < servers) {	

 		bzero( (char *) &serv_addr, sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = server[tries];

		s=getservbyname("tacacs", "tcp");
		if(s == NULL) 
			serv_addr.sin_port = htons(TAC_PLUS_PORT);
		else
			serv_addr.sin_port = s->s_port;

		if((fd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
       	   		syslog(LOG_WARNING, 
				"%s: socket creation error for %s: %m", __FUNCTION__,
							inet_ntoa(serv_addr.sin_addr));
			tries++;
			continue;
		}

		/* put socket in non blocking mode for timeout support */
		flags = fcntl(fd, F_GETFL, 0);
		if(fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
     	  		syslog(LOG_WARNING, "%s: cannot set socket non blocking",
				 __FUNCTION__); 
			tries++;
			continue;
		}


		retval = connect(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
		if((retval < 0) && (errno != EINPROGRESS)) {
		  	syslog(LOG_WARNING,
				"%s: connection to %s failed: %m", __FUNCTION__,
						inet_ntoa(serv_addr.sin_addr));
			if(fcntl(fd, F_SETFL, flags)) {
     	  			syslog(LOG_WARNING, "%s: cannot restore socket flags",
					 __FUNCTION__); 
			}
			tries++;
			continue;
    		}

		/* set fds for select */
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		writefds = readfds;

#ifdef CONFIG_PD3
		/* set timeout seconds */
		if ((timeout[tries] > 0) && (timeout[tries] < 60))
			tv.tv_sec = timeout[tries];
		else
			tv.tv_sec = tac_timeout;
#else
		/* set timeout seconds */
		tv.tv_sec = tac_timeout;
#endif
		tv.tv_usec = 0;

		/* check if socket is ready for read or write */
		if(!select(fd+1, &readfds, &writefds, NULL, &tv)) {
     	  		syslog(LOG_WARNING, 
				"%s: connection timeout with %s : %m", __FUNCTION__,
						inet_ntoa(serv_addr.sin_addr));
			if(fcntl(fd, F_SETFL, flags)) {
     	  			syslog(LOG_WARNING, "%s: cannot restore socket flags",
					 __FUNCTION__); 
			}
			tries++;
			continue;
		}

		/* connected ok */
		if (fcntl(fd, F_SETFL, flags)) {
			syslog(LOG_WARNING, "%s: cannot restore socket flags", __FUNCTION__);
		}

		TACDEBUG((LOG_DEBUG, "%s: connected to %s", __FUNCTION__, \
			       	inet_ntoa(serv_addr.sin_addr)));

		return(fd);
	}

	/* all attempts failed */
	syslog(LOG_ERR, "%s: all possible TACACS+ servers failed", __FUNCTION__); 
	return(-1);

} /* tac_connect */

#ifdef CONFIG_PD3
int tac_connect_single(u_long server, int timeout) {
	return(tac_connect(&server, &timeout, 1));
} /* tac_connect_single */
#else
int tac_connect_single(u_long server) {
	return(tac_connect(&server, 1));
} /* tac_connect_single */
#endif
