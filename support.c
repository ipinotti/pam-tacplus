/* support.c - support functions for pam_tacplus.c
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>

#ifndef __linux__
	#define _USE_IRS
#endif
#include <netdb.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#ifndef __linux__
	#include <strings.h>
#endif

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
/* #define PAM_SM_PASSWORD */

#ifndef __linux__
	#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "pam_tacplus.h"
#include "tacplus.h"
#include "libtac.h"

#ifdef CONFIG_PD3
static char conf_file[BUFFER_SIZE];	/* configuration file */
#else
unsigned long tac_srv[TAC_MAX_SERVERS];
int tac_srv_no = 0;
#endif
char *tac_service = NULL;
char *tac_protocol = NULL;
char *tac_prompt = NULL;

/* libtac */
extern char *tac_secret;
extern char *tac_login;
extern int tac_encryption;
extern int tac_timeout;

#ifndef xcalloc
void *_xcalloc (size_t size) {
	register void *val = calloc (1, size);
	if (val == 0) {
		syslog (LOG_ERR, "xcalloc: calloc(1,%u) failed", (unsigned) size);
		exit (1);
 	}
	return val;
}
#else
#define _xcalloc xcalloc
#endif

char *_pam_get_terminal(pam_handle_t *pamh) {
	int retval;
	char *tty;

	retval = pam_get_item (pamh, PAM_TTY, (void *)&tty);
	if (retval != PAM_SUCCESS || tty == NULL || *tty == '\0') {
		tty = ttyname(STDIN_FILENO);
		if(tty == NULL || *tty == '\0')
			tty = "unknown";
	}
	return(tty);
}

void _pam_log(int err, const char *format,...) {
	char msg[256];
	va_list args;

	va_start(args, format);
	vsnprintf(msg, sizeof(msg), format, args);
	openlog("PAM-tacplus", LOG_PID, LOG_AUTH);
	syslog(err, "%s", msg);
	va_end(args);
	closelog();
}


/* stolen from pam_stress */
int converse(pam_handle_t * pamh, int nargs
		,struct pam_message **message
		,struct pam_response **response) {
	int retval;
	struct pam_conv *conv;

	if ((retval = pam_get_item (pamh, PAM_CONV, (void *)&conv)) == PAM_SUCCESS) {
#if (defined(__linux__) || defined(__NetBSD__))
		retval = conv->conv (nargs, (const struct pam_message **) message
#else
		retval = conv->conv (nargs, (struct pam_message **) message
#endif
				,response, conv->appdata_ptr);
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_ERR, "(pam_tacplus) converse returned %d", retval);
			_pam_log(LOG_ERR, "that is: %s", pam_strerror (pamh, retval));
		}
	} else {
		_pam_log (LOG_ERR, "(pam_tacplus) converse failed to get pam_conv");
	}

	return retval;
}

/* stolen from pam_stress */
int tacacs_get_password (pam_handle_t * pamh, int flags
			,int ctrl, char **password) {
	char *pass = NULL;

	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;
	int retval;

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: called", __FUNCTION__);

	/* set up conversation call */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;

	if (!tac_prompt) {
		msg[0].msg = "Password: ";
	} else {
		msg[0].msg = tac_prompt;
	}
	resp = NULL;

	if ((retval = converse (pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
		return retval;

	if (resp) {
		if ((resp[0].resp == NULL) && (ctrl & PAM_TAC_DEBUG))
			_pam_log (LOG_DEBUG, "pam_sm_authenticate: NULL authtok given");
		pass = resp[0].resp;	/* remember this! */
		resp[0].resp = NULL;
	} else if (ctrl & PAM_TAC_DEBUG) {
		_pam_log (LOG_DEBUG, "pam_sm_authenticate: no error reported");
		_pam_log (LOG_DEBUG, "getting password, but NULL returned!?");
		return PAM_CONV_ERR;
	}

	free(resp);
	resp = NULL;

	*password = pass;	/* this *MUST* be free()'d by this module */

  if(ctrl & PAM_TAC_DEBUG)
	syslog(LOG_DEBUG, "%s: obtained password", __FUNCTION__);

  return PAM_SUCCESS;
}

unsigned long _resolve_name (const char *serv) {
	struct in_addr addr;
	struct hostent *h;

	if (inet_aton (serv, &addr) == 0) {
		if ((h = gethostbyname (serv)) == NULL) {
			herror("gethostbyname");
		} else {
			bcopy (h->h_addr, (char *) &addr, sizeof (struct in_addr));
			return (addr.s_addr);
		}
	} else {
		return (addr.s_addr);
	}

	return (-1);
}

int _pam_parse (int argc, const char **argv) {
	int ctrl = 0;

#ifdef CONFIG_PD3
        strcpy(conf_file, TACPLUS_CONF_FILE);
#else
        /* otherwise the list will grow with each call */
        tac_srv_no = 0;
#endif

	for (ctrl = 0; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "debug")) { /* all */
			ctrl |= PAM_TAC_DEBUG;
		} else if (!strcmp (*argv, "encrypt")) {
			ctrl |= PAM_TAC_ENCRYPT;
			tac_encryption = 1;
		} else if (!strcmp (*argv, "first_hit")) { /* authentication */
			ctrl |= PAM_TAC_FIRSTHIT;
		} else if (!strncmp (*argv, "service=", 8)) { /* author & acct */
			tac_service = (char *) _xcalloc (strlen (*argv + 8) + 1);
			strcpy (tac_service, *argv + 8);
		} else if (!strncmp (*argv, "protocol=", 9)) { /* author & acct */
			tac_protocol = (char *) _xcalloc (strlen (*argv + 9) + 1);
			strcpy (tac_protocol, *argv + 9);
		} else if (!strncmp (*argv, "prompt=", 7)) { /* authentication */
			tac_prompt = (char *) _xcalloc (strlen (*argv + 7) + 1);
			strcpy (tac_prompt, *argv + 7);
			// Replace _ with space
			int chr;
			for (chr = 0; chr < strlen(tac_prompt); chr++) {
				if (tac_prompt[chr] == '_') {
					tac_prompt[chr] = ' ';
				}
			}
		} else if (!strcmp (*argv, "acct_all")) {
			ctrl |= PAM_TAC_ACCT;
#ifdef CONFIG_PD3
		} else if (!strcmp(*argv, "cmd_acct")) {
			ctrl |= PAM_TAC_CMD_ACCT;
		} else if (!strcmp(*argv, "cmd_author")) {
			ctrl |= PAM_TAC_CMD_AUTHOR;
		} else if (!strncmp(*argv, "conf=", 5)) {
                        strcpy(conf_file, *argv + 5);
#else
		} else if (!strncmp (*argv, "server=", 7)) { /* authen & acct */
			unsigned long addr = 0;
			if(tac_srv_no < TAC_MAX_SERVERS) { 
				addr = _resolve_name (*argv + 7);
				if (addr != -1) {
					tac_srv[tac_srv_no] = addr;
					tac_srv_no++;
				} else {
					_pam_log (LOG_ERR,
						"skip invalid server: %s (h_errno %d)",
						*argv + 7, h_errno);
				}
			} else {
				_pam_log(LOG_ERR, "maximum number of servers (%d) exceeded, skipping",
					TAC_MAX_SERVERS);
			}
		} else if (!strncmp (*argv, "secret=", 7)) {
			tac_secret = (char *) _xcalloc (strlen (*argv + 7) + 1);
			strcpy (tac_secret, *argv + 7);
		} else if (!strncmp (*argv, "timeout=", 8)) {
			tac_timeout = atoi(*argv + 8);
#endif
		} else if (!strncmp (*argv, "login=", 6)) {
			tac_login = (char *) _xcalloc (strlen (*argv + 6) + 1);
			strcpy (tac_login, *argv + 6);
		} else {
			_pam_log (LOG_WARNING, "unrecognized option: %s", *argv);
		}
	}

	return ctrl;
}	/* _pam_parse */

#ifdef CONFIG_PD3
#ifndef _pam_forget
#define _pam_forget(X) if (X) {memset(X, 0, strlen(X));free(X);X = NULL;}
#endif
#ifndef _pam_drop
#define _pam_drop(X) if (X) {free(X);X = NULL;}
#endif
void cleanup(tacacs_server_t **server)
{
	tacacs_server_t *next;

	while (*server) {
		next = (*server)->next;
		_pam_drop((*server)->hostname);
		_pam_forget((*server)->secret);
		_pam_drop(*server);
		*server = next;
	}
}

int initialize(tacacs_server_t **conf)
{
	char hostname[BUFFER_SIZE];
	char secret[BUFFER_SIZE];
	char buffer[BUFFER_SIZE];
	char *p;
	FILE *fserver;
	tacacs_server_t *server = NULL;
	int timeout;
	int line = 0;
#if 0
	int ctrl = 1;		/* for DPRINT */
#else
	int ctrl = 0;		/* for DPRINT */
#endif

	/* the first time around, read the configuration file */
	strcpy(conf_file, TACPLUS_CONF_FILE);
	if ((fserver = fopen(conf_file, "r")) == (FILE *) NULL) {
		printf("Could not fopen\n");
		_pam_log(LOG_ERR, "Could not open configuration file %s: %s\n",
			 conf_file, strerror(errno));
		return PAM_ABORT;
	}

	while (!feof(fserver) &&
	       (fgets(buffer, sizeof (buffer), fserver) != (char *) NULL) &&
	       (!ferror(fserver))) {
		line++;
		p = buffer;

		/*
		 *  Skip blank lines and whitespace
		 */
		while (*p &&
		       ((*p == ' ') || (*p == '\t') ||
			(*p == '\r') || (*p == '\n')))
			p++;

		/*
		 *  Nothing, or just a comment.  Ignore the line.
		 */
		if ((!*p) || (*p == '#'))
			continue;

		timeout = 1;
#define SECRET_OPTIONAL		/* optional key for tac-server */
#ifdef SECRET_OPTIONAL
		secret[0] = 0;	/* if missing secret, use zero sized one! */
		if (sscanf(p, "%s %s %d", hostname, secret, &timeout) < 1) {
			_pam_log(LOG_ERR,
				 "ERROR reading %s, line %d: Could not read hostname\n",
#else
		if (sscanf(p, "%s %s %d", hostname, secret, &timeout) < 2) {
			_pam_log(LOG_ERR,
				 "ERROR reading %s, line %d: Could not read hostname or secret\n",
#endif
				 conf_file, line);
			continue;	/* invalid line */
		} else {	/* read it in and save the data */
			tacacs_server_t *tmp;

			tmp = malloc(sizeof (tacacs_server_t));
			if (server) {
				server->next = tmp;
				server = server->next;
			} else {
				*conf = tmp;	/* first server */
				server = tmp;	/* first time */
			}

			/* sometime later do memory checks here */
			server->hostname = strdup(hostname);
			server->secret = strdup(secret);
			if (inet_aton(server->hostname, &server->ip) <= 0) {
				_pam_log(LOG_ERR,
					 "DEBUG: invalid ip %s address.\n",
					 server->hostname);
			}

			if ((timeout < 1) || (timeout > 60)) {
				server->timeout = 1;
			} else {
				server->timeout = timeout;
			}
			server->next = NULL;
		}
	}
	fclose(fserver);

	if (!server) {		/* no server found, die a horrible death */
		if (ctrl & PAM_TAC_DEBUG)
			_pam_log(LOG_ERR,
				 "No TACACS server found in configuration file %s\n",
				 conf_file);
		return PAM_AUTHINFO_UNAVAIL;
	}
	return PAM_SUCCESS;
}
#endif
