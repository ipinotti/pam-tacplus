/* authen_s.c - Send authentication request to the server.
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
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

#ifndef __linux__
  #include <strings.h>
#endif

#include "tacplus.h"
#include "libtac.h"
#include "md5.h"

#include <librouter/pam.h>

/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 */
int tac_authen_send(int fd, const char *service, const char *user, char *pass, char *tty)
{
	HDR *th;		/* TACACS+ packet header */
	struct authen_start tb;	/* start message body */
	int user_len, port_len, pass_len, bodylength, w;
	int pkt_len;
	u_char *pkt;
	int ret = 0;
	int enable = 0; /* Use to indicate enable authentication */
	char *enable_user = NULL;

	session_id = 0; /* Grant us a new session ID */

	th = _tac_req_header(TAC_PLUS_AUTHEN);

	/* set some header options */
	th->version = TAC_PLUS_VER_0;
	th->encryption = tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', pass '%s', tty '%s', encrypt: %s",
		  __FUNCTION__, user, pass, tty,
		  (tac_encryption) ? "yes" : "no"))

	if (!strcmp(service,"enable")) {
		enable = 1;
		enable_user = calloc(1, 64);
		librouter_pam_get_username(enable_user);
	}

	/* fill the body of message */
	tb.action = TAC_PLUS_AUTHEN_LOGIN;
	tb.authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;

	if (enable) {
		tb.service = TAC_PLUS_AUTHEN_SVC_ENABLE;
		tb.priv_lvl = librouter_pam_get_privilege();
		if ( (!strcmp(user, "admin")) || (!strcmp(user, "root")) || (tb.priv_lvl == 0) )
			tb.priv_lvl = TAC_PLUS_PRIV_LVL_MAX;
	}
	else {
		tb.service = TAC_PLUS_AUTHEN_SVC_LOGIN;
		tb.priv_lvl = TAC_PLUS_PRIV_LVL_USR;
	}


	/* get size of submitted data */

	user_len = enable ? strlen(enable_user) : strlen(user);
	port_len = strlen(tty);
	pass_len = strlen(pass);

	tb.user_len = user_len;
	tb.port_len = port_len;
	tb.rem_addr_len = 0;	/* may be e.g Caller-ID in future */
	tb.data_len = 0;	/* Not used */

	/* fill body length in header */
	bodylength = sizeof (tb) + user_len + port_len;
	th->datalength = htonl(bodylength);

	/* build the packet */
	pkt = (u_char *) xcalloc(1, TAC_PLUS_HDR_SIZE + bodylength + 10);
	pkt_len = 0;
	bcopy(th, pkt, TAC_PLUS_HDR_SIZE);	/* packet header copy */
	pkt_len += TAC_PLUS_HDR_SIZE;
	bcopy(&tb, pkt + pkt_len, sizeof (tb));	/* packet body beginning */
	pkt_len += sizeof (tb);
	bcopy(enable ? enable_user : user, pkt + pkt_len, user_len);	/* user */
	pkt_len += user_len;
	bcopy(tty, pkt + pkt_len, port_len);	/* tty */
	pkt_len += port_len;

	/* pkt_len == bodylength ? */
	if (pkt_len - TAC_PLUS_HDR_SIZE != bodylength) {
		TACDEBUG((LOG_DEBUG,
			  "tac_authen_login_send: bodylength %d != pkt_len %d",
			  bodylength, pkt_len));
	}

	/* encrypt the body */
	_tac_crypt(pkt + TAC_PLUS_HDR_SIZE, th, bodylength);

	w = write(fd, pkt, pkt_len);
	if (w < 0 || w < pkt_len) {
		TACDEBUG((LOG_ERR,
		       "%s: short write on login packet: wrote %d of %d: %m",
		       __FUNCTION__, w, pkt_len));
		ret = -1;
	}

	if (enable_user)
		free(enable_user);
	free(pkt);
	free(th);

	return(ret);
} /* tac_authen_send */
