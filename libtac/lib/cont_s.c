/* cont_s.c - Send continue request to the server.
 * 
 * Copyright (C) 2010, Jeroen Nijhof <jeroen@nijhofnet.nl>
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

#include "tacplus.h"
#include "libtac.h"
#include "md5.h"

/* this function sends a continue packet do TACACS+ server, asking
 * for validation of given password
 */
int tac_cont_send(int fd, char *pass)
{
	HDR *th; /* TACACS+ packet header */
	struct authen_cont tb; /* continue body */
	int pass_len, bodylength, w;
	int pkt_len = 0;
	int ret = 0;
	u_char *pkt;

	th = _tac_req_header(TAC_PLUS_AUTHEN);

	/* set some header options */
	th->version = TAC_PLUS_VER_0;
	th->seq_no = 3; /* 1 = request, 2 = reply, 3 = continue, 4 = reply */
	th->encryption = tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	/* get size of submitted data */
	pass_len = strlen(pass);

	/* fill the body of message */
	tb.user_msg_len = htons(pass_len);
	tb.user_data_len = tb.flags = 0;

	/* fill body length in header */
	bodylength = sizeof (tb) + pass_len;
	th->datalength = htonl(bodylength);

	/* build the packet */
	pkt = (u_char *) xcalloc(1, TAC_PLUS_HDR_SIZE + bodylength);
	pkt_len = 0;
	bcopy(th, pkt, TAC_PLUS_HDR_SIZE);	/* packet header copy */
	pkt_len += TAC_PLUS_HDR_SIZE;
	bcopy(&tb, pkt + pkt_len, sizeof (tb));	/* packet body beginning */
	pkt_len += sizeof (tb);
	bcopy(pass, pkt + pkt_len, pass_len);	/* passwd */
	pkt_len += pass_len;

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
		syslog(LOG_ERR,
		       "%s: short write on login packet: wrote %d of %d: %m",
		       __FUNCTION__, w, pkt_len);
		ret = -1;
	}

	free(pkt);
	free(th);

	return (ret);
} /* tac_cont_send */
