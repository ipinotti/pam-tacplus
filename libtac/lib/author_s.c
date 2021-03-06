/* author_s.c - Send authorization request to the server.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>
#include <unistd.h>

#ifndef __linux__
#include <strings.h>
#endif

#include "tacplus.h"
#include "libtac.h"
#include "xalloc.h"

#include <librouter/defines.h>
#include <librouter/pam.h>

/* Send authorization request to the server, along with attributes
 specified in attribute list prepared with tac_add_attrib.
 */
int tac_author_send(int fd, const char *user, char *tty, struct tac_attrib *attr)
{
	HDR *th;
	struct author tb;
	u_char user_len, port_len;
	struct tac_attrib *a;
	int i = 0; /* attributes count */
	int pkt_len = 0; /* current packet length */
	int pktl = 0; /* temporary storage for previous pkt_len values */
	int w; /* write() return value */
	u_char *pkt; /* packet building pointer */
	/* u_char *pktp; *//* obsolete */
	int ret = 0;
	unsigned char *data, *d;
	int mode;

	th = _tac_req_header(TAC_PLUS_AUTHOR);

	/* set header options */
	th->version = TAC_PLUS_VER_0;
	th->encryption = tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	syslog(LOG_INFO, "TACACS+: %s: user '%s', tty '%s', encrypt: %s",
					__FUNCTION__, user,
					tty, tac_encryption ? "yes" : "no");

	user_len = (u_char) strlen(user);
	port_len = (u_char) strlen(tty);

	mode = librouter_pam_get_current_mode(FILE_PAM_LOGIN);
	switch (mode) {
	case AAA_AUTH_NONE:
		tb.authen_method = AUTHEN_METH_NONE;
		break;
	case AAA_AUTH_LOCAL:
		tb.authen_method = AUTHEN_METH_LOCAL;
		break;
	case AAA_AUTH_RADIUS:
	case AAA_AUTHOR_RADIUS_LOCAL:
		tb.authen_method = AUTHEN_METH_RADIUS;
		break;
	case AAA_AUTH_TACACS:
	case AAA_AUTH_TACACS_LOCAL:
	default:
		tb.authen_method = AUTHEN_METH_TACACSPLUS;
		break;
	}

	if (strcmp(tac_login, "chap") == 0) {
		tb.authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP;
	} else if (strcmp(tac_login, "login") == 0) {
		tb.authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
	} else {
		tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
	}

	tb.service = TAC_PLUS_AUTHEN_SVC_NONE;
	tb.priv_lvl = TAC_PLUS_PRIV_LVL_USR;

	tb.user_len = user_len;
	tb.port_len = port_len;
	tb.rem_addr_len = 0;

	/* allocate packet */
	pkt = (u_char *) xcalloc(1, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE);
	pkt_len = sizeof(tb);

	/* fill attribute length fields */
	a = attr;
	while (a) {
		/* Hack para autorizar comandos primarios (antes do ENABLE) com privilegio 1, e depois do ENABLE, com privilegio 15 ou 7*/
		/* syslog(LOG_DEBUG, "%s: user '%s', attr-> %s",__FUNCTION__, user, a->attr); */
		if (strstr(a->attr, "priv-lvl")){
			if (strstr(a->attr,"15") || strstr(a->attr,"7")){
				tb.priv_lvl = librouter_pam_get_privilege();
				if ( (!strcmp(user, "admin")) || (!strcmp(user, "root")) || (tb.priv_lvl == 0) )
					tb.priv_lvl = TAC_PLUS_PRIV_LVL_MAX;
			}
			else
				tb.priv_lvl = TAC_PLUS_PRIV_LVL_USR;
		}

		pktl = pkt_len;
		pkt_len += sizeof(a->attr_len);
		pkt = xrealloc(pkt, pkt_len);

		/* bad method: realloc() is allowed to return different pointer
		 with each call
		 pktp=pkt + pkt_len;
		 pkt_len += sizeof(a->attr_len);
		 pkt = xrealloc(pkt, pkt_len);
		 */

		bcopy(&a->attr_len, pkt + pktl, sizeof(a->attr_len));
		i++;

		a = a->next;
	}

	/* fill the arg count field and add the fixed fields to packet */
	tb.arg_cnt = i;
	bcopy(&tb, pkt, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE);

#define PUTATTR(data, len) \
	pktl = pkt_len; \
	pkt_len += len; \
	pkt = xrealloc(pkt, pkt_len); \
	bcopy(data, pkt + pktl, len);

	/* fill user and port fields */
	PUTATTR(user, user_len)
	PUTATTR(tty, port_len)

	/* fill attributes */
	a = attr;
	while (a) {
		PUTATTR(a->attr, a->attr_len)

		a = a->next;
	}

	/* finished building packet, fill len_from_header in header */
	th->datalength = htonl(pkt_len);

	/* encrypt packet body  */
	_tac_crypt(pkt, th, pkt_len);

	data = xcalloc(1, TAC_PLUS_HDR_SIZE + pkt_len);
	d = data;
	bcopy(th, d, TAC_PLUS_HDR_SIZE);
	d += TAC_PLUS_HDR_SIZE;
	bcopy(pkt, d, pkt_len);

	/* send everything  */
	w = write(fd, data, TAC_PLUS_HDR_SIZE + pkt_len);
	if (w < (TAC_PLUS_HDR_SIZE + pkt_len)) {
		syslog(LOG_ERR, "%s: author send failed: wrote %d of %d bytes", __FUNCTION__, w, pkt_len);
		ret = -1;
	}

	free(data);
	free(pkt);
	free(th);

	return (ret);
}
