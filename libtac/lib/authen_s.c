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

/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 */
int tac_authen_send(int fd, const char *user, char *pass, char *tty)
{
#ifdef CONFIG_PD3
	HDR *th;		/* TACACS+ packet header */
	struct authen_start tb;	/* start message body */
	int user_len, port_len, pass_len, bodylength, w;
	int pkt_len;
	u_char *pkt;
	int ret = 0;

	session_id = 0; /* Grant us a new session ID */

	th = _tac_req_header(TAC_PLUS_AUTHEN);

	/* set some header options */
	th->version = TAC_PLUS_VER_0;
	th->encryption = tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', pass '%s', tty '%s', encrypt: %s",
		  __FUNCTION__, user, pass, tty,
		  (tac_encryption) ? "yes" : "no"))

	/* get size of submitted data */
	user_len = strlen(user);
	port_len = strlen(tty);
	pass_len = strlen(pass);

	syslog(LOG_INFO, "session id %d\n", th->session_id);

	/* fill the body of message */
	tb.action = TAC_PLUS_AUTHEN_LOGIN;
	tb.priv_lvl = TAC_PLUS_PRIV_LVL_USR;
	tb.authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
	tb.service = TAC_PLUS_AUTHEN_SVC_LOGIN;
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
	bcopy(user, pkt + pkt_len, user_len);	/* user */
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

#else
#error "CONFIG_PD3 not defined!"
 	HDR *th; 		 /* TACACS+ packet header */
 	struct authen_start tb; /* message body */
 	int user_len, port_len, chal_len, mdp_len, token_len, bodylength, w;
 	int pkt_len=0;
	int ret=0;
	char *chal = "1234123412341234";
	char digest[MD5_LEN];
	char *token;
 	u_char *pkt, *mdp;
	MD5_CTX mdcontext;

 	th=_tac_req_header(TAC_PLUS_AUTHEN);

 	/* set some header options */
	if(strcmp(tac_login,"login") == 0) {
 		th->version=TAC_PLUS_VER_0;
	} else {
 		th->version=TAC_PLUS_VER_1;
	}
 	th->encryption=tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', tty '%s', encrypt: %s", \
		 __FUNCTION__, user, tty, \
	 	(tac_encryption) ? "yes" : "no"))	 
	
	if(strcmp(tac_login,"chap") == 0) {
		chal_len = strlen(chal);
		mdp_len = sizeof(u_char) + strlen(pass) + chal_len;
		mdp = (u_char *) xcalloc(1, mdp_len);
		mdp[0] = 5;
		memcpy(&mdp[1], pass, strlen(pass));
		memcpy(mdp + strlen(pass) + 1, chal, chal_len);
		MD5Init(&mdcontext);
		MD5Update(&mdcontext, mdp, mdp_len);
		MD5Final((u_char *) digest, &mdcontext);
		free(mdp);
		token = xcalloc(1, sizeof(u_char) + 1 + chal_len + MD5_LEN);
		token[0] = 5;
		memcpy(&token[1], chal, chal_len);
		memcpy(token + chal_len + 1, digest, MD5_LEN);
	} else {
		token = pass;
	}

 	/* get size of submitted data */
 	user_len=strlen(user);
 	port_len=strlen(tty);
 	token_len=strlen(token);

 	/* fill the body of message */
 	tb.action=TAC_PLUS_AUTHEN_LOGIN;
 	tb.priv_lvl=TAC_PLUS_PRIV_LVL_USR;
	if(strcmp(tac_login,"chap") == 0) {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP;
	} else if(strcmp(tac_login,"login") == 0) {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII;
	} else {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_PAP;
	}

	if (!strcmp(user, "$enable$"))
		tb.service=TAC_PLUS_AUTHEN_SVC_ENABLE;
	else
		tb.service=TAC_PLUS_AUTHEN_SVC_LOGIN;

 	tb.user_len=user_len;
 	tb.port_len=port_len;
 	tb.rem_addr_len=0;          /* may be e.g Caller-ID in future */
#ifdef CONFIG_PD3
 	/* No password should be send on START packets */
 	if (!strcmp(tac_login, "login"))
 		tb.data_len = 0;
 	else
 		tb.data_len=token_len;

 	/* fill body length in header */
 	 bodylength=sizeof(tb) + user_len + port_len;
#else
  	tb.data_len=token_len;
  	/* fill body length in header */
 	bodylength=sizeof(tb) + user_len + port_len + token_len; /* + rem_addr_len */

#endif




 	th->datalength= htonl(bodylength);

 	/* we can now write the header */
 	w=write(fd, th, TAC_PLUS_HDR_SIZE);
	if(w < 0 || w < TAC_PLUS_HDR_SIZE) {
		syslog(LOG_ERR, "%s: short write on header: wrote %d of %d: %m", 
						__FUNCTION__, w, TAC_PLUS_HDR_SIZE);
		free(th);
		return -1;
	}

 	/* build the packet */
 	pkt=(u_char *) xcalloc(1, bodylength+10);

 	bcopy(&tb, pkt+pkt_len, sizeof(tb)); /* packet body beginning */
 	pkt_len+=sizeof(tb);
 	bcopy(user, pkt+pkt_len, user_len);  /* user */
 	pkt_len+=user_len;
 	bcopy(tty, pkt+pkt_len, port_len);   /* tty */
 	pkt_len+=port_len;
 	/* No password on START packets */
#ifndef CONFIG_PD3
 	bcopy(token, pkt+pkt_len, token_len);  /* password */
 	pkt_len+=token_len;
#endif

 	/* pkt_len == bodylength ? */
	if(pkt_len != bodylength) {
		syslog(LOG_ERR, "%s: bodylength %d != pkt_len %d",
					__FUNCTION__, bodylength, pkt_len);
		ret=-1;
	} 
 	
	/* encrypt the body */
 	_tac_crypt(pkt, th, bodylength);

 	w=write(fd, pkt, pkt_len);
	if(w < 0 || w < pkt_len) {
		syslog(LOG_ERR, "%s: short write on body: wrote %d of %d: %m",
					   __FUNCTION__, w, pkt_len);
		ret=-1;
	}
#endif
	free(pkt);
	free(th);

	return(ret);
} /* tac_authen_send */
