/* libtac.h
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

#ifndef _AUTH_TAC_H
#define _AUTH_TAC_H

#ifndef CONFIG_PD3
#define CONFIG_PD3
#endif

#if defined(DEBUGTAC) && !defined(TACDEBUG)
#define TACDEBUG(x)	syslog x;
#else
#define TACDEBUG(x)
#endif

/* u_int32_t support for sun */
#ifdef sun
typedef unsigned int u_int32_t;
#endif

/* version.c */
extern int tac_ver_major;
extern int tac_ver_minor;
extern int tac_ver_patch;

/* header.c */
extern int session_id;
extern int tac_encryption;
extern char *tac_secret;
extern char *tac_login;

/* connect.c */
extern int tac_timeout;
#ifdef CONFIG_PD3
extern int tac_connect(u_long *server, int *timeout, int servers);
extern int tac_connect_single(u_long server, int timeout);
#else
extern int tac_connect(u_long *server, int servers);
extern int tac_connect_single(u_long server);
#endif

/* magic.c */
extern u_int32_t magic();

/*  authen_s.c*/
extern int tac_authen_send(int fd, const char *user, char *pass, char *tty);
extern int tac_authen_read(int fd);
extern int tac_cont_send(int fd, char *pass);
extern HDR *_tac_req_header(u_char type);
extern void _tac_crypt(u_char *buf, HDR *th, int length);
extern u_char *_tac_md5_pad(int len, HDR *hdr);
extern void tac_add_attrib(struct tac_attrib **attr, char *name, char *value);
extern void tac_free_attrib(struct tac_attrib **attr);
extern int tac_account_send(int fd, int type, const char *user, char *tty,
	 struct tac_attrib *attr);
extern char *tac_account_read(int fd);
extern void *xcalloc(size_t nmemb, size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern char *_tac_check_header(HDR *th, int type);
extern int tac_author_send(int fd, const char *user, char *tty, 
	struct tac_attrib *attr);
extern void tac_author_read(int fd, struct areply *arep);

#endif

