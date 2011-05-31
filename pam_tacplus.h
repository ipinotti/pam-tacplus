/* pam_tacplus.h
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

#ifndef CONFIG_PD3
#define CONFIG_PD3
#endif

/* pam_tacplus command line options */
#define PAM_TAC_DEBUG		0x01
#define PAM_TAC_ENCRYPT		0x02
#define PAM_TAC_FIRSTHIT	0x04
#define PAM_TAC_ACCT		0x10 /* account on all specified servers */
#define PAM_TAC_CMD_ACCT	0x20
#define PAM_TAC_CMD_AUTHOR	0x40

/* how many TACPLUS+ servers can be defined */
#define TAC_MAX_SERVERS		4

/* pam_tacplus major, minor and patchlevel version numbers */
#define PAM_TAC_VMAJ		1
#define PAM_TAC_VMIN		3
#define PAM_TAC_VPAT		2

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif


#ifdef CONFIG_PD3
#define USE_CONF_FILE
#define BUFFER_SIZE 1024

#ifndef TACPLUS_CONF_FILE       /* the configuration file holding the server/secret/timeout */
#define TACPLUS_CONF_FILE       "/etc/tacdb/server"
#endif /* CONF_FILE */

typedef struct tacacs_server_t {
  struct tacacs_server_t *next;
  struct in_addr ip;
  char *hostname;
  char *secret;
  int timeout;
} tacacs_server_t;
#endif /* CONFIG_PD3 */
