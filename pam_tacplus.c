/* pam_tacplus.c - PAM interface for TACACS+ protocol.
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

#include <stdlib.h>	/* malloc */
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>	/* gethostbyname */
#include <sys/socket.h>	/* in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>	/* va_ */
#include <signal.h>
#include <string.h>	/* strdup */
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef __linux__
#include <strings.h>
#endif

#include "tacplus.h"
#include "libtac.h"
#include "pam_tacplus.h"
#include "support.h"

#include <librouter/defines.h>
#include <librouter/args.h>
#include <librouter/pam.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
/* #define PAM_SM_PASSWORD */

#ifndef __linux__
#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* support.c */
tacacs_server_t *tac_srv = NULL;
extern char *tac_service;
extern char *tac_protocol;
extern int _pam_parse(int argc, const char **argv);
extern unsigned long _getserveraddr(char *serv);
extern int tacacs_get_password(pam_handle_t * pamh, int flags, int ctrl, char **password);
extern int converse(pam_handle_t * pamh,
                    int nargs,
                    struct pam_message **message,
                    struct pam_response **response);
extern void _pam_log(int err, const char *format, ...);
extern void *_xcalloc(size_t size);

/* libtac */
extern char *tac_secret;
extern int tac_encryption;

/* address of server discovered by pam_sm_authenticate */
static u_long active_server = 0;
static int active_encryption = 0;
/* accounting task identifier */
static short int task_id = 0;

struct tacacs_data_t {
	u_long active_server;
	int active_encryption;
	int active_timeout;
	char key[128];
};

int tacacs_librouter_pam_get_privilege(){
	int ret = 0;

	if ((ret = librouter_pam_get_privilege()) == 0)
		ret = 15; /* tb.priv_lvl = TAC_PLUS_PRIV_LVL_MAX */

	return ret;
}


/**
* _get_config	Get user data saved earlier
*
* @param username
* @return 0 if success, -1 if fail
*/
int _get_config(char *username)
{
	int fd;
	char filename[64];
	struct tacacs_data_t cfg;

	memset(&cfg, 0, sizeof(struct tacacs_data_t));
	sprintf(filename, "/var/run/tacplus.%s.data", username);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		_pam_log(LOG_ERR, "Could not fetch user data\n");
		return -1;
	}

	read(fd, (void *) &cfg, sizeof(struct tacacs_data_t));

	active_server = cfg.active_server;
	active_encryption  = cfg.active_encryption;

	tac_secret = _xcalloc(strlen(cfg.key) + 1);
	strcpy(tac_secret, cfg.key);

	return 0;
}

/**
 * _set_config	Save data for later use
 *
 * @param username
 * @return 0 if success, -1 if fail
 */
int _set_config(char *username)
{
	int fd;
	char filename[64];
	struct tacacs_data_t cfg;

	sprintf(filename, "/var/run/tacplus.%s.data", username);
	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC);
	if (fd < 0)
		return -1;

	cfg.active_encryption = active_encryption;
	cfg.active_server = active_server;

	if (active_encryption)
		strncpy(cfg.key, tac_secret, sizeof(cfg.key));

	write(fd, (const void *) &cfg, sizeof(struct tacacs_data_t));

	return 0;
}

/* Helper functions */
int _pam_send_account(int tac_fd, int type, char *user, char *tty, char *cmd, char *enable_cli)
{
	struct tac_attrib *attr = NULL;
	int retval, status = -1;
	char priv[6];
	char buf[40];
	memset(&priv, 0, sizeof(priv));
	memset(&buf, 0, sizeof(buf));

#if 0
	/*CONFIG_PD3*/
	/* Código original do accounting removido por impedir remanejo no pacote na função de send*/
	attr = (struct tac_attrib *) _xcalloc(sizeof(struct tac_attrib));
#endif

	sprintf(buf, "%lu", (long unsigned int) time(0));

	tac_add_attrib(&attr, (type == TAC_PLUS_ACCT_FLAG_START) ? "start_time" : "stop_time", buf);
	sprintf(buf, "%hu", task_id);
	tac_add_attrib(&attr, "task_id", buf);

	/* If we have no service configured, put shell as default */
	if (tac_service != NULL) {
		if (!strcmp(tac_service, "shell") || !strcmp(tac_service, "ppp"))
			tac_add_attrib(&attr, "service", tac_service);
		else
			tac_add_attrib(&attr, "service", "shell");
	} else
		tac_add_attrib(&attr, "service", "shell");

	/* Do not add protocol if service is not PPP  */
	if (!strcmp(tac_service, "ppp"))
		tac_add_attrib(&attr, "protocol", tac_protocol);

	/* Command log */
	if ((cmd != NULL) && (enable_cli != NULL)) {
		tac_add_attrib(&attr, "cmd", cmd);

		if (atoi(enable_cli))
			sprintf(priv, "%d", tacacs_librouter_pam_get_privilege());
		else
			sprintf(priv, "%d", TAC_PLUS_PRIV_LVL_USR);
	}
	else
		sprintf(priv, "%d", TAC_PLUS_PRIV_LVL_USR);

	tac_add_attrib(&attr, "priv-lvl", priv);

	retval = tac_account_send(tac_fd, type, user, tty, attr);

	/* this is no longer needed */
	tac_free_attrib(&attr);

	if (retval < 0) {
		_pam_log(LOG_WARNING, "TACACS+: %s: send %s accounting failed (task %hu)", __FUNCTION__,
		                (type == TAC_PLUS_ACCT_FLAG_START) ? "start" : "stop", task_id);
#ifdef CONFIG_PD3
		status = PAM_AUTHINFO_UNAVAIL;
#else
		status = -1;
#endif

		goto ErrExit;
	}

	if (tac_account_read(tac_fd) != NULL) {
		_pam_log(LOG_WARNING, "TACACS+: %s: accounting %s failed (task %hu)", __FUNCTION__,
		                (type == TAC_PLUS_ACCT_FLAG_START) ? "start" : "stop", task_id);
#ifdef CONFIG_PD3
		status = PAM_AUTH_ERR;
#else
		status = -1;
#endif

		goto ErrExit;
	}

	status = PAM_SUCCESS;

	ErrExit: close(tac_fd);
	return status;
}

int _pam_account(pam_handle_t *pamh, int argc, const char **argv, int type)
{
	int retval;
	static int ctrl;
	char *user = NULL;
	char *tty = NULL;
	char *typemsg;
	int status = PAM_SESSION_ERR;
	char *tac_cmd = NULL;
	char *enable_cli = NULL;

	typemsg = (type == TAC_PLUS_ACCT_FLAG_START) ? "START" : "STOP";

	ctrl = _pam_parse(argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: [%s] called (pam_tacplus v%hu.%hu.%hu)", __FUNCTION__,
		                typemsg, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	retval = pam_get_item(pamh, PAM_USER, (const void **) (const void*) &user);
	if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
		_pam_log(LOG_ERR, "%s: unable to obtain username", __FUNCTION__);
		return PAM_SESSION_ERR;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: username [%s] obtained", __FUNCTION__, user);


	if (!tac_srv) {
		retval = initialize(&tac_srv);
		if (retval != PAM_SUCCESS)
			return retval;
	}

	if (!active_server)
		_get_config((char *)user);

	tty = _pam_get_terminal(pamh);

	if (!strncmp(tty, "/dev/", 5))
		tty += 5;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

	/* checks for specific data required by TACACS+, which should
	 be supplied in command line  */
	if (tac_service == NULL || *tac_service == '\0') {
		_pam_log(LOG_ERR, "TACACS+: service type not configured");
		return PAM_AUTH_ERR;
	}


	/* when this module is called from within pppd or other
	 application dealing with serial lines, it is likely
	 that we will get hit with signal caused by modem hangup;
	 this is important only for STOP packets, it's relatively
	 rare that modem hangs up on accounting start */
	if (type == TAC_PLUS_ACCT_FLAG_STOP) {
		signal(SIGALRM, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}

	if (!(ctrl & PAM_TAC_ACCT)) {
		/* normal mode, send packet to the first available server */
		int tac_fd;
		int i;
		tacacs_server_t *srv_i;
		u_long tac_servers[TAC_MAX_SERVERS];
		int tac_timeout[TAC_MAX_SERVERS];

		status = PAM_SUCCESS;

		if (tac_secret != NULL){
			free(tac_secret);
			tac_secret = NULL;
		}
		tac_secret = (char *) _xcalloc(strlen(tac_srv->secret) + 1);
		strcpy(tac_secret, tac_srv->secret);
		if (strlen(tac_secret))
			tac_encryption = 1;
		else
			tac_encryption = 0;

		for (srv_i = tac_srv, i = 0; srv_i; srv_i = srv_i->next, i++) {
			tac_servers[i] = srv_i->ip.s_addr;
			tac_timeout[i] = srv_i->timeout;
		}
		tac_fd = tac_connect(tac_servers, tac_timeout, i);

		if (tac_fd < 0) {
			_pam_log(LOG_ERR, "TACACS+: %s: error sending %s - no servers", __FUNCTION__,
			                typemsg);
			/*CONFIG_PD3*/
			status = PAM_AUTHINFO_UNAVAIL;
		}
		if (ctrl & PAM_TAC_DEBUG)
			syslog(LOG_DEBUG, "%s: connected with fd=%d", __FUNCTION__, tac_fd);

		if (ctrl & PAM_TAC_CMD_ACCT) {
			retval = pam_get_item(pamh, PAM_USER_PROMPT, (const void **) (const void *) &tac_cmd);
			if (retval != PAM_SUCCESS)
				_pam_log(LOG_ERR, "TACACS+: unable to obtain cmd\n");

			/*CONFIG_PD3*/
			/*Hack para adquirir status do _cish_enable do CLI para o PAM*/
			retval = pam_get_item(pamh, PAM_XDISPLAY, (const void **) (const void *) &enable_cli);
			if (retval != PAM_SUCCESS)
				_pam_log(LOG_ERR, "unable to obtain enable_cli status\n");
		}

		retval = _pam_send_account(tac_fd, type, user, tty, tac_cmd, enable_cli);

		if (retval < 0) {
			_pam_log(LOG_ERR, "TACACS+: %s: error sending %s", __FUNCTION__, typemsg);
			/*CONFIG_PD3*/
			status = PAM_AUTHINFO_UNAVAIL;
		}

		close(tac_fd);

		if (ctrl & PAM_TAC_DEBUG) {
			syslog(LOG_DEBUG, "%s: [%s] for [%s] sent", __FUNCTION__, typemsg, user);
		}
	} else {
		/* send packet to all servers specified */
		tacacs_server_t *srv_i;

		status = PAM_SESSION_ERR;

		for (srv_i = tac_srv; srv_i; srv_i = srv_i->next) {
			int tac_fd;

			if (tac_secret != NULL){
				free(tac_secret);
				tac_secret = NULL;
			}
			tac_secret = (char *) _xcalloc(strlen(srv_i->secret) + 1);
			strcpy(tac_secret, srv_i->secret);
			if (strlen(tac_secret))
				tac_encryption = 1;
			else
				tac_encryption = 0;

			if (ctrl & PAM_TAC_CMD_ACCT)
				syslog(LOG_INFO, "TACACS+: trying accounting command with %s", srv_i->hostname);
			else
				syslog(LOG_INFO, "TACACS+: trying accounting exec/login with %s", srv_i->hostname);

			tac_fd = tac_connect_single(srv_i->ip.s_addr, srv_i->timeout);
			if (tac_fd < 0) {
				_pam_log(LOG_WARNING, "TACACS+: %s: error sending %s (fd)", __FUNCTION__,
				                typemsg);
				continue;
			}

			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "%s: connected with fd=%d (srv %s)", __FUNCTION__, tac_fd, srv_i->hostname);

#ifdef CONFIG_PD3
			if (ctrl & PAM_TAC_CMD_ACCT) {
				retval = pam_get_item(pamh, PAM_USER_PROMPT, (const void **) (const void *) &tac_cmd);
				if (retval != PAM_SUCCESS)
					_pam_log(LOG_ERR, "TACACS+: unable to obtain cmd\n");

				/*CONFIG_PD3*/
				/*Hack para adquirir status do _cish_enable do CLI para o PAM*/
				retval = pam_get_item(pamh, PAM_XDISPLAY, (const void **) (const void *) &enable_cli);
				if (retval != PAM_SUCCESS)
					_pam_log(LOG_ERR, "unable to obtain enable_cli status\n");
			}
#else
			retval = pam_get_item(pamh, PAM_RHOST, (const void **) (const void *) &tac_cmd);
			if (retval != PAM_SUCCESS)
				_pam_log(LOG_ERR, "TACACS+: unable to obtain cmd\n");
#endif

			retval = _pam_send_account(tac_fd, type, user, tty, tac_cmd, enable_cli);

			/* return code from function in this mode is
			 status of the last server we tried to send
			 packet to */
			switch(retval){
				case 0: status = PAM_SUCCESS;
						if (ctrl & PAM_TAC_DEBUG)
							syslog(LOG_DEBUG, "%s: [%s] for [%s] sent", __FUNCTION__, typemsg, user);
						close(tac_fd);
						goto acct_end;
						break;
				case 9: _pam_log(LOG_WARNING, "TACACS+: %s: error sending %s (acct) - server unavailable", __FUNCTION__, typemsg);
						status = PAM_AUTHINFO_UNAVAIL;
						close(tac_fd);
						break;
				case -1:
				case 7:
				default:_pam_log(LOG_WARNING, "TACACS+: %s: accounting failed in %s (acct)", __FUNCTION__, typemsg);
						status = PAM_AUTH_ERR;
						close(tac_fd);
						goto acct_end;
						break;
			}
		}
	} /* acct mode */

acct_end:
	if (type == TAC_PLUS_ACCT_FLAG_STOP) {
		signal(SIGALRM, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
	}

	cleanup(&tac_srv);

	return status;
}

/* Main PAM functions */

/* authenticates user on remote TACACS+ server
 * returns PAM_SUCCESS if the supplied username and password
 * pair is valid 
 */PAM_EXTERN
int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	int ctrl, retval;
	const char *user, *service;
	char *pass;
	char *tty;
	tacacs_server_t *srv_i;
	int tac_fd;
	int status = PAM_AUTH_ERR;

	user = pass = tty = NULL;

	ctrl = _pam_parse(argc, argv);

	if (!tac_srv) {
		retval = initialize(&tac_srv);
		if (retval != PAM_SUCCESS)
			return retval;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)", __FUNCTION__,
		                PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	retval = pam_get_user(pamh, &user, "Username: ");
	if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
		_pam_log(LOG_ERR, "unable to obtain username");
		return PAM_USER_UNKNOWN;
	}

	retval = pam_get_item(pamh, PAM_SERVICE, (const void **) (const void *) &service);
	if (retval != PAM_SUCCESS || service == NULL || *service == '\0') {
		_pam_log(LOG_ERR, "unable to obtain service");
		return PAM_USER_UNKNOWN;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: user [%s] obtained", __FUNCTION__, user);

	/* uwzgledniac PAM_DISALLOW_NULL_AUTHTOK */

	retval = tacacs_get_password(pamh, flags, ctrl, &pass);
	if (retval != PAM_SUCCESS || pass == NULL || *pass == '\0') {
		_pam_log(LOG_ERR, "unable to obtain password");
		return PAM_CRED_INSUFFICIENT;
	}

	retval = pam_set_item(pamh, PAM_AUTHTOK, pass);
	if (retval != PAM_SUCCESS) {
		_pam_log(LOG_ERR, "unable to set password");
		return PAM_CRED_INSUFFICIENT;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: password obtained", __FUNCTION__);

	tty = _pam_get_terminal(pamh);

	if (!strncmp(tty, "/dev/", 5))
		tty += 5;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

	for (srv_i = tac_srv; srv_i; srv_i = srv_i->next) {
		int msg = TAC_PLUS_AUTHEN_STATUS_FAIL;

		syslog(LOG_INFO, "TACACS+: trying authentication with %s", srv_i->hostname);

		if (tac_secret != NULL){
			free(tac_secret);
			tac_secret = NULL;
		}
		tac_secret = (char *) _xcalloc(strlen(srv_i->secret) + 1);
		strcpy(tac_secret, srv_i->secret);
		if (strlen(tac_secret))
			tac_encryption = 1;
		else
			tac_encryption = 0;

		tac_fd = tac_connect_single(srv_i->ip.s_addr, srv_i->timeout);

		if (tac_fd < 0) {
			free(tac_secret);
			tac_secret = NULL;
			if (srv_i->next == NULL) {
				/* last server tried */
				_pam_log(LOG_ERR, "no more servers to connect");
				return PAM_AUTHINFO_UNAVAIL;
			} else {
				continue; /* Try next server */
			}
		}

		if (tac_authen_send(tac_fd, service, user, pass, tty) < 0) {
			_pam_log(LOG_ERR, "TACACS+: Error sending 'authentication request' to TACACS+ server");
			status = PAM_AUTHINFO_UNAVAIL;
			goto auth_end;
		}

		msg = tac_authen_read(tac_fd);

		if (msg == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "TACACS+: %s: tac_cont_send called", __FUNCTION__);
			if (tac_cont_send(tac_fd, pass) < 0) {
				_pam_log(LOG_ERR, "TACACS+: Error sending 'continue request' to TACACS+ server");
				status = PAM_AUTHINFO_UNAVAIL;
			} else {
				msg = tac_authen_read(tac_fd);
				if (msg != TAC_PLUS_AUTHEN_STATUS_PASS) {
					_pam_log(LOG_ERR, "TACACS+: auth failed: %d", msg);
					status = PAM_AUTH_ERR;
					/*CONFIG_PD3*/
					/* HACK para desistir na primeira negação de password/login, evitando verificar em outros servers tacacs*/
					active_server = srv_i->ip.s_addr;
					active_encryption = tac_encryption;
					close(tac_fd);
					break;
				} else {
					/* OK, we got authenticated; save the server that
					 accepted us for pam_sm_acct_mgmt and exit the loop */
					status = PAM_SUCCESS;
					active_server = srv_i->ip.s_addr;
					active_encryption = tac_encryption;
					close(tac_fd);
					break;
				}
			}
		} else if (msg != TAC_PLUS_AUTHEN_STATUS_PASS) {
			_pam_log(LOG_ERR, "TACACS+: auth failed: %d", msg);
			status = PAM_AUTH_ERR;
		} else {
			/* OK, we got authenticated; save the server that
			 accepted us for pam_sm_acct_mgmt and exit the loop */
			status = PAM_SUCCESS;
			active_server = srv_i->ip.s_addr;
			active_encryption = tac_encryption;
			close(tac_fd);
			break;
		}


auth_end:
		close(tac_fd);

		if (msg == PAM_AUTHINFO_UNAVAIL) {
			/* Somehow we got connected, but communication with
			 * server failed. Try the next one. */
			if (srv_i->next == NULL) {
				/* last server tried */
				_pam_log(LOG_ERR, "TACACS+: no more servers to connect");
				return PAM_AUTHINFO_UNAVAIL;
			} else {
				continue; /* Try next server */
			}
		}
	}

	/* Save info for using during this session */
	if (status == PAM_SUCCESS) {
		_set_config((char *)user);
		free(tac_secret);
		tac_secret = NULL;
	}

	cleanup(&tac_srv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: exit with pam status: %i", __FUNCTION__, status);

	bzero(pass, strlen(pass));
	free(pass);
	pass = NULL;

	return status;
} /* pam_sm_authenticate */

/* no-op function to satisfy PAM authentication module */PAM_EXTERN
int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	int ctrl = _pam_parse(argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)", __FUNCTION__,
		                PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	return PAM_SUCCESS;
} /* pam_sm_setcred */

/* authorizes user on remote TACACS+ server, i.e. checks
 * his permission to access requested service
 * returns PAM_SUCCESS if the service is allowed
 */PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	int retval, ctrl, status = PAM_AUTH_ERR;
	const char *user;
	char *tty;
	struct areply arep;
	struct tac_attrib *attr = NULL;
	int tac_fd;
	char *rhostname;
	u_long rhost = 0;
	char *tac_cmd = NULL;
	char *enable_cli = NULL;
	tacacs_server_t *srv_i;
	u_long tac_servers[TAC_MAX_SERVERS];
	int tac_timeout[TAC_MAX_SERVERS];
	int mode = 0;

	if (!tac_srv) {
		retval = initialize(&tac_srv);
		if (retval != PAM_SUCCESS)
			return retval;
	}

	user = tty = rhostname = NULL;

	/* this also obtains service name for authorization
	 this should be normally performed by pam_get_item(PAM_SERVICE)
	 but since PAM service names are incompatible TACACS+
	 we have to pass it via command line argument until a better
	 solution is found ;) */
	ctrl = _pam_parse(argc, argv);


	if (ctrl & PAM_TAC_DEBUG) {
		struct in_addr addr;

		syslog(LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)", __FUNCTION__,
		                PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

		bcopy(&active_server, &addr.s_addr, sizeof(addr.s_addr));
		syslog(LOG_DEBUG, "%s: active server is [%s]", __FUNCTION__, inet_ntoa(addr));
	}

	retval = pam_get_item(pamh, PAM_USER, (const void **) (const void*) &user);
	if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
		_pam_log(LOG_ERR, "unable to obtain username");
		return PAM_USER_UNKNOWN;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: username obtained [%s]", __FUNCTION__, user);

	tty = _pam_get_terminal(pamh);

	if (!strncmp(tty, "/dev/", 5))
		tty += 5;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty obtained [%s]", __FUNCTION__, tty);

	/* If there are no active servers, check for data file */
	if (!active_server){
		_get_config((char *) user);
	}

	if (ctrl & PAM_TAC_CMD_AUTHOR) {
		/*CONFIG_PD3*/
		/*Hack para adquirir cmds do CLI para o PAM*/
		retval = pam_get_item(pamh, PAM_USER_PROMPT, (const void **) (const void *) &tac_cmd);
		if (retval != PAM_SUCCESS)
			_pam_log(LOG_ERR, "unable to obtain cmd\n");

		/*CONFIG_PD3*/
		/*Hack para adquirir status do _cish_enable do CLI para o PAM*/
		retval = pam_get_item(pamh, PAM_XDISPLAY, (const void **) (const void *) &enable_cli);
		if (retval != PAM_SUCCESS)
			_pam_log(LOG_ERR, "unable to obtain enable_cli status\n");
	}

	/* checks for specific data required by TACACS+, which should
	 be supplied in command line  */
	if (tac_service == NULL || *tac_service == '\0') {
		_pam_log(LOG_ERR, "TACACS+ service type not configured");
		return PAM_AUTH_ERR;
	}

	tac_add_attrib(&attr, "service", tac_service);

	/* AV cmd in tests has been always necessary */
	if (tac_cmd != NULL && *tac_cmd != '\0') {
		arglist *args;
		int i;
		char priv[6];
		memset(&priv, 0, sizeof(priv));

		if (atoi(enable_cli))
			sprintf(priv, "%d", tacacs_librouter_pam_get_privilege());
		else
			sprintf(priv, "%d", TAC_PLUS_PRIV_LVL_USR);

		tac_add_attrib(&attr, "priv-lvl", priv);

		args = librouter_make_args(tac_cmd);
		tac_add_attrib(&attr, "cmd", args->argv[0]);
		for (i = 1; i < args->argc; i++)
			tac_add_attrib(&attr, "cmd-args", args->argv[i]);
		librouter_destroy_args(args);
	}
	else{
		tac_add_attrib(&attr, "cmd", "");
	}

	/* AV protocol is necessary only on PPP, we shouldn't fail if not set */
	if (tac_protocol != NULL && *tac_protocol != '\0')
		tac_add_attrib(&attr, "protocol", tac_protocol);

	if (rhost) {
		struct in_addr addr;
		bcopy(&rhost, &addr.s_addr, sizeof(addr.s_addr));
		tac_add_attrib(&attr, "ip", inet_ntoa(addr));
	}

	tac_encryption = active_encryption;

	status = PAM_PERM_DENIED;

	if (ctrl & PAM_TAC_CMD_AUTHOR)
		mode = librouter_pam_get_current_cmd_author_mode(FILE_PAM_CLI);
	else
		mode = librouter_pam_get_current_author_mode(FILE_PAM_LOGIN);

	for (srv_i = tac_srv; srv_i; srv_i = srv_i->next) {
	/* No active server, so perhaps we were not authenticated by TACACS+.
	 * Try all configured servers then! */
		if (tac_secret != NULL){
			free(tac_secret);
			tac_secret = NULL;
		}
		tac_secret = (char *) _xcalloc(strlen(tac_srv->secret) + 1);
		strcpy(tac_secret, srv_i->secret);
		if (strlen(tac_secret))
			tac_encryption = 1;
		else
			tac_encryption = 0;

		if (ctrl & PAM_TAC_CMD_AUTHOR)
			syslog(LOG_INFO, "TACACS+: trying authorizing command with %s", srv_i->hostname);
		else
			syslog(LOG_INFO, "TACACS+: trying authorizing exec/login with %s", srv_i->hostname);

		tac_fd = tac_connect_single(srv_i->ip.s_addr, srv_i->timeout);
		if (tac_fd < 0) {
			_pam_log(LOG_WARNING, "TACACS+: %s: server unavailable", __FUNCTION__);
			if (mode == AAA_AUTHOR_TACACS_LOCAL || mode == AAA_AUTHOR_NONE)
				status = PAM_AUTHINFO_UNAVAIL;
			else
				status = PAM_PERM_DENIED;
			continue;
		}

		if (ctrl & PAM_TAC_DEBUG)
			syslog(LOG_DEBUG, "%s: connected with fd=%d (srv %s)", __FUNCTION__, tac_fd, srv_i->hostname);

		retval = tac_author_send(tac_fd, user, tty, attr);

		if (retval < 0) {
			_pam_log(LOG_ERR, "TACACS+: error getting authorization - server unavailable");
			/*CONFIG_PD3*/
			/* Hack para retornar PAM_AUTHINFO_UNAVAIL e autorizar login quando tacacs server falha, assumindo local */
			/*status = PAM_AUTH_ERR;*/
			if (mode == AAA_AUTHOR_TACACS_LOCAL || mode == AAA_AUTHOR_NONE)
				status = PAM_AUTHINFO_UNAVAIL;
			else
				status = PAM_PERM_DENIED;
			continue;
		}

		if (ctrl & PAM_TAC_DEBUG)
			syslog(LOG_DEBUG, "%s: sent authorization request", __FUNCTION__);

		tac_author_read(tac_fd, &arep);

		if (arep.status != AUTHOR_STATUS_PASS_ADD && arep.status != AUTHOR_STATUS_PASS_REPL) {
			_pam_log(LOG_ERR, "TACACS+ authorization failed for [%s]", user);
			status = PAM_PERM_DENIED;
			if (attr != NULL)
				tac_free_attrib(&attr);
			goto ErrExit;
		}
		else{
			status = 0;
			break;
		}
	}

	if (attr != NULL)
		tac_free_attrib(&attr);

	if (status == PAM_AUTHINFO_UNAVAIL || status == PAM_PERM_DENIED)
		goto ErrExit;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: user [%s] successfully authorized", __FUNCTION__, user);

	status = PAM_SUCCESS;

	attr = arep.attr;
	while (attr != NULL) {
		char attribute[attr->attr_len];
		char value[attr->attr_len];
		char *sep;

		sep = index(attr->attr, '=');
		if (sep == NULL)
			sep = index(attr->attr, '*');
		if (sep != NULL) {
			bcopy(attr->attr, attribute, attr->attr_len - strlen(sep));
			attribute[attr->attr_len - strlen(sep)] = '\0';
			bcopy(sep, value, strlen(sep));
			value[strlen(sep)] = '\0';

			size_t i;
			for (i = 0; attribute[i] != '\0'; i++) {
				attribute[i] = toupper(attribute[i]);
				if (attribute[i] == '-')
					attribute[i] = '_';
			}

			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "%s: returned attribute `%s%s' from server",
				                __FUNCTION__, attribute, value);

			/* set PAM_RHOST if 'addr' attribute was returned from server */
			if (!strncmp(attribute, "addr", 4) && isdigit((int)*value)) {
				retval = pam_set_item(pamh, PAM_RHOST, value);
				if (retval != PAM_SUCCESS)
					syslog(LOG_WARNING,
					                "%s: unable to set remote address for PAM",
					                __FUNCTION__);
				else if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "%s: set remote addr to `%s'",
					                __FUNCTION__, value);
			}

			/* make returned attributes available for other PAM modules via PAM environment */
			if (pam_putenv(pamh, strncat(attribute, value, strlen(value)))
			                != PAM_SUCCESS)
				syslog(LOG_WARNING, "%s: unable to set PAM environment",
				                __FUNCTION__);

		} else {
			syslog(LOG_WARNING, "%s: invalid attribute `%s', no separator",
			                __FUNCTION__, attr->attr);
		}
		attr = attr->next;
	}

	/* free returned attributes */
	if (arep.attr != NULL)
		tac_free_attrib(&arep.attr);

ErrExit:
	close(tac_fd);
	cleanup(&tac_srv);

	return status;
} /* pam_sm_acct_mgmt */

/* sends START accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
/* accounting packets may be directed to any TACACS+ server,
 * independent from those used for authentication and authorization;
 * it may be also directed to all specified servers
 */PAM_EXTERN
int pam_sm_open_session(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	task_id = (short int) magic();

	return (_pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_START));
} /* pam_sm_open_session */

/* sends STOP accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */PAM_EXTERN
int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return (_pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_STOP));
} /* pam_sm_close_session */

#ifdef PAM_SM_PASSWORD
/* no-op function for future use */
PAM_EXTERN
int pam_sm_chauthtok (pam_handle_t * pamh, int flags,
		int argc, const char **argv) {
	int ctrl = _pam_parse (argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
	syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
			, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	return PAM_SUCCESS;
} /* pam_sm_chauthtok */
#endif

#ifdef PAM_STATIC
struct pam_module _pam_tacplus_modstruct
{
	"pam_tacplus",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
#ifdef PAM_SM_PASSWORD
	pam_sm_chauthtok
#else
	NULL
#endif
};
#endif

