/**
 * @file fetion.h
 *
 * purple
 *
 * Copyright (C) 2005, Thomas Butter <butter@uni-mannheim.de>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#ifndef _PURPLE_FETION_H
#define _PURPLE_FETION_H

#include <glib.h>
#include <time.h>

#include "cipher.h"
#include "circbuffer.h"
#include "dnsquery.h"
#include "dnssrv.h"
#include "network.h"
#include "proxy.h"
#include "prpl.h"
#include "internal.h"

#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "debug.h"
#include "notify.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"
#include "sipmsg.h"

#define FETION_BUF_INC 4096
#define FETION_REGISTER_RETRY_MAX 2

#define FETION_REGISTER_SENT 1
#define FETION_REGISTER_RETRY 2
#define FETION_REGISTER_COMPLETE 3

#define PUBLISH_EXPIRATION 600
#define SUBSCRIBE_EXPIRATION 1200

struct sip_dialog {
	gchar *ourtag;
	gchar *theirtag;
	gchar *callid;
};

struct fetion_watcher {
	gchar *name;
	time_t expire;
	struct sip_dialog dialog;
	gboolean needsxpidf;
};

struct fetion_buddy {
	gchar *name;
	gchar *icon_buf;
	gchar *icon_crc;
	gchar *host;
	gint icon_size;
	gint icon_rcv_len;
	gint inpa;
	struct fetion_account_data *sip;

	time_t resubscribe;
	struct sip_dialog *dialog;
};

struct fetion_cfg {
	PurpleProxyConnectData *conn;
	gchar *buf;
	gint size;
	gint rcv_len;
	gint inpa;
};

struct sip_auth {
	int type;		/* 1 = Digest / 2 = NTLM */
	gchar *nonce;
	gchar *cnonce;
	gchar *domain;
	gchar *target;
	guint32 flags;
	int nc;
	gchar *digest_session_key;
	int retries;
};

struct group_chat {
	gint chatid;
	gchar *callid;
	gchar *groupname;
	PurpleConversation *conv;
};

struct group_attr {
	gchar *name;
	gchar *id;
};

struct fetion_account_data {
	PurpleConnection *gc;
	gchar *servername;
	gchar *username;
	gchar *mobileno;
	gchar *password;
	gchar *uri;
	gchar *impresa;
	gchar *ssic;
	gchar *SsicServer;
	gchar *SysCfgServer;
	gchar *UploadServer;
	gchar *UploadPrefix;
	gchar *MsgServer;
	gchar *PortraitServer;
	gchar *PortraitPrefix;
	gchar *ServerVersion;
	gchar *ServiceNoVersion;
	gchar *ParaVersion;
	gchar *HintsVersion;
	gchar *HttpAppVersion;
	gchar *ClientCfgVersion;
	gchar *CfgVersion;
	PurpleDnsQueryData *query_data;
	PurpleSrvQueryData *srv_query_data;
	PurpleNetworkListenData *listen_data;
	int MsgPort;
	//int SysCfg_inpa;
	int fd;
	int cseq;
	int tg;			//for temp group chat id
	time_t reregister;
	time_t republish;
	int registerstatus;	/* 0 nothing, 1 first registration send, 2 auth received, 3 registered */
	struct fetion_cfg SysCfg;
	struct sip_auth registrar;
	struct sip_auth proxy;
	int listenfd;
	int listenport;
	int listenpa;
	gchar *status;
	GHashTable *buddies;
	GHashTable *group;
	GHashTable *group2id;
	GHashTable *tempgroup;
	GHashTable *portrait_con;
	GList *tempgroup_id;
	guint registertimeout;
	guint resendtimeout;
	gboolean connecting;
	PurpleAccount *account;
	PurpleCircBuffer *txbuf;
	guint tx_handler;
	gchar *regcallid;
	GSList *transactions;
	GSList *watcher;
	GSList *openconns;
	gboolean udp;
	struct sockaddr_in serveraddr;
	int registerexpire;
	gchar *realhostname;
	int realport;		/* port and hostname from SRV record */
	PurpleStoredImage *icon;
	struct fetion_buddy *who;	/* log the user we are dowdloading portrait */
	guint icon_handler;
	PurpleCircBuffer *icon_buf;
	guint GetContactTimeOut;
	guint GetContactFlag;
};

struct sip_connection {
	int fd;
	gchar *inbuf;
	int inbuflen;
	int inbufused;
	int inputhandler;
};

struct transaction;

typedef gboolean(*TransCallback) (struct fetion_account_data *,
				  struct sipmsg *, struct transaction *);

struct transaction {
	time_t time;
	int timer;
	int retries;
	int transport;		/* 0 = tcp, 1 = udp */
	int fd;
	const gchar *cseq;
	struct sipmsg *msg;
	struct fetion_account_data *sip;
	TransCallback callback;
};

void fetion_input_cb(gpointer data, gint source, PurpleInputCondition cond);
gchar *find_tag(const gchar * hdr);
void send_sip_request(PurpleConnection * gc, const gchar * method,
		      const gchar * url, const gchar * to,
		      const gchar * addheaders, const gchar * body,
		      struct sip_dialog *dialog, TransCallback tc);

void send_sip_response(PurpleConnection * gc, struct sipmsg *msg, int code,
		       const char *text, const char *body);
gboolean process_subscribe_response(struct fetion_account_data *sip,
				    struct sipmsg *msg, struct transaction *tc);
gboolean process_register_response(struct fetion_account_data *sip,
				   struct sipmsg *msg, struct transaction *tc);
guint fetion_ht_hash_nick(const char *nick);
gboolean fetion_ht_equals_nick(const char *nick1, const char *nick2);
void srvresolved(gpointer data);
#endif				/* _PURPLE_FETION_H */
