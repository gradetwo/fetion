/**
 * @file fetion.c
 *
 * purple
 *
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
 *
 * ***
 * Thanks to Google's Summer of Code Program and the helpful mentors
 * ***
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

#include "internal.h"

#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "dnsquery.h"
#include "debug.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"
#include "network.h"
#include "xmlnode.h"
#include "request.h"
#include "imgstore.h"
#include "sslconn.h"
#include "cmds.h"

#include "sipmsg.h"
#include "dnssrv.h"
#include "ntlm.h"

#include "sipmsg.h"

#include "fetion.h"
#include "f_buddy.h"
#include "f_chat.h"
#include "f_group.h"
#include "f_login.h"
#include "f_sysmsg.h"
#include "f_portrait.h"
#include "f_user.h"
#include "f_util.h"
#include "f_gchat.h"
gint g_callid;

static const char *fetion_list_icon(PurpleAccount * a, PurpleBuddy * b)
{
	return "fetion";
}

static void fetion_keep_alive(PurpleConnection * gc)
{
	struct fetion_account_data *sip = gc->proto_data;
	time_t curtime = time(NULL);
	/* register again if first registration expires */
	if (sip->reregister < curtime) {
		do_register(sip);
	}

	return;
}

static void fetion_set_status(PurpleAccount * account, PurpleStatus * status)
{
	/*
	   Away = 100,
	   BeRightBack = 300,
	   Busy = 600,
	   DoNotDisturb = 800,
	   InTheMeeting = 850,
	   Invisible = 0x383,
	   Offline = 0,
	   Online = 400,
	   OnThePhone = 500,
	   OutToLunch = 150,
	   SmsOnline = 1,
	   Unknown = -1
	 */
	const char *status_id;
	char *body;
	int status_code;

	status_id = purple_status_get_id(status);

	if (!strcmp(status_id, "away"))
		status_code = 100;
	else if (!strcmp(status_id, "brb"))
		status_code = 300;
	else if (!strcmp(status_id, "busy"))
		status_code = 600;
	else if (!strcmp(status_id, "phone"))
		status_code = 500;
	else if (!strcmp(status_id, "lunch"))
		status_code = 150;
	else if (!strcmp(status_id, "invisible"))
		status_code = 0x383;
	else
		status_code = 400;

	body =
	    g_strdup_printf
	    ("<args><presence><basic value=\"%d\" /></presence></args>",
	     status_code);
	send_sip_request(account->gc, "S", "", "", "N: SetPresence\r\n", body,
			 NULL, NULL);
	g_free(body);
	//<args><presence><basic value="400" /></presence></args>
}

static struct sip_connection *connection_find(struct fetion_account_data
					      *sip, int fd)
{
	struct sip_connection *ret = NULL;
	GSList *entry = sip->openconns;
	while (entry) {
		ret = entry->data;
		if (ret->fd == fd)
			return ret;
		entry = entry->next;
	}
	return NULL;
}

static struct sip_connection *connection_create(struct fetion_account_data
						*sip, int fd)
{
	struct sip_connection *ret = g_new0(struct sip_connection, 1);
	ret->fd = fd;
	sip->openconns = g_slist_append(sip->openconns, ret);
	return ret;
}

static void connection_remove(struct fetion_account_data *sip, int fd)
{
	struct sip_connection *conn = connection_find(sip, fd);
	sip->openconns = g_slist_remove(sip->openconns, conn);
	if (conn->inputhandler)
		purple_input_remove(conn->inputhandler);
	g_free(conn->inbuf);
	g_free(conn);
}

static void connection_free_all(struct fetion_account_data *sip)
{
	struct sip_connection *ret = NULL;
	GSList *entry = sip->openconns;
	while (entry) {
		ret = entry->data;
		connection_remove(sip, ret->fd);
		entry = sip->openconns;
	}
}

static GList *fetion_status_types(PurpleAccount * acc)
{
	PurpleStatusType *status;
	GList *types = NULL;

	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE,
					     "available", NULL, FALSE, TRUE,
					     FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY,
					     "away", NULL, FALSE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY,
					     "brb", _("Be Right Back"), FALSE,
					     TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE,
					     "busy", _("Busy"), FALSE, TRUE,
					     FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_UNAVAILABLE,
					     "phone", _("On the Phone"), FALSE,
					     TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_AWAY,
					     "lunch", _("Out to Lunch"), FALSE,
					     TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_INVISIBLE,
					     NULL, NULL, FALSE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE,
					     NULL, NULL, FALSE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_MOBILE,
					     "mobile", _("Mobile on Line"),
					     FALSE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static void
fetion_canwrite_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct fetion_account_data *sip = gc->proto_data;
	gsize max_write;
	gssize written;

	max_write = purple_circ_buffer_get_max_read(sip->txbuf);

	if (max_write == 0) {
		purple_input_remove(sip->tx_handler);
		sip->tx_handler = 0;
		return;
	}

	written = write(sip->fd, sip->txbuf->outptr, max_write);

	if (written < 0 && errno == EAGAIN)
		written = 0;
	else if (written <= 0) {
		/*TODO: do we really want to disconnect on a failure to write? */
		purple_connection_error_reason(gc,
					       PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					       _("Could not write"));
		return;
	}

	purple_circ_buffer_mark_read(sip->txbuf, written);
}

static void send_later_cb(gpointer data, gint source, const gchar * error)
{
	PurpleConnection *gc = data;
	struct fetion_account_data *sip;
	struct sip_connection *conn;

	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		if (source >= 0)
			close(source);
		return;
	}

	if (source < 0) {
		purple_connection_error_reason(gc,
					       PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					       _("Could not connect"));
		return;
	}

	sip = gc->proto_data;
	sip->fd = source;
	sip->connecting = FALSE;

	fetion_canwrite_cb(gc, sip->fd, PURPLE_INPUT_WRITE);

	/* If there is more to write now, we need to register a handler */
	if (sip->txbuf->bufused > 0)
		sip->tx_handler = purple_input_add(sip->fd, PURPLE_INPUT_WRITE,
						   fetion_canwrite_cb, gc);

	conn = connection_create(sip, source);
	conn->inputhandler =
	    purple_input_add(sip->fd, PURPLE_INPUT_READ, fetion_input_cb, gc);
}

static void sendlater(PurpleConnection * gc, const char *buf)
{
	struct fetion_account_data *sip = gc->proto_data;

	if (!sip->connecting) {
		purple_debug_info("fetion", "connecting to %s port %d\n",
				  sip->
				  realhostname ? sip->realhostname : "{NULL}",
				  sip->realport);
		if (purple_proxy_connect
		    (gc, sip->account, sip->realhostname, sip->realport,
		     send_later_cb, gc) == NULL) {
			purple_connection_error_reason(gc,
						       PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
						       _
						       ("Couldn't create socket"));
		}
		sip->connecting = TRUE;
	}

	if (purple_circ_buffer_get_max_read(sip->txbuf) > 0)
		purple_circ_buffer_append(sip->txbuf, "\r\n", 2);

	purple_circ_buffer_append(sip->txbuf, buf, strlen(buf));
}

static void sendout_pkt(PurpleConnection * gc, const gchar * buf)
{
	struct fetion_account_data *sip = gc->proto_data;
	time_t currtime = time(NULL);
	gint writelen = strlen(buf);
	gint ret;

	purple_debug(PURPLE_DEBUG_MISC, "fetion",
		     "\n\nsending - %s\n######\n%s\n######\n\n",
		     ctime(&currtime), buf);

	if (sip->fd < 0) {
		sendlater(gc, buf);
		return;
	}

	if (sip->tx_handler) {
		ret = -1;
		errno = EAGAIN;
	} else
		ret = write(sip->fd, buf, writelen);

	if (ret < 0 && errno == EAGAIN)
		ret = 0;
	else if (ret <= 0) {	/* XXX: When does this happen legitimately? */
		sendlater(gc, buf);
		return;
	}

	if (ret < writelen) {
		if (!sip->tx_handler)
			sip->tx_handler = purple_input_add(sip->fd,
							   PURPLE_INPUT_WRITE,
							   fetion_canwrite_cb,
							   gc);

		/* XXX: is it OK to do this? You might get part of a request sent
		   with part of another. */
		if (sip->txbuf->bufused > 0)
			purple_circ_buffer_append(sip->txbuf, "\r\n", 2);

		purple_circ_buffer_append(sip->txbuf, buf + ret,
					  writelen - ret);
	}

}

static int fetion_send_raw(PurpleConnection * gc, const char *buf, int len)
{
	sendout_pkt(gc, buf);
	return len;
}

/*
   static void sendout_sipmsg(struct fetion_account_data *sip, struct sipmsg *msg)
   {
   GSList *tmp = msg->headers;
   gchar *name;
   gchar *value;
   GString *outstr = g_string_new("");
   g_string_append_printf(outstr, "%s %s SIP/2.0\r\n", msg->method, msg->target);
   while(tmp)
   {
   name = ((struct siphdrelement*) (tmp->data))->name;
   value = ((struct siphdrelement*) (tmp->data))->value;
   g_string_append_printf(outstr, "%s: %s\r\n", name, value);
   tmp = g_slist_next(tmp);
   }
   g_string_append_printf(outstr, "\r\n%s", msg->body ? msg->body : "");
   sendout_pkt(sip->gc, outstr->str);
   g_string_free(outstr, TRUE);
   }

*/

void
send_sip_response(PurpleConnection * gc, struct sipmsg *msg, int code,
		  const char *text, const char *body)
{
	GSList *tmp = msg->headers;
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");

	/* When sending the acknowlegements and errors, the content length from the original
	   message is still here, but there is no body; we need to make sure we're sending the
	   correct content length */
	sipmsg_remove_header(msg, "L");
	if (body) {
		gchar len[12];
		sprintf(len, "%d", (int)strlen(body));
		sipmsg_add_header(msg, "L", len);
	}

	g_string_append_printf(outstr, "SIP-C/2.0 %d %s\r\n", code, text);
	while (tmp) {
		name = ((struct siphdrelement *)(tmp->data))->name;
		value = ((struct siphdrelement *)(tmp->data))->value;

		g_string_append_printf(outstr, "%s: %s\r\n", name, value);
		tmp = g_slist_next(tmp);
	}
	g_string_append_printf(outstr, "\r\n%s", body ? body : "");
	sendout_pkt(gc, outstr->str);
	g_string_free(outstr, TRUE);
}

static void transaction_timeout(gpointer data)
{
	struct transaction *trans;
	g_return_if_fail(data != NULL);
	trans = data;
	if (trans->callback) {
		/* call the callback to process response */
		(trans->callback) (trans->sip, trans->msg, trans);
	}

	if (trans->timer)
		purple_timeout_remove(trans->timer);

}

static void
transactions_remove(struct fetion_account_data *sip, struct transaction *trans)
{
	if (trans->msg)
		sipmsg_free(trans->msg);
	if (trans->timer)
		purple_timeout_remove(trans->timer);
	sip->transactions = g_slist_remove(sip->transactions, trans);
	g_free(trans);
}

static void
transactions_add_buf(struct fetion_account_data *sip, const gchar * buf,
		     void *callback)
{
	struct transaction *trans = g_new0(struct transaction, 1);

	trans->sip = sip;
	trans->time = time(NULL);
	trans->msg = sipmsg_parse_msg(buf);
	trans->cseq = sipmsg_find_header(trans->msg, "Q");
	trans->callback = callback;
	if (!strcmp(trans->msg->method, "M"))
		trans->timer =
		    purple_timeout_add(60000, (GSourceFunc) transaction_timeout,
				       trans);
	sip->transactions = g_slist_append(sip->transactions, trans);
}

static void transactions_free_all(struct fetion_account_data *sip)
{
	GSList *entry;
	while ((entry = sip->transactions) != NULL) {
		transactions_remove(sip, entry->data);
	}
}

static struct transaction *transactions_find(struct fetion_account_data
					     *sip, struct sipmsg *msg)
{
	struct transaction *trans;
	GSList *transactions = sip->transactions;
	const gchar *cseq = sipmsg_find_header(msg, "Q");

	if (cseq) {
		while (transactions) {
			trans = transactions->data;
			if (!strcmp(trans->cseq, cseq)) {
				return trans;
			}
			transactions = transactions->next;
		}
	} else {
		purple_debug(PURPLE_DEBUG_MISC, "fetion",
			     "Received message contains no CSeq header.\n");
	}

	return NULL;
}

void
send_sip_request(PurpleConnection * gc, const gchar * method,
		 const gchar * url, const gchar * to,
		 const gchar * addheaders, const gchar * body,
		 struct sip_dialog *dialog, TransCallback tc)
{
	struct fetion_account_data *sip = gc->proto_data;
	gchar *callid = dialog ? g_strdup(dialog->callid) : gencallid();
	const gchar *addh = "";
	GString *outstr = g_string_new("");

	if (!strcmp(method, "R")) {
		if (sip->regcallid) {
			g_free(callid);
			callid = g_strdup(sip->regcallid);
		} else
			sip->regcallid = g_strdup(callid);
	}

	if (addheaders)
		addh = addheaders;

	g_string_append_printf(outstr, "%s fetion.com.cn SIP-C/2.0\r\n"
			       "F: %s\r\n"
			       "I: %s\r\n"
			       "Q: %d %s\r\n"
			       "%s%s",
			       method,
			       sip->username,
			       callid, ++sip->cseq, method, to, addh);
	if (body)
		g_string_append_printf(outstr, "L: %d\r\n\r\n%s",
				       (int)strlen(body), body);
	else
		g_string_append_printf(outstr, "\r\n\r\n");

	g_free(callid);

	/* add to ongoing transactions */

	transactions_add_buf(sip, outstr->str, tc);

	sendout_pkt(gc, outstr->str);

	g_string_free(outstr, TRUE);
}

gboolean
process_subscribe_response(struct fetion_account_data *sip,
			   struct sipmsg *msg, struct transaction *tc)
{
	purple_debug_info("fetion", "process subscribe response[%s]\n",
			  msg->body);

	return TRUE;
}

static void
fetion_unsubscribe(char *name, struct fetion_buddy *buddy,
		   struct fetion_account_data *sip)
{
	if (buddy->dialog) {
		purple_debug_info("fetion", "Unsubscribing from %s\n", name);
		fetion_subscribe_exp(sip, buddy);
	}
}

static int
fetion_im_send(PurpleConnection * gc, const char *who, const char *what,
	       PurpleMessageFlags flags)
{
	struct fetion_account_data *sip = gc->proto_data;
	char *to = g_strdup(who);
	char *text = purple_unescape_html(what);
	fetion_send_message(sip, to, text, NULL, FALSE);
	g_free(to);
	g_free(text);
	return 1;
}

gboolean
process_register_response(struct fetion_account_data * sip,
			  struct sipmsg * msg, struct transaction * tc)
{
	const gchar *tmp;
	const gchar *szExpire;
	purple_debug(PURPLE_DEBUG_MISC, "fetion",
		     "in process register response response: %d\n",
		     msg->response);
	switch (msg->response) {
	case 200:
		if (sip->registerstatus < FETION_REGISTER_COMPLETE) {
			/* get buddies from blist */
			GetPersonalInfo(sip);
			if (sip->GetContactTimeOut)
				purple_timeout_remove(sip->GetContactTimeOut);
			sip->GetContactTimeOut =
			    purple_timeout_add(5000,
					       (GSourceFunc) GetContactList,
					       sip);
			GetContactList(sip);
		}
		sip->registerstatus = FETION_REGISTER_COMPLETE;
		szExpire = sipmsg_find_header(msg, "X");
		if (szExpire != NULL)
			sip->registerexpire = atoi(szExpire);
		purple_debug_info("Register:", "[%s]", szExpire);
		purple_connection_set_state(sip->gc, PURPLE_CONNECTED);

		break;
	case 401:
		if (sip->registerstatus != FETION_REGISTER_RETRY) {
			purple_debug_info("fetion", "REGISTER retries %d\n",
					  sip->registrar.retries);
			if (sip->registrar.retries > FETION_REGISTER_RETRY_MAX) {
				if (!purple_account_get_remember_password
				    (sip->gc->account))
					purple_account_set_password(sip->
								    gc->account,
								    NULL);
				purple_connection_error_reason(sip->gc,
							       PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
							       _
							       ("Incorrect password."));
				return TRUE;
			}
			tmp = sipmsg_find_header(msg, "W");
			purple_debug_info("befor fill_auth:", "%s\n", tmp);
			fill_auth(sip, tmp, &sip->registrar);
			sip->registerstatus = FETION_REGISTER_RETRY;
			do_register(sip);
		}
		break;
	default:
		if (sip->registerstatus != FETION_REGISTER_RETRY) {
			purple_debug_info("fetion",
					  "Unrecognized return code for REGISTER.%d\n",
					  msg->response);
			if (sip->registrar.retries > FETION_REGISTER_RETRY_MAX) {
				purple_connection_error_reason(sip->gc,
							       PURPLE_CONNECTION_ERROR_OTHER_ERROR,
							       _
							       ("Unknown server response."));
				return TRUE;
			}
			//sip->registerstatus = FETION_REGISTER_RETRY;
			//do_register(sip);
		}
		break;
	}
	return TRUE;
}

static gboolean dialog_match(struct sip_dialog *dialog, struct sipmsg *msg)
{
	const gchar *fromhdr;
	const gchar *tohdr;
	const gchar *callid;
	gchar *ourtag, *theirtag;
	gboolean match = FALSE;

	fromhdr = sipmsg_find_header(msg, "F");
	tohdr = sipmsg_find_header(msg, "T");
	callid = sipmsg_find_header(msg, "I");

	if (!fromhdr || !tohdr || !callid)
		return FALSE;

	ourtag = find_tag(tohdr);
	theirtag = find_tag(fromhdr);

	if (ourtag && theirtag &&
	    !strcmp(dialog->callid, callid) &&
	    !strcmp(dialog->ourtag, ourtag) &&
	    !strcmp(dialog->theirtag, theirtag))
		match = TRUE;

	g_free(ourtag);
	g_free(theirtag);

	return match;
}

static void
process_incoming_notify(struct fetion_account_data *sip, struct sipmsg *msg)
{
	gchar *from;
	const gchar *fromhdr;
	gchar *basicstatus_data;
	xmlnode *pidf;
	xmlnode *basicstatus = NULL, *tuple, *status;
	gboolean isonline = FALSE;
	struct fetion_buddy *b = NULL;
	const gchar *sshdr = NULL;

	fromhdr = sipmsg_find_header(msg, "F");
	from = parse_from(fromhdr);
	if (!from)
		return;

	b = g_hash_table_lookup(sip->buddies, from);
	if (!b) {
		g_free(from);
		purple_debug_info("fetion", "Could not find the buddy.\n");
		return;
	}

	if (b->dialog && !dialog_match(b->dialog, msg)) {
		/* We only accept notifies from people that
		 * we already have a dialog with.
		 */
		purple_debug_info("fetion",
				  "No corresponding dialog for notify--discard\n");
		g_free(from);
		return;
	}

	pidf = xmlnode_from_str(msg->body, msg->bodylen);

	if (!pidf) {
		purple_debug_info("fetion",
				  "process_incoming_notify: no parseable pidf\n");
		sshdr = sipmsg_find_header(msg, "Subscription-State");
		if (sshdr) {
			int i = 0;
			gchar **ssparts = g_strsplit(sshdr, ":", 0);
			while (ssparts[i]) {
				g_strchug(ssparts[i]);
				if (g_str_has_prefix(ssparts[i], "terminated")) {
					purple_debug_info("fetion",
							  "Subscription expired!");
					g_free(b->dialog->ourtag);
					g_free(b->dialog->theirtag);
					g_free(b->dialog->callid);
					g_free(b->dialog);
					b->dialog = NULL;

					purple_prpl_got_user_status
					    (sip->account, from, "offline",
					     NULL);
					break;
				}
				i++;
			}
			g_strfreev(ssparts);
		}
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
		g_free(from);
		return;
	}

	if ((tuple = xmlnode_get_child(pidf, "tuple")))
		if ((status = xmlnode_get_child(tuple, "status")))
			basicstatus = xmlnode_get_child(status, "basic");

	if (!basicstatus) {
		purple_debug_info("fetion",
				  "process_incoming_notify: no basic found\n");
		xmlnode_free(pidf);
		g_free(from);
		return;
	}

	basicstatus_data = xmlnode_get_data(basicstatus);

	if (!basicstatus_data) {
		purple_debug_info("fetion",
				  "process_incoming_notify: no basic data found\n");
		xmlnode_free(pidf);
		g_free(from);
		return;
	}

	if (strstr(basicstatus_data, "open"))
		isonline = TRUE;

	if (isonline)
		purple_prpl_got_user_status(sip->account, from, "available",
					    NULL);
	else
		purple_prpl_got_user_status(sip->account, from, "offline",
					    NULL);

	xmlnode_free(pidf);
	g_free(from);
	g_free(basicstatus_data);

	send_sip_response(sip->gc, msg, 200, "OK", NULL);
}

gchar *find_tag(const gchar * hdr)
{
	const gchar *tmp = strstr(hdr, ";tag="), *tmp2;

	if (!tmp)
		return NULL;
	tmp += 5;
	if ((tmp2 = strchr(tmp, ';'))) {
		return g_strndup(tmp, tmp2 - tmp);
	}
	return g_strdup(tmp);
}

static void
process_input_message(struct fetion_account_data *sip, struct sipmsg *msg)
{
	gboolean found = FALSE;
	if (msg->response == 0) {	/* request */
		if (!strcmp(msg->method, "M")) {
			process_incoming_message(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "BN")) {
			process_incoming_BN(sip, msg);
			found = TRUE;

		} else if (!strcmp(msg->method, "I")) {
			process_incoming_invite(sip, msg);
			found = TRUE;

		} else if (!strcmp(msg->method, "A")) {

		} else if (!strcmp(msg->method, "IN")) {
			const gchar *from;
			from = sipmsg_find_header(msg, "F");
			serv_got_attention(sip->gc, from, 0);
			found = TRUE;
		} else if (!strcmp(msg->method, "N")) {
			process_incoming_notify(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "B")) {
			send_sip_response(sip->gc, msg, 200, "OK", NULL);
			found = TRUE;

		} else if (!strcmp(msg->method, "O")) {
			send_sip_response(sip->gc, msg, 200, "OK", NULL);
			found = TRUE;

		} else {
			purple_debug_info("fetion:", "not implemented:\n%s\n",
					  msg->body);
		}
	} else {		/* response */
		struct transaction *trans = transactions_find(sip, msg);
		if (trans) {
			if (msg->response == 407) {
				gchar *resend, *auth;
				const gchar *ptmp;

				if (sip->proxy.retries > 3)
					return;
				sip->proxy.retries++;
				/* do proxy authentication */

				ptmp =
				    sipmsg_find_header(msg,
						       "Proxy-Authenticate");

				fill_auth(sip, ptmp, &sip->proxy);
				auth =
				    auth_header(sip, &sip->proxy,
						trans->msg->method,
						trans->msg->target);
				sipmsg_remove_header(trans->msg,
						     "Proxy-Authorization");
				sipmsg_add_header(trans->msg,
						  "Proxy-Authorization", auth);
				g_free(auth);
				resend = sipmsg_to_string(trans->msg);
				/* resend request */
				sendout_pkt(sip->gc, resend);
				g_free(resend);
			} else if (msg->response == 522) {

				if (!strcmp(trans->msg->method, "S")) {
					purple_debug_info("fetion:",
							  "AddBuddy:522\n");
					if (trans->callback)
						(trans->callback) (sip, msg,
								   trans);
				}
				found = TRUE;
			} else if (msg->response == 406 || msg->response == 480
				   || msg->response == 400) {
				//406 Not Acceptable
				purple_connection_error_reason(sip->gc,
							       PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
							       _
							       ("Error Connect.Try reconnect."));
			} else if ((!strcmp(trans->msg->method, "M"))
				   && (msg->response == 200
				       || msg->response == 280)) {
				transactions_remove(sip, trans);
				found = TRUE;
			} else {
				if (msg->response == 100) {
					/* ignore provisional response */
					purple_debug_info("fetion",
							  "got trying response\n");
				} else {
					sip->proxy.retries = 0;
					if (strcmp(trans->msg->method, "R") ==
					    0) {

						if (msg->response != 200) {
							/* denied for some other reason! */
							sip->
							    registrar.retries++;
						} else {
							const gchar *callid;

							callid =
							    sipmsg_find_header
							    (msg, "I");
							sip->registrar.retries =
							    0;
							sip->regcallid =
							    g_strdup(callid);
						}
					} else {
						if (msg->response == 401) {
							/* This is encountered when a generic (MESSAGE, NOTIFY, etc)
							 * was denied until further authorization is provided.
							 */
						} else {
							/* Reset any count of retries that may have
							 * accumulated in the above branch.
							 */
							sip->registrar.retries =
							    0;
						}
					}
					if (trans->callback) {
						/* call the callback to process response */
						(trans->callback) (sip, msg,
								   trans);
					}
					transactions_remove(sip, trans);
				}
			}
			found = TRUE;
		} else {
			purple_debug(PURPLE_DEBUG_MISC, "fetion",
				     "received response to unknown transaction");
		}
	}
	if (!found) {
		purple_debug(PURPLE_DEBUG_MISC, "fetion",
			     "received a unknown sip message with method %s and response %d\n",
			     msg->method, msg->response);
	}
}

static void
process_input(struct fetion_account_data *sip, struct sip_connection *conn)
{
	char *cur;
	char *dummy;
	struct sipmsg *msg;
	int restlen;
	cur = conn->inbuf;

	/* according to the RFC remove CRLF at the beginning */
	while (*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if (cur != conn->inbuf) {
		memmove(conn->inbuf, cur,
			conn->inbufused - (cur - conn->inbuf));
		conn->inbufused = strlen(conn->inbuf);
	}

	do {

		/* Received a full Header? */
		if ((cur = strstr(conn->inbuf, "\r\n\r\n")) != NULL) {
			time_t currtime = time(NULL);
			cur += 2;
			cur[0] = '\0';
			purple_debug_info("fetion",
					  "\n\nreceived - %s\n######\n%s\n#######\n\n",
					  ctime(&currtime), conn->inbuf);
			msg = sipmsg_parse_header(conn->inbuf);
			cur[0] = '\r';
			cur += 2;
			restlen = conn->inbufused - (cur - conn->inbuf);
			if (restlen >= msg->bodylen) {
				dummy = g_malloc(msg->bodylen + 1);
				memcpy(dummy, cur, msg->bodylen);
				dummy[msg->bodylen] = '\0';
				msg->body = dummy;
				cur += msg->bodylen;
				memmove(conn->inbuf, cur,
					conn->inbuflen - (cur - conn->inbuf));
				conn->inbufused = strlen(conn->inbuf);
			} else {
				sipmsg_free(msg);
				return;
			}
			purple_debug(PURPLE_DEBUG_MISC, "fetion",
				     "in process response response: %d\n",
				     msg->response);
			process_input_message(sip, msg);
		} else {
			purple_debug(PURPLE_DEBUG_MISC, "fetion",
				     "received a incomplete sip msg: %s\n",
				     conn->inbuf);
			break;
		}

	}
	while (conn->inbufused != 0);
}

void fetion_input_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct fetion_account_data *sip = gc->proto_data;
	int len;
	struct sip_connection *conn = connection_find(sip, source);
	if (!conn) {
		purple_debug_error("fetion", "Connection not found!\n");
		return;
	}

	if (conn->inbuflen < conn->inbufused + FETION_BUF_INC) {
		conn->inbuflen += FETION_BUF_INC;
		conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
	}

	len = read(source, conn->inbuf + conn->inbufused, FETION_BUF_INC - 1);

	if (len < 0 && errno == EAGAIN) {
		purple_debug_info("fetion", "fetion_input_cb: len<0\n");
		return;
	} else if (len <= 0) {
		purple_debug_info("fetion", "fetion_input_cb: read error\n");
		connection_remove(sip, source);
		if (sip->fd == source)
			sip->fd = -1;
		return;
	}

	conn->inbufused += len;
	conn->inbuf[conn->inbufused] = '\0';

	process_input(sip, conn);
}

static void login_cb(gpointer data, gint source, const gchar * error_message)
{
	PurpleConnection *gc = data;
	struct fetion_account_data *sip;
	struct sip_connection *conn;
	purple_debug_info("fetion:", "in login_cb\n");
	g_callid = 0;

	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		if (source >= 0)
			close(source);
		return;
	}

	if (source < 0) {
		purple_connection_error_reason(gc,
					       PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					       _("Could not connect"));
		return;
	}

	sip = gc->proto_data;
	sip->fd = source;

	conn = connection_create(sip, source);

	conn->inputhandler =
	    purple_input_add(sip->fd, PURPLE_INPUT_READ, fetion_input_cb, gc);
	do_register(sip);

}

guint fetion_ht_hash_nick(const char *nick)
{
	char *lc = g_utf8_strdown(nick, -1);
	guint bucket = g_str_hash(lc);
	g_free(lc);

	return bucket;
}

gboolean fetion_ht_equals_nick(const char *nick1, const char *nick2)
{
	return (purple_utf8_strcasecmp(nick1, nick2) == 0);
}

static void fetion_tcp_connect_listen_cb(int listenfd, gpointer data)
{
	struct fetion_account_data *sip = (struct fetion_account_data *)data;

	sip->listen_data = NULL;

	sip->listenfd = listenfd;
	if (sip->listenfd == -1) {
		purple_connection_error_reason(sip->gc,
					       PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					       _
					       ("Could not create listen socket"));
		return;
	}

	purple_debug_info("fetion", "listenfd: %d\n", sip->listenfd);

	/* open tcp connection to the server */
	if (purple_proxy_connect(sip->gc, sip->account, sip->realhostname,
				 sip->realport, login_cb, sip->gc) == NULL) {
		purple_connection_error_reason(sip->gc,
					       PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
					       _("Couldn't create socket"));
	}
}

void srvresolved(gpointer data)
{
	struct fetion_account_data *sip;
	int port;

	sip = data;
	sip->srv_query_data = NULL;

	port = purple_account_get_int(sip->account, "port", 8080);

	sip->realhostname = g_strdup(sip->MsgServer);
	sip->realport = sip->MsgPort;
	if (!sip->realport)
		sip->realport = 8080;

	/* TCP case */
	fetion_tcp_connect_listen_cb(0, sip);
}

static void fetion_close(PurpleConnection * gc)
{
	struct fetion_account_data *sip = gc->proto_data;

	if (sip) {
		/* unregister */
		if (sip->registerstatus == FETION_REGISTER_COMPLETE) {
			g_hash_table_foreach(sip->buddies,
					     (GHFunc) fetion_unsubscribe,
					     (gpointer) sip);

			do_register_exp(sip, 0);
		}
		connection_free_all(sip);
		transactions_free_all(sip);

		if (sip->query_data != NULL)
			purple_dnsquery_destroy(sip->query_data);

		if (sip->srv_query_data != NULL)
			purple_srv_cancel(sip->srv_query_data);

		if (sip->listen_data != NULL)
			purple_network_listen_cancel(sip->listen_data);

		g_free(sip->servername);
		g_free(sip->username);
		g_free(sip->password);
		g_free(sip->registrar.nonce);
		g_free(sip->registrar.target);
		g_free(sip->registrar.digest_session_key);
		g_free(sip->proxy.nonce);
		g_free(sip->proxy.target);
		g_free(sip->proxy.digest_session_key);
		if (sip->txbuf)
			purple_circ_buffer_destroy(sip->txbuf);
		g_free(sip->realhostname);
		if (sip->listenpa)
			purple_input_remove(sip->listenpa);
		if (sip->tx_handler)
			purple_input_remove(sip->tx_handler);
		if (sip->resendtimeout)
			purple_timeout_remove(sip->resendtimeout);
		if (sip->registertimeout)
			purple_timeout_remove(sip->registertimeout);
		if (sip->GetContactTimeOut)
			purple_timeout_remove(sip->GetContactTimeOut);
	}
	g_free(gc->proto_data);
	gc->proto_data = NULL;
}

/* not needed since privacy is checked for every subscribe */
static void dummy_add_deny(PurpleConnection * gc, const char *name)
{
}

static void dummy_permit_deny(PurpleConnection * gc)
{
}

static GList *fetion_actions(PurplePlugin * plugin, gpointer context)
{

	GList *m = NULL;
	PurplePluginAction *act;

	act = purple_plugin_action_new(_("设置心情短语..."),
				       fetion_set_impresa);
	m = g_list_append(m, act);
	m = g_list_append(m, NULL);

	return m;

}

static char *fetion_status_text(PurpleBuddy * buddy)
{
	PurplePresence *presence;
	PurpleStatus *status;

	presence = purple_buddy_get_presence(buddy);
	status = purple_presence_get_active_status(presence);

	if (!purple_presence_is_available(presence)
	    && !purple_presence_is_idle(presence)) {
		return g_strdup(purple_status_get_name(status));
	}

	return NULL;
}

static void fetion_temp_group_chat(PurpleBlistNode * node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(buddy->account);
	purple_debug(PURPLE_DEBUG_MISC, "fetion", "in fetion_tem_group_chat\n");
	CreateTempGroup(gc, buddy);
	//      serv_got_joined_chat(gc, swboard->chat_id, "Fetion Chat");
	//      purple_conv_chat_add_user(,purple_account_get_alias(buddy->account),NULL, PURPLE_CBFLAGS_NONE, TRUE);
}

static void send_sms_cb(PurpleBuddy * buddy, const char *text)
{
	PurpleConnection *gc;
	struct fetion_account_data *sip;
	char *to = NULL;
	to = g_strdup(purple_buddy_get_name(buddy));
	gc = purple_account_get_connection(buddy->account);
	sip = gc->proto_data;
	fetion_send_message(sip, to, text, NULL, TRUE);

	g_free(to);
}

static void fetion_send_sms(PurpleBlistNode * node, gpointer data)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	struct fetion_account_data *sip;

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *) node;
	gc = purple_account_get_connection(buddy->account);

	sip = gc->proto_data;

	purple_debug(PURPLE_DEBUG_MISC, "fetion", "in fetion_send_sms\n");

	purple_request_input(gc, NULL, _("Send a mobile message."), NULL,
			     NULL, TRUE, FALSE, NULL,
			     _("Send"), G_CALLBACK(send_sms_cb),
			     _("Close"), NULL,
			     purple_connection_get_account(gc),
			     purple_buddy_get_name(buddy), NULL, buddy);

}

static GList *fetion_buddy_menu(PurpleBuddy * buddy)
{
	GList *m = NULL;
	PurpleMenuAction *act;

	g_return_val_if_fail(buddy != NULL, NULL);

	act = purple_menu_action_new(_("Send to Mobile"),
				     PURPLE_CALLBACK(fetion_send_sms),
				     NULL, NULL);
	m = g_list_append(m, act);
	act = purple_menu_action_new(_("Initiate _Chat"),
				     PURPLE_CALLBACK(fetion_temp_group_chat),
				     NULL, NULL);
	m = g_list_append(m, act);
	//}

	return m;

}

static GList *fetion_blist_node_menu(PurpleBlistNode * node)
{
	if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		return fetion_buddy_menu((PurpleBuddy *) node);
	} else {
		return NULL;
	}
}

static void *fetion_find_group_with_id(struct fetion_account_data *sip,
				       int chat_id)
{
	GList *l;

	g_return_val_if_fail(sip != NULL, NULL);
	g_return_val_if_fail(chat_id >= 0, NULL);

	for (l = sip->tempgroup_id; l != NULL; l = l->next) {
		struct group_chat *g_chat;

		g_chat = l->data;

		if (g_chat->chatid == chat_id)
			return g_chat;
	}

	return NULL;
}

static void
fetion_chat_invite(PurpleConnection * gc, int id, const char *msg,
		   const char *who)
{
	gchar *body, *hdr, *fullto;
	gint xml_len;
	xmlnode *root, *son;
	struct fetion_account_data *sip = gc->proto_data;
	struct group_chat *g_chat = NULL;
	struct sip_dialog *dialog;

	g_chat = fetion_find_group_with_id(sip, id);
	g_return_if_fail(g_chat != NULL);
	dialog = g_new(struct sip_dialog, 1);
	dialog->callid = g_strdup(g_chat->callid);

	fullto = g_strdup_printf("T: %s\r\n", g_chat->groupname);

	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	son = xmlnode_new_child(root, "temporary-group");
	g_return_if_fail(son != NULL);
	xmlnode_set_attrib(son, "uri", g_chat->groupname);
	son = xmlnode_new_child(son, "participant");
	g_return_if_fail(son != NULL);

	xmlnode_set_attrib(son, "uri", who);

	hdr = g_strdup("N: AddParticipant\r\n");
	body = g_strdup_printf(xmlnode_to_str(root, &xml_len));
	purple_debug(PURPLE_DEBUG_MISC, "fetion", "in CreateTempGroup[%s]\n",
		     body);
	send_sip_request(sip->gc, "S", "", fullto, hdr, body, dialog, NULL);

	g_free(fullto);
	g_free(dialog->callid);
	g_free(dialog);
	g_free(body);
	g_free(hdr);
	xmlnode_free(root);

}

static void fetion_chat_leave(PurpleConnection * gc, int id)
{
	gchar *fullto;
	struct fetion_account_data *sip = gc->proto_data;
	struct group_chat *g_chat = NULL;
	struct sip_dialog *dialog;

	g_chat = fetion_find_group_with_id(sip, id);
	g_return_if_fail(g_chat != NULL);
	dialog = g_new(struct sip_dialog, 1);
	dialog->callid = g_strdup(g_chat->callid);
	fullto = g_strdup_printf("T: %s\r\n", g_chat->groupname);

	send_sip_request(sip->gc, "B", "", fullto, "", NULL, dialog, NULL);

	g_free(fullto);
	g_free(dialog->callid);
	g_free(dialog);
}

static int
fetion_chat_send(PurpleConnection * gc, int id, const char *message,
		 PurpleMessageFlags flags)
{
	struct fetion_account_data *sip = gc->proto_data;
	char *text = purple_unescape_html(message);
	struct group_chat *g_chat = NULL;
	struct sip_dialog *dialog;
	gchar *hdr;
	gchar *fullto;
	g_chat = fetion_find_group_with_id(sip, id);
	g_return_val_if_fail(g_chat != NULL, 1);
	dialog = g_new(struct sip_dialog, 1);
	dialog->callid = g_strdup(g_chat->callid);

	fullto = g_strdup_printf("T: %s\r\n", g_chat->groupname);

	purple_debug_info("fetion:chat sending ", "to:[%s] msg:[%s] \n",
			  g_chat->groupname, text);
	hdr = g_strdup("C: text/plain\r\n");

	//send_sip_request(sip->gc, "M", NULL, fullto, hdr, text, dialog, NULL);
	send_sip_request(sip->gc, "M", NULL, fullto, hdr, text, dialog,
			 (TransCallback) SendMsgTimeout_cb);
	serv_got_chat_in(sip->gc, id, purple_account_get_alias(sip->account),
			 0, message, time(NULL));

	g_free(dialog->callid);
	g_free(dialog);
	g_free(hdr);
	g_free(fullto);
	g_free(text);

	return 1;
}

static void fetion_get_info(PurpleConnection * gc, const char *who)
{
	//fixme  should call GetBuddyInfo()
	/*
	   PurpleNotifyUserInfo *user_info;
	   purple_debug(PURPLE_DEBUG_MISC, "fetion", "get info [%s]\n",who);
	   user_info = purple_notify_user_info_new();
	   purple_notify_user_info_add_section_header(user_info, _("General"));
	   purple_notify_userinfo(gc, who, user_info, NULL, NULL);
	   purple_notify_user_info_destroy(user_info);
	 */
	GetBuddyInfo((struct fetion_account_data *)gc->proto_data, who);

}

static GList *fetion_attention_types(PurpleAccount * account)
{
	PurpleAttentionType *attn;
	static GList *list = NULL;

	if (!list) {
		attn = g_new0(PurpleAttentionType, 1);
		attn->name = _("Nudge");
		attn->incoming_description = _("%s has nudged you!");
		attn->outgoing_description = _("Nudging %s...");
		list = g_list_append(list, attn);
	}

	return list;
}

static gboolean
fetion_send_attention(PurpleConnection * gc, const char *who, guint type)
{
	/* <is-composing><state>nudge</state></is-composing>
	 */
	struct fetion_account_data *sip = gc->proto_data;
	char *fullto = g_strdup_printf("T: %s\r\n", who);
	char *msg;
	PurpleBuddy *b;
	struct fetion_buddy *buddy = NULL;
	PurplePresence *presence;
	b = purple_find_buddy(sip->account, who);
	presence = purple_buddy_get_presence(b);
	if (purple_presence_is_status_primitive_active
	    (presence, PURPLE_STATUS_MOBILE))
		return TRUE;
	buddy = g_hash_table_lookup(sip->buddies, who);
	if (buddy == NULL) {
		buddy = g_new0(struct fetion_buddy, 1);
		buddy->name = g_strdup(who);
		g_hash_table_insert(sip->buddies, buddy->name, buddy);
	}
	if (buddy->dialog == NULL) {
		buddy->dialog = g_new0(struct sip_dialog, 1);
		buddy->dialog->callid = g_strdup_printf("%d", -1);
	}
	if (strncmp(buddy->dialog->callid, "-1", 2) == 0) {
		g_free(buddy->dialog->callid);
		buddy->dialog->callid = gencallid();
		SendInvite(sip, who);
	}

	msg = g_strdup("<is-composing><state>nudge</state></is-composing>");
	send_sip_request(sip->gc, "IN", NULL, fullto, NULL, msg, buddy->dialog,
			 NULL);
	g_free(msg);
	g_free(fullto);

	return TRUE;
}

static PurpleCmdRet
fetion_cmd_nudge(PurpleConversation * conv, const gchar * cmd,
		 gchar ** args, gchar ** error, void *data)
{
	PurpleAccount *account = purple_conversation_get_account(conv);
	PurpleConnection *gc = purple_account_get_connection(account);
	const gchar *username;

	username = purple_conversation_get_name(conv);

	serv_send_attention(gc, username, 0);

	return PURPLE_CMD_RET_OK;
}

static PurplePluginProtocolInfo prpl_info = {
	0,
	NULL,			/* user_splits */
	NULL,			/* protocol_options */
	{"png", 0, 0, 96, 96, 0, PURPLE_ICON_SCALE_SEND},	/* icon_spec */
	fetion_list_icon,	/* list_icon */
	NULL,			/* list_emblems */
	fetion_status_text,	/* status_text */
	NULL,			/* tooltip_text */
	fetion_status_types,	/* away_states */
	fetion_blist_node_menu,	/* blist_node_menu */
	NULL,			/* chat_info */
	NULL,			/* chat_info_defaults */
	fetion_login,		/* login */
	fetion_close,		/* close */
	fetion_im_send,		/* send_im */
	NULL,			/* set_info */
	NULL,			// fetion_typing,                  /* send_typing */
	fetion_get_info,	/* get_info */
	fetion_set_status,	/* set_status */
	NULL,			/* set_idle */
	NULL,			/* change_passwd */
	fetion_add_buddy,	/* add_buddy */
	NULL,			/* add_buddies */
	fetion_remove_buddy,	/* remove_buddy */
	fetion_remove_buddies,	/* remove_buddies */
	dummy_add_deny,		/* add_permit */
	dummy_add_deny,		/* add_deny */
	dummy_add_deny,		/* rem_permit */
	dummy_add_deny,		/* rem_deny */
	dummy_permit_deny,	/* set_permit_deny */
	NULL,			/* join_chat */
	NULL,			/* reject_chat */
	NULL,			/* get_chat_name */
	fetion_chat_invite,	/* chat_invite */
	fetion_chat_leave,	/* chat_leave */
	NULL,			/* chat_whisper */
	fetion_chat_send,	/* chat_send */
	fetion_keep_alive,	/* keepalive */
	NULL,			/* register_user */
	NULL,			/* get_cb_info */
	NULL,			/* get_cb_away */
	fetion_alias_buddy,	/* alias_buddy */
	fetion_change_group,	/* group_buddy */
	fetion_rename_group,	/* rename_group */
	NULL,			/* buddy_free */
	NULL,			/* convo_closed */
	NULL,			/* normalize */
	fetion_set_buddy_icon,	/* set_buddy_icon */
	fetion_remove_group,	/* remove_group */
	NULL,			/* get_cb_real_name */
	NULL,			/* set_chat_topic */
	NULL,			/* find_blist_chat */
	NULL,			/* roomlist_get_list */
	NULL,			/* roomlist_cancel */
	NULL,			/* roomlist_expand_category */
	NULL,			/* can_receive_file */
	NULL,			/* send_file */
	NULL,			/* new_xfer */
	NULL,			/* offline_message */
	NULL,			/* whiteboard_prpl_ops */
	fetion_send_raw,	/* send_raw */
	NULL,			/* roomlist_room_serialize */

	/* padding */
	NULL,
	fetion_send_attention,
	fetion_attention_types,
	NULL
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,				    /**< type           */
	NULL,						  /**< ui_requirement */
	0,						  /**< flags          */
	NULL,						  /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,			    /**< priority       */

	"prpl-fetion",					  /**< id             */
	"fetion",					  /**< name           */
	DISPLAY_VERSION,				  /**< version        */
	N_("SIP-C 2.0 Protocol Plugin"),		 /**  summary        */
	N_("The SIP-C 2.0 Protocol Plugin"),		 /**  description    */
	"gradetwo <gradetwo@gmail.com>",		/**< author         */
	"http://www.linuxsir.org",				       /**< homepage       */

	NULL,						  /**< load           */
	NULL,						  /**< unload         */
	NULL,						  /**< destroy        */

	NULL,						  /**< ui_info        */
	&prpl_info,					  /**< extra_info     */
	NULL,
	fetion_actions,

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void _init_plugin(PurplePlugin * plugin)
{
	PurpleAccountUserSplit *split;
	PurpleAccountOption *option;
	split = purple_account_user_split_new(_("Server"), "", '@');
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	option =
	    purple_account_option_string_new(_("Real Name"), "realname", "");
	prpl_info.protocol_options =
	    g_list_append(prpl_info.protocol_options, option);

	purple_cmd_register("nudge", "", PURPLE_CMD_P_PRPL,
			    PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_PRPL_ONLY,
			    "prpl-fetion", fetion_cmd_nudge,
			    _("nudge: nudge a user to get their attention"),
			    NULL);

}

PURPLE_INIT_PLUGIN(fetion, _init_plugin, info);
