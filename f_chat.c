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

#include "sipmsg.h"
#include "dnssrv.h"
#include "ntlm.h"

#include "sipmsg.h"
#include "f_chat.h"

void
SendMsgTimeout_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		  struct transaction *tc)
{
	PurpleConversation *conv;
	const gchar *who;
	who = sipmsg_find_header(msg, "T");
	if (!who)
		return;

	conv =
	    purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, who,
						  sip->gc->account);
	if (conv) {
		purple_conversation_write(conv, NULL,
					  _
					  ("Message may have not been sent,because of timeout! "),
					  PURPLE_MESSAGE_ERROR, time(NULL));
		purple_conversation_write(conv, NULL, msg->body,
					  PURPLE_MESSAGE_RAW, time(NULL));
	}

}

void
SendInvite_cb(struct fetion_account_data *sip, struct sipmsg *msg,
	      struct transaction *tc)
{
	const gchar *to;
	gchar *fullto;

	to = sipmsg_find_header(msg, "T");
	fullto = g_strdup_printf("T: %s\r\n", to);

	purple_debug_info("fetion:", "SendACK:\n");
	send_sip_request(sip->gc, "A", "", fullto, NULL, NULL, NULL, NULL);

	g_free(fullto);
}

void SendInvite(struct fetion_account_data *sip, const gchar * who)
{
	gchar *body, *hdr, *fullto;
	const gchar *my_ip;
	gint my_port;
	struct fetion_buddy *buddy = NULL;
	if (strncmp("sip:", who, 4) == 0)
		fullto = g_strdup_printf("T: %s\r\n", who);
	else
		return;
	buddy = g_hash_table_lookup(sip->buddies, who);
	g_return_if_fail(buddy != NULL);
	my_ip = purple_network_get_my_ip(sip->fd);
	my_port = purple_network_get_port_from_fd(sip->fd);
	purple_debug_info("fetion:", "SendInvite:[%s:%d]\n", my_ip, my_port);
	hdr = g_strdup_printf("K: text/html-fragment\r\n"
			      "K: multiparty\r\n" "K: nudge\r\n");
	body = g_strdup_printf("v=0\r\n"
			       "o=-0 0 IN %s:%d\r\n"
			       "s=session\r\n"
			       "c=IN IP4 %s:%d\r\n"
			       "t=0 0\r\n"
			       "m=message %d sip %s\r\n",
			       my_ip, my_port, my_ip, my_port, my_port,
			       sip->uri);

	purple_debug_info("fetion:", "SendInvite:[%s]\n", body);
	send_sip_request(sip->gc, "I", "", fullto, hdr, body, buddy->dialog,
			 (TransCallback) SendInvite_cb);

	g_free(fullto);
	g_free(hdr);
	g_free(body);
}

void
process_incoming_invite(struct fetion_account_data *sip, struct sipmsg *msg)
{
	const gchar *to, *callid;
	gchar *body;
	const gchar *my_ip;
	gint my_port;
	struct group_chat *g_chat;
	struct fetion_buddy *buddy = NULL;
	my_ip = purple_network_get_my_ip(sip->fd);
	my_port = purple_network_get_port_from_fd(sip->fd);
	purple_debug_info("fetion:", "Invite:[%s:%d]\n", my_ip, my_port);
	body = g_strdup_printf("v=0\r\n"
			       "o=-0 0 IN %s:%d\r\n"
			       "s=session\r\n"
			       "c=IN IP4 %s:%d\r\n"
			       "t=0 0\r\n"
			       "m=message %d sip %s\r\n",
			       my_ip, my_port, my_ip, my_port, my_port,
			       sip->uri);

	purple_debug_info("fetion:", "Invite:answer[%s]\n", body);
	send_sip_response(sip->gc, msg, 200, "OK", body);

	callid = sipmsg_find_header(msg, "I");
	to = sipmsg_find_header(msg, "F");
	if (strncmp(to, "sip:TG", 6) != 0) {
		buddy = g_hash_table_lookup(sip->buddies, to);
		if (buddy == NULL) {
			buddy = g_new0(struct fetion_buddy, 1);
			buddy->name = g_strdup(to);
			g_hash_table_insert(sip->buddies, buddy->name, buddy);
		}
		if (buddy->dialog == NULL)
			buddy->dialog = g_new0(struct sip_dialog, 1);
		else
			g_free(buddy->dialog->callid);
		buddy->dialog->callid = g_strdup(callid);
	} else {
		g_chat = g_new0(struct group_chat, 1);
		g_chat->chatid = sip->tg++;
		g_chat->callid = g_strdup(callid);
		g_chat->groupname = g_strdup(to);
		g_hash_table_insert(sip->tempgroup, g_chat->groupname, g_chat);
		sip->tempgroup_id = g_list_append(sip->tempgroup_id, g_chat);

		g_chat->conv =
		    serv_got_joined_chat(sip->gc, g_chat->chatid,
					 "Fetion Chat");
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(g_chat->conv),
					  purple_account_get_alias
					  (sip->account), NULL,
					  PURPLE_CBFLAGS_NONE, TRUE);
	}
	g_free(body);
}

void
fetion_send_message(struct fetion_account_data *sip, const gchar * to,
		    const gchar * msg, const gchar * type, const gboolean sms)
{
	gchar *hdr;
	gchar *fullto;
	gint self_flag, sms_flag;
	struct fetion_buddy *buddy = NULL;
	PurplePresence *presence;
	PurpleBuddy *b;

	self_flag = 0;
	sms_flag = 0;
	buddy = g_hash_table_lookup(sip->buddies, to);
	if (buddy == NULL) {
		buddy = g_new0(struct fetion_buddy, 1);
		buddy->name = g_strdup(to);
		g_hash_table_insert(sip->buddies, buddy->name, buddy);
	}
	if (buddy->dialog == NULL) {
		buddy->dialog = g_new0(struct sip_dialog, 1);
		buddy->dialog->callid = g_strdup_printf("%d", -1);
	}
	if (!sms) {
		if (strcmp(sip->uri, to) != 0) {
			b = purple_find_buddy(sip->account, to);
			presence = purple_buddy_get_presence(b);
			if (!purple_presence_is_status_primitive_active
			    (presence, PURPLE_STATUS_MOBILE)) {
				if (strncmp(buddy->dialog->callid, "-1", 2) ==
				    0) {
					g_free(buddy->dialog->callid);
					buddy->dialog->callid = gencallid();
					SendInvite(sip, to);
				}
				sms_flag = 0;
			} else {
				if (strncmp(buddy->dialog->callid, "-1", 2) !=
				    0) {
					g_free(buddy->dialog->callid);
					buddy->dialog->callid =
					    g_strdup_printf("%d", -1);
				}
				sms_flag = 1;
			}

		} else
			self_flag = 1;
	} else {
		if (strncmp(buddy->dialog->callid, "-1", 2) != 0) {
			g_free(buddy->dialog->callid);
			buddy->dialog->callid = g_strdup_printf("%d", -1);
		}
		sms_flag = 1;
	}

	if ((sms_flag == 0) && (self_flag != 1)
	    && (strncmp("sip:", to, 4) == 0))
		fullto = g_strdup_printf("T: %s\r\n", to);
	else
		fullto = g_strdup_printf("T: %s\r\nN: SendSMS\r\n", to);

	purple_debug_info("fetion:sending ", "to:[%s] msg:[%s]\n", to, msg);
	if (type)
		hdr = g_strdup_printf("C: %s\r\n", type);
	else
		hdr = g_strdup("C: text/plain\r\n");

	send_sip_request(sip->gc, "M", NULL, fullto, hdr, msg, buddy->dialog,
			 (TransCallback) SendMsgTimeout_cb);
	g_free(hdr);
	g_free(fullto);
}

void
process_incoming_message(struct fetion_account_data *sip, struct sipmsg *msg)
{
	const gchar *from;
	struct group_chat *g_chat = NULL;
	const gchar *contenttype;
	gboolean found = FALSE;

	from = sipmsg_find_header(msg, "F");
	if (!from)
		return;

	purple_debug(PURPLE_DEBUG_MISC, "fetion", "got message from %s: %s\n",
		     from, msg->body);

	contenttype = sipmsg_find_header(msg, "C");
	if (!contenttype || !strncmp(contenttype, "text/plain", 10)
	    || !strncmp(contenttype, "text/html-fragment", 18)) {
		if (strncmp(from, "sip:TG", 6) == 0) {
			g_chat = g_hash_table_lookup(sip->tempgroup, from);
			g_return_if_fail(g_chat != NULL);
			from = sipmsg_find_header(msg, "SO");
			g_return_if_fail(from != NULL);
			serv_got_chat_in(sip->gc, g_chat->chatid, from, 0,
					 msg->body, time(NULL));
		} else
			serv_got_im(sip->gc, from, msg->body, 0, time(NULL));
		sipmsg_remove_header(msg, "C");
		sipmsg_remove_header(msg, "D");
		sipmsg_remove_header(msg, "K");
		sipmsg_remove_header(msg, "XI");
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
		found = TRUE;
	}

	if (!found) {
		purple_debug_info("fetion", "got unknown mime-type\n");

		contenttype = sipmsg_find_header(msg, "N");
		if (contenttype == NULL
		    || strncmp(contenttype, "system-message", 14) != 0)
			send_sip_response(sip->gc, msg, 415,
					  "Unsupported media type", NULL);
	}
}
