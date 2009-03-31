#ifndef _F_CHAT_H_
#define _F_CHAT_H_
#include "fetion.h"
#include "f_buddy.h"
#include "f_group.h"
#include "f_login.h"
#include "f_sysmsg.h"
#include "f_portrait.h"
#include "f_user.h"
#include "f_util.h"
void SendMsgTimeout_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		       struct transaction *tc);
void SendInvite_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		   struct transaction *tc);
void SendInvite(struct fetion_account_data *sip, const gchar * who);
void process_incoming_invite(struct fetion_account_data *sip,
			     struct sipmsg *msg);
void fetion_send_message(struct fetion_account_data *sip, const gchar * to,
			 const gchar * msg, const gchar * type,
			 const gboolean sms);
void process_incoming_message(struct fetion_account_data *sip,
			      struct sipmsg *msg);
#endif
