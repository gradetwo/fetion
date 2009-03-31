#ifndef _F_USER_H_
#define  _F_USER_H_
#include "fetion.h"
#include "f_buddy.h"
#include "f_chat.h"
#include "f_group.h"
#include "f_login.h"
#include "f_sysmsg.h"
#include "f_portrait.h"
#include "f_util.h"
void send_impresa_request(PurpleConnection * gc, const gchar * text);
const gchar *fetion_get_impresa(struct fetion_account_data *sip);
void fetion_set_impresa(PurplePluginAction * action);
gboolean GetPersonalInfo_cb(struct fetion_account_data *sip,
			    struct sipmsg *msg, struct transaction *tc);
gboolean GetPersonalInfo(struct fetion_account_data *sip);
#endif
