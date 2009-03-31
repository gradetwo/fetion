#ifndef _F_LOGIN_H_
#define  _F_LOGIN_H_
#include "fetion.h"
#include "f_buddy.h"
#include "f_chat.h"
#include "f_group.h"
#include "f_sysmsg.h"
#include "f_portrait.h"
#include "f_user.h"
#include "f_util.h"
void fetion_subscribe_exp(struct fetion_account_data *sip,
			  struct fetion_buddy *buddy);
void do_register_exp(struct fetion_account_data *sip, gint expire);
void do_register(struct fetion_account_data *sip);
gboolean read_cookie(gpointer sodata, PurpleSslConnection * source, gint con);
gboolean Ssi_cb(gpointer sodata, PurpleSslConnection * gsc, gint con);
void LoginToSsiPortal(gpointer sodata);
gint ParseCfg(struct fetion_account_data *sip);
void RetriveSysCfg_cb(gpointer sodata, gint source,
		      const gchar * error_message);
gint RetriveSysCfg(gpointer sodata, gint source, const gchar * error_message);
void fetion_login(PurpleAccount * account);
#endif
