#ifndef _F_BUDDY_H_
#define _F_BUDDY_H_
#include "fetion.h"

#include "f_chat.h"
#include "f_group.h"
#include "f_login.h"
#include "f_portrait.h"
#include "f_user.h"
#include "f_util.h"
#include "f_sysmsg.h"

gboolean GetContactList_cb(struct fetion_account_data *sip,
			   struct sipmsg *msg, struct transaction *tc);
gboolean GetContactList(struct fetion_account_data *sip);
void AddMobileBuddy_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		       struct transaction *tc);
void AddMobileBuddy(struct fetion_account_data *sip, struct sipmsg *msg,
		    struct transaction *tc);
gboolean AddBuddy_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		     struct transaction *tc);
void fetion_add_buddy(PurpleConnection * gc, PurpleBuddy * buddy,
		      PurpleGroup * group);
void fetion_get_buddies_in_group(PurpleConnection * gc,
				 const gchar * group_name);
void fetion_remove_buddies(PurpleConnection * gc, GList * buddies,
			   GList * groups);
void fetion_remove_buddy(PurpleConnection * gc, PurpleBuddy * buddy,
			 PurpleGroup * group);
void fetion_alias_buddy(PurpleConnection * gc, const gchar * who,
			const gchar * alias);
void GetBuddyInfo(struct fetion_account_data *sip, const char *who);
#endif
