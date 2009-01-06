#ifndef _F_GROUP_H_ 
#define  _F_GROUP_H_ 
#include "fetion.h"
#include "f_buddy.h"
#include "f_chat.h"
#include "f_login.h"
#include "f_sysmsg.h"
#include "f_portrait.h"
#include "f_user.h"
#include "f_util.h"
gboolean CreateGroup_cb(struct fetion_account_data *sip, struct sipmsg *msg, struct transaction *tc);
void fetion_add_group(PurpleConnection *gc,const gchar *who,const gchar *old_group, const gchar *new_group);
void fetion_change_group(PurpleConnection *gc, const char *who,const char *old_group, const char *new_group);
void fetion_remove_group(PurpleConnection *gc, PurpleGroup *group);
void fetion_rename_group(PurpleConnection *gc,const gchar *old_name,
		PurpleGroup *group, GList *moved_buddies);
#endif
