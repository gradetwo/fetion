#ifndef _F_PORTRAIT_H_
#define  _F_PORTRAIT_H_
#include "fetion.h"
#include "f_buddy.h"
#include "f_chat.h"
#include "f_group.h"
#include "f_login.h"
#include "f_sysmsg.h"
#include "f_user.h"
#include "f_util.h"
void CheckPortrait(struct fetion_account_data *sip, const gchar * who,
		   const gchar * crc);
void DownLoadPortrait(gpointer data, gint source, const gchar * error_message);
void GetPortrait_cb(gpointer data, gint source, const gchar * error_message);
void GetPortrait(struct fetion_account_data *sip, struct fetion_buddy *buddy,
		 const gchar * host);
void UploadPortrait_cb(gpointer data, gint source, const gchar * error_message);
void UploadPortrait(gpointer data, gint source, const gchar * error_message);
void fetion_set_buddy_icon(PurpleConnection * gc, PurpleStoredImage * img);
#endif
