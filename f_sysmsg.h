#ifndef _F_SYSMSG_H_
#define  _F_SYSMSG_H_
#include "fetion.h"
#include "f_buddy.h"
#include "f_chat.h"
#include "f_group.h"
#include "f_login.h"
#include "f_portrait.h"
#include "f_user.h"
#include "f_util.h"
void process_incoming_BN(struct fetion_account_data *sip, struct sipmsg *msg);
#endif
