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
#include "f_smiley.h"

void fetion_got_custom_smiley()
{
	PurpleConversation *conv;
	PurpleConnection *gc;
	const char *who;

	gc = slpcall->slplink->session->account->gc;
	who = slpcall->slplink->remote_user;

	if ((conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, who, gc->account))) {

		purple_conv_custom_smiley_write(conv, slpcall->data_info, data, size);
		purple_conv_custom_smiley_close(conv, slpcall->data_info);
	}

}

void fetion_got__chat()
{
	conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, who, 
			session->account);

	if (!conv) {
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, session->account, who);
	}

	if (purple_conv_custom_smiley_add(conv, smile, "sha1", sha1, TRUE)) {
		fetion_request_custom_smiley(slplink, smile, fetion_got_custom_smiley, NULL, obj);
	}

}

void fetion_send_custom_smiley()
{
}

void fetion_check_custom_smiley()
{
}

void fetion_upload_custom_smiley()
{
}
