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
#include "f_gchat.h"
void CreateTempGroup_cb()
{
}

void CreateTempGroup(PurpleConnection * gc, PurpleBuddy * buddy)
{
	gchar *body, *hdr;
	gint xml_len;
	xmlnode *root, *son, *item;
	struct fetion_account_data *sip = gc->proto_data;

	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	son = xmlnode_new_child(root, "participants");
	g_return_if_fail(son != NULL);
	son = xmlnode_new_child(son, "participant");
	g_return_if_fail(son != NULL);

	xmlnode_set_attrib(son, "uri", buddy->name);

	hdr = g_strdup("N: CreateTemporaryGroup\r\nK: text/html-fragment\r\n");
	body = g_strdup_printf(xmlnode_to_str(root, &xml_len));
	purple_debug(PURPLE_DEBUG_MISC, "fetion", "in CreateTempGroup[%s]\n",
		     body);
	send_sip_request(sip->gc, "S", "", "", hdr, body, NULL,
			 CreateTempGroup_cb);

	g_free(body);
	g_free(hdr);
	xmlnode_free(root);

}
