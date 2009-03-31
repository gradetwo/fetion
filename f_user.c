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
#include "f_user.h"

void send_impresa_request(PurpleConnection * gc, const gchar * text)
{
	xmlnode *root, *item;
	gchar *body, *new_impresa;
	gint xml_len;
	struct fetion_account_data *sip = gc->proto_data;
	if (text == NULL || *text == '\0')
		new_impresa = g_strdup_printf(" ");
	else
		new_impresa = g_strdup(text);
	//      if(sip->impresa!=NULL)
	//              g_free(sip->impresa);
	sip->impresa = g_strdup(new_impresa);

	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	item = xmlnode_new_child(root, "personal");
	g_return_if_fail(item != NULL);
	xmlnode_set_attrib(item, "impresa", new_impresa);

	body = g_strdup(xmlnode_to_str(root, &xml_len));
	send_sip_request(gc, "S", "", "", "N: SetPersonalInfo\r\n", body, NULL,
			 NULL);

	xmlnode_free(root);
	g_free(body);

}

const gchar *fetion_get_impresa(struct fetion_account_data *sip)
{
	g_return_val_if_fail(sip != NULL, NULL);

	return sip->impresa;
}

void fetion_set_impresa(PurplePluginAction * action)
{
	PurpleConnection *gc;
	struct fetion_account_data *sip;

	gc = (PurpleConnection *) action->context;
	sip = gc->proto_data;

	gc = (PurpleConnection *) action->context;
	purple_request_input(gc, NULL, _("Set your impresa."),
			     _("This is the impresa that other  buddies will "
			       "see you as."),
			     fetion_get_impresa(sip), FALSE, FALSE, NULL,
			     _("OK"), G_CALLBACK(send_impresa_request),
			     _("Cancel"), NULL,
			     purple_connection_get_account(gc), NULL, NULL, gc);

}

gboolean
GetPersonalInfo_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		   struct transaction *tc)
{
	xmlnode *root, *personal;
	const gchar *nickname;
	const gchar *impresa;
	purple_debug(PURPLE_DEBUG_MISC, "fetion",
		     "in process GetPersonalInfo response response: %d\n",
		     msg->response);
	switch (msg->response) {
	case 200:
		root = xmlnode_from_str(msg->body, msg->bodylen);
		g_return_val_if_fail(root != NULL, FALSE);
		personal = xmlnode_get_child(root, "personal");
		g_return_val_if_fail(personal != NULL, FALSE);
		nickname = xmlnode_get_attrib(personal, "nickname");
		if ((nickname != NULL) && (*nickname != '\0'))
			purple_account_set_alias(sip->account, nickname);
		impresa = xmlnode_get_attrib(personal, "impresa");
		if ((impresa != NULL) && (*impresa != '\0'))
			sip->impresa = g_strdup(impresa);
		else
			sip->impresa = g_strdup_printf(" ");
		xmlnode_free(root);

		//purple_util_write_data_to_file("PersonalInfo.xml",msg->body,msg->bodylen);

		break;
	default:
		GetPersonalInfo(sip);

		break;
	}
	return TRUE;
}

gboolean GetPersonalInfo(struct fetion_account_data * sip)
{
	gchar *body, *hdr;
	hdr = g_strdup("N: GetPersonalInfo\r\n");
	body =
	    g_strdup
	    ("<args><personal attributes=\"all\" /><services version=\"\" attributes=\"all\" /><config version=\"0\" attributes=\"all\" /><mobile-device attributes=\"all\" /></args>");

	send_sip_request(sip->gc, "S", "", "", hdr, body, NULL,
			 GetPersonalInfo_cb);

	g_free(body);
	g_free(hdr);
	return TRUE;
}
