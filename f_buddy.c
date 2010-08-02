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
#include "f_buddy.h"

void GetAllBuddyInfo(struct fetion_account_data *sip);
gboolean
GetContactList_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		  struct transaction *tc)
{
	xmlnode *item, *group, *isc;
	const gchar *name_group, *group_id;
	PurpleBuddy *b;
	PurpleGroup *g = NULL;
	struct fetion_buddy *bs;
	struct group_attr *g_attr;
	gint len = msg->bodylen;

	purple_debug(PURPLE_DEBUG_MISC, "fetion",
		     "in process GetContactList response response: %d\n",
		     msg->response);
	switch (msg->response) {
	case 200:
		/*Convert the contact from XML to Purple Buddies */
		isc = xmlnode_from_str(msg->body, len);
		purple_debug_info("fetion:", "after xmlnode to str\n");
		group = xmlnode_get_child(isc, "contacts/buddy-lists");
		g_return_val_if_fail(group != NULL, FALSE);

		/* ToDo. Find for all groups */
		sip->GetContactFlag = 1;
		for ((group = xmlnode_get_child(group, "buddy-list")); group;
		     group = xmlnode_get_next_twin(group)) {
			purple_debug_info("fetion:", "buddy-list\n");
			name_group = xmlnode_get_attrib(group, "name");
			group_id = xmlnode_get_attrib(group, "id");
			g_return_val_if_fail(name_group != NULL, FALSE);
			purple_debug_info("fetion", "name_group->%s\n",
					  name_group);
			g = purple_find_group(name_group);
			if (!g) {
				g = purple_group_new(name_group);
			}
			g_attr = g_new0(struct group_attr, 1);
			g_attr->name = g_strdup(name_group);
			g_attr->id = g_strdup(group_id);
			g_hash_table_insert(sip->group, g_attr->id, g_attr);
			g_hash_table_insert(sip->group2id, g_attr->name,
					    g_attr);
		}

		group = xmlnode_get_child(isc, "contacts/buddies");
		g_return_val_if_fail(group != NULL, FALSE);

		for (item = xmlnode_get_child(group, "buddy"); item;
		     item = xmlnode_get_next_twin(item)) {
			const gchar *uri, *name;
			char *buddy_name;
			const gchar *g_id;
                        const gchar *relation_status;

			uri = xmlnode_get_attrib(item, "uri");
			name = xmlnode_get_attrib(item, "local-name");
			g_id = xmlnode_get_attrib(item, "buddy-lists");
                        relation_status = xmlnode_get_attrib(item, "relation-status");

			buddy_name = g_strdup_printf("%s", uri);
			if ((g_id == NULL) || (*g_id == '\0')
			    || strlen(g_id) > 1) {
				g = purple_find_group("未分组");
				if (!g)
					g = purple_group_new("未分组");
			} else {
				g_attr = g_hash_table_lookup(sip->group, g_id);
				g_return_val_if_fail(g_attr != NULL, FALSE);
				g = purple_find_group(g_attr->name);

				if (!g)
					g = purple_group_new(g_attr->name);
			}

			b = purple_find_buddy(sip->account, buddy_name);
			if (!b) {
				b = purple_buddy_new(sip->account, buddy_name,
						     NULL);
			}
			g_free(buddy_name);

			purple_blist_add_buddy(b, NULL, g, NULL);
			if (name != NULL && *name != '\0')
				purple_blist_alias_buddy(b, name);

                        if(strstr(relation_status, "0"))
                        {
                            if (name != NULL && *name != '\0')
                                purple_blist_alias_buddy(b, g_strconcat(name, "未通过好友请求"));
                            else
                                purple_blist_alias_buddy(b, g_strconcat(uri, "未通过好友请求"));
                        }
                        if(strstr(relation_status, "2"))
                        {
                            if (name != NULL && *name != '\0')
                                purple_blist_alias_buddy(b, g_strconcat(name, "拒绝好友请求"));
                            else
                                purple_blist_alias_buddy(b, g_strconcat(uri, "拒绝好友请求"));
                        }
                        purple_debug_info("relation_status:", "%s", relation_status);
			bs = g_new0(struct fetion_buddy, 1);
			bs->name = g_strdup(b->name);
			g_hash_table_insert(sip->buddies, bs->name, bs);

			purple_prpl_got_user_status(sip->account, uri, "mobile",
						    NULL);

		}
		group = xmlnode_get_child(isc, "contacts/mobile-buddies");
		g_return_val_if_fail(group != NULL, FALSE);

		for (item = xmlnode_get_child(group, "mobile-buddy"); item;
		     item = xmlnode_get_next_twin(item)) {
			const gchar *uri, *name;
			gchar *buddy_name;
			const gchar *g_id;
                        const gchar *relation_status;

			uri = xmlnode_get_attrib(item, "uri");
			name = xmlnode_get_attrib(item, "local-name");
			g_id = xmlnode_get_attrib(item, "buddy-lists");
                        relation_status = xmlnode_get_attrib(item, "relation-status");
                        purple_debug_info("relation_status:", "%s", relation_status);
                        

			buddy_name = g_strdup_printf("%s", uri);
			if ((g_id == NULL) || (*g_id == '\0')
			    || strlen(g_id) > 1) {
				g = purple_find_group("未分组");
				if (!g)
					g = purple_group_new("未分组");
			} else {
				g_attr = g_hash_table_lookup(sip->group, g_id);
				//g_return_val_if_fail(g_attr!=NULL,FALSE);
				if (g_attr == NULL)
					continue;
				g = purple_find_group(g_attr->name);
				if (!g)
					g = purple_group_new(g_attr->name);
			}

			b = purple_find_buddy(sip->account, buddy_name);
			if (!b) {
				b = purple_buddy_new(sip->account, buddy_name,
						     uri);
			}
			g_free(buddy_name);

			purple_blist_add_buddy(b, NULL, g, NULL);
			if (name != NULL && *name != '\0')
				purple_blist_alias_buddy(b, name);
			else
				purple_blist_alias_buddy(b, uri);
                    
                        if(strstr(relation_status, "0"))
                        {
                            if (name != NULL && *name != '\0')
                                purple_blist_alias_buddy(b, g_strconcat(name, "未通过好友请求"));
                            else
                                purple_blist_alias_buddy(b, g_strconcat(uri, "未通过好友请求"));

                        }
                        if(strstr(relation_status, "2"))
                        {
                            if (name != NULL && *name != '\0')
                                purple_blist_alias_buddy(b, g_strconcat(name, "拒绝好友请求"));
                            else
                                purple_blist_alias_buddy(b, g_strconcat(uri, "拒绝好友请求"));
                        }
                        purple_debug_info("relation_status:", "%s", relation_status);

			bs = g_new0(struct fetion_buddy, 1);
			bs->name = g_strdup(b->name);
			g_hash_table_insert(sip->buddies, bs->name, bs);
			purple_prpl_got_user_status(sip->account, uri, "mobile",
						    NULL);
		}

		fetion_subscribe_exp(sip, NULL);
                /* Plato Wu,2010/01/03: It cause crash! */
//		GetAllBuddyInfo(sip);
		//Add youself

		b = purple_find_buddy(sip->account, sip->uri);
		if (!b) {
			b = purple_buddy_new(sip->account, sip->uri, NULL);
		}

		purple_blist_add_buddy(b, NULL, g, NULL);
		purple_blist_alias_buddy(b, "轰炸自己");
		bs = g_new0(struct fetion_buddy, 1);
		bs->name = g_strdup(b->name);
		g_hash_table_insert(sip->buddies, bs->name, bs);

		purple_prpl_got_user_status(sip->account, sip->uri, "mobile",
					    NULL);

		xmlnode_free(isc);

		break;
	default:
		GetContactList(sip);
		break;
	}

	return TRUE;
}

gboolean GetContactList(struct fetion_account_data * sip)
{
	gchar *body, *hdr;

	if (sip->GetContactFlag == 1) {
		purple_timeout_remove(sip->GetContactTimeOut);
		sip->GetContactTimeOut = NULL;
		return TRUE;
	}
	hdr = g_strdup("N: GetContactList\r\n");
	body =
	    g_strdup
	    ("<args><contacts><buddy-lists /><buddies attributes=\"all\" /><mobile-buddies attributes=\"all\" /><chat-friends /><blacklist /></contacts></args>");
	send_sip_request(sip->gc, "S", "", "", hdr, body, NULL,
			 GetContactList_cb);

	g_free(body);
	g_free(hdr);

	return TRUE;
}

void
AddMobileBuddy_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		  struct transaction *tc)
{
	return;
}

void
AddMobileBuddy(struct fetion_account_data *sip, struct sipmsg *msg,
	       struct transaction *tc)
{
	gint xml_len;
	xmlnode *root, *son, *item;
	gchar *body;
	const gchar *uri, *name, *group_id;
	struct group_attr *g_attr = NULL;
	gchar *buddy_name;
	PurpleBuddy *b;
	PurpleGroup *g = NULL;
	struct fetion_buddy *bs;
	struct sipmsg *old = NULL;
	const gchar *real_name;

	real_name =
	    purple_account_get_string(sip->account, "realname", sip->username);

	if (!real_name || strlen(real_name) < 1) {
		real_name = sip->username;
	}

	g_return_if_fail(tc->msg != NULL);
	old = tc->msg;
	g_return_if_fail(old != NULL);
	purple_debug_info("fetion:", "AddMobileBuddy:oldmsg[%s]", old->body);
	root = xmlnode_from_str(old->body, old->bodylen);
	item = xmlnode_get_child(root, "contacts/buddies/buddy");
	g_return_if_fail(item != NULL);

	uri = xmlnode_get_attrib(item, "uri");
	name = xmlnode_get_attrib(item, "local-name");
	group_id = xmlnode_get_attrib(item, "buddy-lists");
	buddy_name = g_strdup_printf("%s", uri);
	g_attr = g_hash_table_lookup(sip->group, group_id);
	g_return_if_fail(g_attr != NULL);
	g = purple_find_group(g_attr->name);
	if (!g)
		g = purple_group_new(g_attr->name);

	b = purple_find_buddy(sip->account, buddy_name);
	if (!b) {
		b = purple_buddy_new(sip->account, buddy_name, NULL);
	}

	purple_blist_add_buddy(b, NULL, g, NULL);
	if (name != NULL && *name != '\0')
		purple_blist_alias_buddy(b, name);
	bs = g_new0(struct fetion_buddy, 1);
	bs->name = g_strdup(b->name);
	g_hash_table_insert(sip->buddies, bs->name, bs);

	xmlnode_free(root);

	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	son = xmlnode_new_child(root, "contacts");
	g_return_if_fail(son != NULL);
	son = xmlnode_new_child(son, "mobile-buddies");
	g_return_if_fail(son != NULL);
	item = xmlnode_new_child(son, "mobile-buddy");
	g_return_if_fail(item != NULL);

	xmlnode_set_attrib(item, "expose-mobile-no", "1");
	xmlnode_set_attrib(item, "expose-name", "1");
	xmlnode_set_attrib(item, "invite", "1");

	xmlnode_set_attrib(item, "uri", buddy_name);
	xmlnode_set_attrib(item, "buddy-lists", "1");
	//xmlnode_set_attrib(item,"desc",sip->mobileno);
	xmlnode_set_attrib(item, "desc", real_name);

	body = g_strdup_printf("%s",xmlnode_to_str(root, &xml_len));
	purple_debug_info("fetion:", "add_buddy:body=[%s]", body);

	send_sip_request(sip->gc, "S", "", "", "N: AddMobileBuddy\r\n", body,
			 NULL, (TransCallback) AddMobileBuddy_cb);

	g_free(buddy_name);
	xmlnode_free(root);
	g_free(body);

}

void
GetBuddyInfo_cb(struct fetion_account_data *sip, struct sipmsg *msg,
		struct transaction *tc)
{
	xmlnode *root, *son, *item;
	/* Plato Wu,2009/04/16: add mobile no into Buddy Info */
	const gchar *uri, *name;
	const gchar *nickname, *gender, *mobile_no;
	const gchar *impresa, *birthday;

	/* Chen Xing, 2010/05/08: Update portrait icon when clicked */
	const gchar *portrait_crc;

	PurpleNotifyUserInfo *user_info;


	purple_debug_info("fetion:", "GetBuddyInfo_cb[%s]", msg->body);
	root = xmlnode_from_str(msg->body, msg->bodylen);
	item = xmlnode_get_child(root, "contacts/contact");
	g_return_if_fail(item != NULL);

	uri = xmlnode_get_attrib(item, "uri");
	item = xmlnode_get_child(item, "personal");
	g_return_if_fail(item != NULL);

	nickname = xmlnode_get_attrib(item, "nickname");
	impresa = xmlnode_get_attrib(item, "impresa");
	gender = xmlnode_get_attrib(item, "gender");
	mobile_no = xmlnode_get_attrib(item, "mobile-no");

	portrait_crc = xmlnode_get_attrib(item, "portrait-crc");
	// Try to update portrait
//	if ((portrait_crc != NULL) && (strcmp(portrait_crc, "0") != 0))
//		CheckPortrait(sip, uri, portrait_crc);


	purple_debug(PURPLE_DEBUG_MISC, "fetion", "get info \n");
	user_info = purple_notify_user_info_new();
	purple_notify_user_info_add_pair(user_info, "昵称", nickname);
	//purple_notify_user_info_add_pair(user_info,"手机号码",mobileno);
	//purple_notify_user_info_add_pair(user_info,"飞信号码",uri);
	//purple_notify_user_info_add_section_header(user_info, _("General"));
	if ((gender != NULL) && (gender[0] == '1'))
		purple_notify_user_info_add_pair(user_info, "性别", "男");
	else if ((gender != NULL) && (gender[0] == '2'))
		purple_notify_user_info_add_pair(user_info, "性别", "女");
	else
		purple_notify_user_info_add_pair(user_info, "性别", "未知");

	purple_notify_user_info_add_pair(user_info, "手机号码", mobile_no);
	purple_notify_user_info_add_pair(user_info, "心情短语", impresa);

	purple_notify_userinfo(sip->gc, uri, user_info, NULL, NULL);
	purple_notify_user_info_destroy(user_info);

	xmlnode_free(root);

}

void GetBuddyInfo(struct fetion_account_data *sip, const char *who)
{
	gint xml_len;
	xmlnode *root, *son, *item;
	gchar *body;

//	GetAllBuddyInfo(sip);

	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	son = xmlnode_new_child(root, "contacts");
	xmlnode_set_attrib(son, "attributes", "all");
	//xmlnode_set_attrib(son,"extended-attributes","score-level");
	g_return_if_fail(son != NULL);
	item = xmlnode_new_child(son, "contact");
	g_return_if_fail(item != NULL);

	xmlnode_set_attrib(item, "uri", who);

	body = g_strdup_printf("%s",xmlnode_to_str(root, &xml_len));
	purple_debug_info("fetion:", "GetBuddyInfo:body=[%s]", body);

	send_sip_request(sip->gc, "S", "", "", "N: GetContactsInfo\r\n", body,
			 NULL, (TransCallback) GetBuddyInfo_cb);

	xmlnode_free(root);
	g_free(body);

}
void GetAllBuddyInfo(struct fetion_account_data *sip)
{
	gchar body[10240];
	GSList *buddy_list;
	memset(body, 0, sizeof(body));
	g_strlcat(body, "<args><contacts attributes=\"provisioning;impresa;mobile-no;nickname;name;gender;portrait-crc;ivr-enabled\" extended-attributes=\"score-level\">", 10240);

	buddy_list = purple_find_buddies(sip->account, NULL);
	for (; buddy_list; buddy_list = g_slist_next(buddy_list)) {
		if ((strncmp (((PurpleBuddy *) buddy_list->data)->name, "sip", 3) == 0) &&
				(strcmp (((PurpleBuddy *) buddy_list->data)->name, sip->uri) != 0))
		{
			g_strlcat(body, "<contact uri=\"", 10240);
			g_strlcat(body, ((PurpleBuddy *) buddy_list-> data)->name, 10240);
			g_strlcat(body, "\" />", 10240);
		} else
			continue;
	}


	g_strlcat(body, "</contacts></args>", 10240);

	send_sip_request(sip->gc, "S", "", "", "N: GetContactsInfo\r\n", body,
			 NULL, NULL);

}

gboolean
AddBuddy_cb(struct fetion_account_data *sip, struct sipmsg *msg,
	    struct transaction *tc)
{
	xmlnode *root, *item;
	const gchar *uri, *name, *group_id;
	struct group_attr *g_attr;
	gchar *buddy_name;
	PurpleBuddy *b;
	PurpleGroup *g = NULL;
	struct fetion_buddy *bs;

	if (msg->response != 522) {
		root = xmlnode_from_str(msg->body, msg->bodylen);
		item = xmlnode_get_child(root, "contacts/buddies/buddy");
		g_return_val_if_fail(item != NULL, FALSE);

		uri = xmlnode_get_attrib(item, "uri");
		name = xmlnode_get_attrib(item, "local-name");
		group_id = xmlnode_get_attrib(item, "buddy-lists");
		buddy_name = g_strdup_printf("%s", uri);
		g_attr = g_hash_table_lookup(sip->group, group_id);
		if (g_attr == NULL) {
			g = purple_find_group("未分组");
			if (!g)
				g = purple_group_new("未分组");
		} else {
			g = purple_find_group(g_attr->name);
			if (!g)
				g = purple_group_new(g_attr->name);
		}

		b = purple_find_buddy(sip->account, buddy_name);
		if (!b) {
			b = purple_buddy_new(sip->account, buddy_name, NULL);
		}
		g_free(buddy_name);

		purple_blist_add_buddy(b, NULL, g, NULL);
		if (name != NULL && *name != '\0')
			purple_blist_alias_buddy(b, name);
		bs = g_new0(struct fetion_buddy, 1);
		bs->name = g_strdup(b->name);
		g_hash_table_insert(sip->buddies, bs->name, bs);
		fetion_subscribe_exp(sip, bs);
	} else {
		purple_debug_info("fetion:",
				  "AddBuddy_cb:Try to Add as MobileBuddy\n");
		AddMobileBuddy(sip, msg, tc);
	}

	return TRUE;
}

void
fetion_add_buddy(PurpleConnection * gc, PurpleBuddy * buddy,
		 PurpleGroup * group)
{
	struct fetion_account_data *sip =
	    (struct fetion_account_data *)gc->proto_data;
	struct group_attr *g_attr = NULL;
	gint xml_len;
	xmlnode *root, *son, *item;
	gchar *body, *group_id;
	gchar *uri;
	const gchar *real_name;

	real_name =
	    purple_account_get_string(sip->account, "realname", sip->username);

	if (!real_name || strlen(real_name) < 1) {
		real_name = sip->username;
	}

	purple_debug_info("fetion:", "AddBuddy:[%s]\n", buddy->name);

	if (strcmp(group->name, "未分组") != 0) {
		g_attr = g_hash_table_lookup(sip->group2id, group->name);
		if (g_attr != NULL)
			group_id = g_strdup(g_attr->id);
		else
			group_id = "";

	} else
		group_id = "";
	if ((strncmp(buddy->name, "sip:", 4) == 0)
	    || (strncmp(buddy->name, "tel:", 4) == 0))
		return;
	/*
	   if(!g_hash_table_lookup(sip->buddies, buddy->name))
	   {
	   b = g_new0(struct fetion_buddy, 1);
	   purple_debug_info("fetion", "fetion_add_buddy %s\n", buddy->name);
	   b->name = g_strdup(buddy->name);
	   g_hash_table_insert(sip->buddies, b->name, b);
	   } else {
	   purple_debug_info("fetion", "buddy %s already in internal list\n", buddy->name);
	   }
	 */
	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	son = xmlnode_new_child(root, "contacts");
	g_return_if_fail(son != NULL);
	son = xmlnode_new_child(son, "buddies");
	g_return_if_fail(son != NULL);
	item = xmlnode_new_child(son, "buddy");
	g_return_if_fail(item != NULL);

	if (strlen(buddy->name) == 11) {
		purple_debug_info("fetion:", "add_buddy:got mobileno:[%s]\n",
				  buddy->name);
		if (!IsCMccNo(buddy->name)) {
			purple_debug_info("fetion:",
					  "add_buddy:Sorry,Only Suport China Mobile\n");
			return;
		}

		uri = g_strdup_printf("tel:%s", buddy->name);
		xmlnode_set_attrib(item, "expose-mobile-no", "1");
		xmlnode_set_attrib(item, "expose-name", "1");

	} else {
		purple_debug_info("fetion:",
				  "add_buddy:Don't panic!Just take it as uri\n");
		uri = g_strdup_printf("sip:%s", buddy->name);
	}
	if (buddy->alias != NULL)
		xmlnode_set_attrib(item, "local-name", buddy->alias);
	xmlnode_set_attrib(item, "uri", uri);
	xmlnode_set_attrib(item, "buddy-lists", group_id);
	xmlnode_set_attrib(item, "desc", real_name);

	body = g_strdup_printf("%s",xmlnode_to_str(root, &xml_len));
	purple_debug_info("fetion:", "add_buddy:body=[%s]", body);

	send_sip_request(sip->gc, "S", "", "", "N: AddBuddy\r\n", body, NULL,
			 AddBuddy_cb);
	purple_blist_remove_buddy(buddy);

	g_free(body);
	g_free(uri);

	/*
	   if(strncmp("sip:", buddy->name, 4))
	   {
	   gchar *buf = g_strdup_printf("%s", buddy->name);
	   purple_blist_rename_buddy(buddy, buf);
	   g_free(buf);
	   }

	 */
}

void
fetion_get_buddies_in_group(PurpleConnection * gc, const gchar * group_name)
{
	PurpleBlistNode *gnode, *cnode, *bnode;
	PurpleGroup *purple_group = purple_find_group(group_name);
	g_return_if_fail(purple_group != NULL);

	purple_debug_info("fetion", "fetion_get_buddies_in_group\n");
	gnode = (PurpleBlistNode *) purple_group;

	if (PURPLE_BLIST_NODE_IS_GROUP(gnode))
		for (cnode = gnode->child; cnode; cnode = cnode->next) {
			if (!PURPLE_BLIST_NODE_IS_CONTACT(cnode))
				continue;
			for (bnode = cnode->child; bnode; bnode = bnode->next) {
				if (!PURPLE_BLIST_NODE_IS_BUDDY(bnode))
					continue;
				if (((PurpleBuddy *) bnode)->account ==
				    gc->account)
					fetion_change_group(gc, ((PurpleBuddy *)
								 bnode)->name,
							    NULL, group_name);
			}
		}
}

void
fetion_remove_buddies(PurpleConnection * gc, GList * buddies, GList * groups)
{

}

void
fetion_remove_buddy(PurpleConnection * gc, PurpleBuddy * buddy,
		    PurpleGroup * group)
{
	xmlnode *root, *son, *item;
	gint xml_len;
	gchar *body;
	struct fetion_account_data *sip =
	    (struct fetion_account_data *)gc->proto_data;
	struct fetion_buddy *b = g_hash_table_lookup(sip->buddies, buddy->name);
	g_hash_table_remove(sip->buddies, buddy->name);

	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	son = xmlnode_new_child(root, "contacts");
	g_return_if_fail(son != NULL);
	son = xmlnode_new_child(son, "buddies");
	g_return_if_fail(son != NULL);
	item = xmlnode_new_child(son, "buddy");
	g_return_if_fail(son != NULL);
	xmlnode_set_attrib(item, "uri", buddy->name);
	body = g_strdup(xmlnode_to_str(root, &xml_len));

	send_sip_request(sip->gc, "S", "", "", "N: DeleteBuddy\r\n", body,
			 NULL, NULL);

	g_free(body);
	g_free(b->name);
	g_free(b);

	/***
	 * N: DeleteBuddy
	 * <args><contacts><buddies><buddy uri="" /></buddies></contacts></args>
	 *
	 */
}

void
fetion_alias_buddy(PurpleConnection * gc, const gchar * who,
		   const gchar * alias)
{
	gchar *body;
	gint xml_len;
	xmlnode *root, *son, *item;
	struct fetion_account_data *sip = gc->proto_data;

	if (strcmp(who, sip->uri) == 0)
		return;
	root = xmlnode_new("args");
	g_return_if_fail(root != NULL);
	son = xmlnode_new_child(root, "contacts");
	g_return_if_fail(son != NULL);
	son = xmlnode_new_child(son, "buddies");
	g_return_if_fail(son != NULL);
	item = xmlnode_new_child(son, "buddy");
	g_return_if_fail(item != NULL);

	xmlnode_set_attrib(item, "uri", who);
	xmlnode_set_attrib(item, "local-name", alias);

	body = g_strdup_printf("%s",xmlnode_to_str(root, &xml_len));

	send_sip_request(sip->gc, "S", "", "", "N: SetBuddyInfo\r\n", body,
			 NULL, NULL);

	g_free(body);
	xmlnode_free(root);
}
