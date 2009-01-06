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
#include "f_group.h"



gboolean CreateGroup_cb(struct fetion_account_data *sip, struct sipmsg *msg, struct transaction *tc) 
{
	xmlnode *root,*item;
	struct group_attr *g_attr;
	const gchar *g_id,*g_name;

	root = xmlnode_from_str(msg->body,msg->bodylen);
	item = xmlnode_get_child(root,"contacts/buddy-lists/buddy-list");
	g_return_val_if_fail(item!=NULL,FALSE);
	g_attr = g_new0(struct group_attr,1);	
	g_id = xmlnode_get_attrib(item,"id");
	g_name = xmlnode_get_attrib(item,"name");
	if(g_id==NULL || g_name==NULL)	
		return FALSE;

	g_attr->id = g_strdup(g_id);
	g_attr->name = g_strdup(g_name);
	g_hash_table_insert(sip->group,g_attr->id,g_attr);
	g_hash_table_insert(sip->group2id,g_attr->name,g_attr);

	fetion_get_buddies_in_group(sip->gc,g_name);
	return TRUE;


}

void fetion_add_group(PurpleConnection *gc,const gchar *who,const gchar *old_group, const gchar *new_group)
{

	gchar *body;
	gint xml_len;
	xmlnode *root,*son,*item;
	struct fetion_account_data *sip = gc->proto_data;


	root = xmlnode_new("args");
	g_return_if_fail(root!=NULL);
	son = xmlnode_new_child(root,"contacts");
	g_return_if_fail(son!=NULL);
	son = xmlnode_new_child(son,"buddy-lists");
	g_return_if_fail(son!=NULL);
	item = xmlnode_new_child(son,"buddy-list");
	g_return_if_fail(item!=NULL);

	xmlnode_set_attrib(item,"name",new_group);


	body = g_strdup_printf(xmlnode_to_str(root,&xml_len));

	send_sip_request(sip->gc,"S","","","N: CreateBuddyList\r\n",body,NULL,CreateGroup_cb);

	g_free(body);
	xmlnode_free(root);

}
void fetion_change_group(PurpleConnection *gc, const char *who,const char *old_group, const char *new_group)
{
	gchar *g_id;
	gchar *body;
	gint xml_len;
	xmlnode *root,*son,*item;
	struct group_attr *g_attr;
	struct fetion_account_data *sip = gc->proto_data;
	g_attr = g_hash_table_lookup(sip->group2id,new_group);
	if(g_attr==NULL)
		return;
	if(g_attr!=NULL)
		g_id=g_strdup(g_attr->id);
	else
	{
		if(strcmp(new_group,"未分组")==0)
			g_id="";
		else
		{
			fetion_add_group(gc,who,old_group,new_group);
			return ;
		}
	}


	root = xmlnode_new("args");
	g_return_if_fail(root!=NULL);
	son = xmlnode_new_child(root,"contacts");
	g_return_if_fail(son!=NULL);
	son = xmlnode_new_child(son,"buddies");
	g_return_if_fail(son!=NULL);
	item = xmlnode_new_child(son,"buddy");
	g_return_if_fail(item!=NULL);

	xmlnode_set_attrib(item,"uri",who);
	xmlnode_set_attrib(item,"buddy-lists",g_id);


	body = g_strdup_printf(xmlnode_to_str(root,&xml_len));

	send_sip_request(sip->gc,"S","","","N: SetBuddyLists\r\n",body,NULL,NULL);

	g_free(body);
	xmlnode_free(root);

}
void fetion_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
	gchar *g_id;
	gchar *body;
	gint xml_len;
	xmlnode *root,*son,*item;
	struct group_attr *g_attr;
	struct fetion_account_data *sip = gc->proto_data;

	g_attr = g_hash_table_lookup(sip->group2id,group->name);
	if(g_attr==NULL)
		return;
	g_id = g_strdup(g_attr->id);
	g_hash_table_remove(sip->group2id,group->name);
	g_hash_table_remove(sip->group,g_id);
	g_free(g_attr);


	root = xmlnode_new("args");
	g_return_if_fail(root!=NULL);
	son = xmlnode_new_child(root,"contacts");
	g_return_if_fail(son!=NULL);
	son = xmlnode_new_child(son,"buddy-lists");
	g_return_if_fail(son!=NULL);
	item = xmlnode_new_child(son,"buddy-list");
	g_return_if_fail(item!=NULL);

	xmlnode_set_attrib(item,"id",g_id);
	xmlnode_set_attrib(item,"name",group->name);


	body = g_strdup_printf(xmlnode_to_str(root,&xml_len));
	purple_debug_info("fetion:","add_buddy:body=[%s]",body);

	send_sip_request(sip->gc,"S","","","N: DeleteBuddyList\r\n",body,NULL,NULL);

	g_free(body);
	xmlnode_free(root);
}
void fetion_rename_group(PurpleConnection *gc,const gchar *old_name,
		PurpleGroup *group, GList *moved_buddies)
{
	gchar *g_id;
	gchar *body;
	gint xml_len;
	xmlnode *root,*son,*item;
	struct group_attr *g_attr;
	struct fetion_account_data *sip = gc->proto_data;

	purple_debug_info("fetion:","rename_group:old[%s]\n",old_name);
	g_attr = g_hash_table_lookup(sip->group2id,old_name);
	g_id = g_strdup(g_attr->id);
	g_hash_table_remove(sip->group2id,old_name);
	g_hash_table_remove(sip->group,g_id);
	g_free(g_attr->name);
	g_attr->name = g_strdup(group->name);
	g_hash_table_insert(sip->group,g_attr->id,g_attr);
	g_hash_table_insert(sip->group2id,g_attr->name,g_attr);


	root = xmlnode_new("args");
	g_return_if_fail(root!=NULL);
	son = xmlnode_new_child(root,"contacts");
	g_return_if_fail(son!=NULL);
	son = xmlnode_new_child(son,"buddy-lists");
	g_return_if_fail(son!=NULL);
	item = xmlnode_new_child(son,"buddy-list");
	g_return_if_fail(item!=NULL);

	xmlnode_set_attrib(item,"id",g_attr->id);
	xmlnode_set_attrib(item,"name",g_attr->name);


	body = g_strdup_printf(xmlnode_to_str(root,&xml_len));
	purple_debug_info("fetion:","add_buddy:body=[%s]",body);

	send_sip_request(sip->gc,"S","","","N: SetBuddyListInfo\r\n",body,NULL,NULL);

	g_free(body);
	xmlnode_free(root);
}
