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
#include "f_sysmsg.h"


void process_incoming_BN(struct fetion_account_data *sip, struct sipmsg *msg)
{
	const gchar * new_crc;
	const gchar *nickname,*basicstatus,*event_type,*uri,*impresa;
	struct fetion_buddy * buddy =NULL;
	struct group_chat *g_chat=NULL;
	const gchar *from;
	gchar *cur,*alias,*nickbuf;
	xmlnode *root, *event_node,*item;
	xmlnode *basic,*personal;
	PurpleBuddy *b = NULL;



	root = xmlnode_from_str(msg->body, msg->bodylen);
	g_return_if_fail(root!=NULL);
purple_debug(PURPLE_DEBUG_MISC, "fetion", "in BN[%s]\n",msg->body);	
	event_node = xmlnode_get_child(root, "event");
	g_return_if_fail(event_node!=NULL);
	event_type = xmlnode_get_attrib(event_node,"type");
	if(strncmp(event_type,"PresenceChanged",15)==0)
	{
		for(item=xmlnode_get_child(event_node,"presence");item;item=xmlnode_get_next_twin(item))
		{
			uri = xmlnode_get_attrib(item,"uri");
			basic = xmlnode_get_child(item,"basic");
			if(basic !=NULL)
			{
				basicstatus = xmlnode_get_attrib(basic,"value");
				if((basicstatus!=NULL) && (strncmp(basicstatus,"0",1)!=0))
				{
					buddy = g_hash_table_lookup(sip->buddies,uri);
					if(buddy==NULL)
					{
						buddy = g_new0(struct fetion_buddy, 1);
						buddy->name = g_strdup(uri);
						g_hash_table_insert(sip->buddies, buddy->name, buddy);
					}
					buddy->dialog=NULL;
					switch(atoi(basicstatus))
					{
						case 100://away
							purple_prpl_got_user_status(sip->account, uri, "away", NULL);
							break;
						case 300://be right back
							purple_prpl_got_user_status(sip->account, uri, "brb", NULL);
							break;
						case 600://busy
						case 800:
						case 850:
							purple_prpl_got_user_status(sip->account, uri, "busy", NULL);
							break;
						case 150:
							purple_prpl_got_user_status(sip->account, uri, "lunch", NULL);
							break;
						default:
							purple_prpl_got_user_status(sip->account, uri, "available", NULL);

					}


				}
				else
					purple_prpl_got_user_status(sip->account, uri, "mobile", NULL);
			}

			personal = xmlnode_get_child(item,"personal");
			if(personal==NULL)
				continue;
			nickname = xmlnode_get_attrib(personal,"nickname");
			impresa = xmlnode_get_attrib(personal,"impresa");
			new_crc = xmlnode_get_attrib(personal,"portrait-crc");
			b = purple_find_buddy(sip->account, uri);
			g_return_if_fail(b!=NULL);
			if(nickname==NULL)
			{
				nickbuf = g_strdup(b->server_alias);
				cur = strstr(nickbuf,"--(");
				if(cur!=NULL)
					*cur = '\0';
				nickname = g_strdup(nickbuf);
				g_free(nickbuf);
			}
			if(impresa!=NULL && *impresa!='\0')
				alias = g_strdup_printf("%s--(%s)",nickname,impresa);
			else 
				alias = g_strdup_printf(nickname);
			if((b!=NULL) && (alias!=NULL) && (*alias!='\0'))
				purple_blist_server_alias_buddy(b,alias);

			if( (new_crc!=NULL) && (strcmp(new_crc,"0")!=0) )
				CheckPortrait(sip,uri,new_crc);


			g_free(alias);



		}

	}
	else if(strncmp(event_type,"UserEntered",11)==0)
	{
		from = sipmsg_find_header(msg,"F");

		if(from!=NULL && strncmp(from,"sip:TG",6)==0)
		{
			g_chat = g_hash_table_lookup(sip->tempgroup,from);
			g_return_if_fail(g_chat!=NULL);
		}
		for(item=xmlnode_get_child(event_node,"member");item;item=xmlnode_get_next_twin(item))
		{
			uri = xmlnode_get_attrib(item,"uri");
			b = purple_find_buddy(sip->account, uri);
			if( b == NULL)
				purple_conv_chat_add_user(PURPLE_CONV_CHAT(g_chat->conv),uri,NULL, PURPLE_CBFLAGS_NONE, TRUE);
			else
				purple_conv_chat_add_user(PURPLE_CONV_CHAT(g_chat->conv),purple_buddy_get_alias(b),NULL, PURPLE_CBFLAGS_NONE, TRUE);
		}

	}
	else if(strncmp(event_type,"UserLeft",11)==0)
	{
		from = sipmsg_find_header(msg,"F");

		if(from!=NULL && strncmp(from,"sip:TG",6)==0)
		{
			g_chat = g_hash_table_lookup(sip->tempgroup,from);
			g_return_if_fail(g_chat!=NULL);
		}
		for(item=xmlnode_get_child(event_node,"member");item;item=xmlnode_get_next_twin(item))
		{
			uri = xmlnode_get_attrib(item,"uri");
			b = purple_find_buddy(sip->account, uri);
			if( b == NULL)
				purple_conv_chat_remove_user(PURPLE_CONV_CHAT(g_chat->conv),uri,NULL);
			else
				purple_conv_chat_remove_user(PURPLE_CONV_CHAT(g_chat->conv),purple_buddy_get_alias(b),NULL);
		}

	}
	else if(strncmp(event_type,"deregistered",12)==0)
	{
		purple_connection_error_reason(sip->gc,
				PURPLE_CONNECTION_ERROR_NAME_IN_USE,
		        _("You have signed on from another location."));

	}

	xmlnode_free(root);

}
