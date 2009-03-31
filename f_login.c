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
#include "f_login.h"

void
fetion_subscribe_exp(struct fetion_account_data *sip,
		     struct fetion_buddy *buddy)
{
	GSList *buddy_list;
	gchar body[10240], *hdr;

	memset(body, 0, sizeof(body));
	g_strlcat(body, "<args><subscription><contacts>", 10240);
	hdr = g_strdup_printf("N: presence\r\n");
	if (buddy == NULL) {
		buddy_list = purple_find_buddies(sip->account, NULL);
		for (; buddy_list; buddy_list = g_slist_next(buddy_list)) {
			if ((strncmp
			     (((PurpleBuddy *) buddy_list->data)->name, "sip",
			      3) == 0)
			    &&
			    (strcmp
			     (((PurpleBuddy *) buddy_list->data)->name,
			      sip->uri)
			     != 0)) {
				g_strlcat(body, "<contact uri=\"", 10240);
				purple_debug_info("fetion:sub", "name=[%s]\n",
						  ((PurpleBuddy *)
						   buddy_list->data)->name);
				g_strlcat(body,
					  ((PurpleBuddy *) buddy_list->
					   data)->name, 10240);
				g_strlcat(body, "\" />", 10240);
			} else
				continue;
		}

	} else {
		g_strlcat(body, "<contact uri=\"", 10240);
		g_strlcat(body, buddy->name, 10240);
		g_strlcat(body, "\" />", 10240);
	}
	g_strlcat(body, "</contacts>", 10240);
	g_strlcat(body,
		  "<presence><basic attributes=\"all\" /><personal attributes=\"all\" /><extended types=\"sms;location;listening;ring-back-tone\" /></presence></subscription><subscription><contacts><contact uri=\"",
		  10240);
	g_strlcat(body, sip->uri, 10240);
	g_strlcat(body,
		  "\" /></contacts><presence><extended types=\"sms;location;listening;ring-back-tone\" /></presence></subscription></args>",
		  10240);

	purple_debug_info("fetion:sub", "name=[%s]\n", body);

	send_sip_request(sip->gc, "SUB", "", "", hdr, body, NULL,
			 process_subscribe_response);

}

void do_register_exp(struct fetion_account_data *sip, gint expire)
{
	gchar *body = NULL;
	gchar *hdr = NULL;

	sip->reregister = time(NULL) + expire - 100;
	body =
	    g_strdup_printf
	    (" <args><device type=\"PC\" version=\"0\" client-version=\"3.3.0370\" /><caps value=\"fetion-im;im-session;temp-group\" /><events value=\"contact;permission;system-message\" /><user-info attributes=\"all\" /><presence><basic value=\"400\" desc=\"\" /></presence></args>");

	if (sip->registerstatus == FETION_REGISTER_COMPLETE) {
		if (expire == 0)
			hdr = g_strdup_printf("X: 0\r\n");
		g_free(body);
		body = NULL;
	} else if (sip->registerstatus == FETION_REGISTER_RETRY
		   && (sip->registrar.digest_session_key)) {
		hdr =
		    g_strdup_printf
		    ("A: Digest response=\"%s\",cnonce=\"%s\"\r\n",
		     sip->registrar.digest_session_key, sip->registrar.cnonce);
	} else {
		sip->registerstatus = FETION_REGISTER_SENT;
		hdr = NULL;
	}

	send_sip_request(sip->gc, "R", "", "", hdr, body, NULL,
			 process_register_response);
	if (body != NULL)
		g_free(body);
	if (hdr != NULL)
		g_free(hdr);
}

void do_register(struct fetion_account_data *sip)
{
	do_register_exp(sip, sip->registerexpire);
}

gboolean read_cookie(gpointer sodata, PurpleSslConnection * source, gint con)
{
	gchar buf[10240];
	gchar *cur = NULL;
	gchar *end = NULL;
	const gchar *uri = NULL;
	xmlnode *isc, *item;
	gint len, rcv_len;
	PurpleSslConnection *gsc;
	struct fetion_account_data *sip;
	sip = sodata;
	purple_debug_info("fetion:", "read cookie\n");
	gsc = (PurpleSslConnection *) source;
	rcv_len = purple_ssl_read(gsc, buf, 10240);
	if (rcv_len > 0) {
		buf[rcv_len] = '\0';
		purple_debug_info("fetion:", "read_cookie:%s\n", buf);
		cur = strstr(buf, "Cookie: ssic=");
		if (cur != NULL) {
			cur += 13;
			end = strstr(cur, ";");
			sip->ssic = g_strndup(cur, end - cur);
			purple_debug_info("fetion:", "read_cookie:[%s]\n",
					  sip->ssic);
			//      end=purple_url_encode(sip->ssic);
			//      purple_debug_info("fetion:","read_cookie:[%s]\n",end);
		}

		if ((cur = strstr(buf, "\r\n\r\n"))) {
			if (((strncmp(buf, "HTTP/1.1 200 OK\r\n", 17) != 0) &&
			     (strncmp(buf, "HTTP/1.1 100 Continue\r\n", 23) !=
			      0))) {
				purple_connection_error_reason(sip->gc,
							       PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
							       _
							       ("Invalid Password or Mobileno"));

				return FALSE;
			}

			cur += 4;
			len = strlen(cur);
			isc = xmlnode_from_str(cur, len);
			g_return_val_if_fail(isc != NULL, FALSE);
			item = xmlnode_get_child(isc, "user");
			g_return_val_if_fail(item != NULL, FALSE);
			uri = xmlnode_get_attrib(item, "uri");
			g_return_val_if_fail(uri != NULL, FALSE);
			sip->uri = g_strdup(uri);
			cur = strstr(uri, "@");
			g_return_val_if_fail(cur != NULL, FALSE);
			*cur = '\0';
			sip->username = g_strdup_printf("%s", uri + 4);
			purple_debug_info("fetion:", "cookie[%s]\n",
					  sip->username);
			purple_timeout_remove(sip->registertimeout);
			srvresolved(sip);

			xmlnode_free(isc);
			purple_ssl_close(gsc);

			return TRUE;

		}

	}
	purple_ssl_close(gsc);
	return FALSE;
}

gboolean Ssi_cb(gpointer sodata, PurpleSslConnection * gsc, gint con)
{
	gchar *head;
	struct fetion_account_data *sip;
	sip = sodata;
	purple_debug_info("Fetion:", "Ssi_cb\n");
	if (sip->mobileno != NULL) {
		head =
		    g_strdup_printf
		    ("GET /ssiportal/SSIAppSignIn.aspx?mobileno=%s&pwd=%s  HTTP/1.1\r\n"
		     "User-Agent: IIC2.0/pc 3.3.0370\r\n" "Host: %s\r\n"
		     "Connection: Keep-Alive\r\n\r\n", sip->mobileno,
		     sip->password, sip->SsicServer);
	} else {
		head =
		    g_strdup_printf
		    ("GET /ssiportal/SSIAppSignIn.aspx?sid=%s&pwd=%s  HTTP/1.1\r\n"
		     "User-Agent: IIC2.0/pc 3.3.0370\r\n" "Host: %s\r\n"
		     "Connection: Keep-Alive\r\n\r\n", sip->username,
		     sip->password, sip->SsicServer);
	}
	purple_ssl_write(gsc, head, strlen(head));

	purple_ssl_input_add(gsc, (PurpleSslInputFunction) read_cookie, sip);
	return TRUE;
}

void LoginToSsiPortal(gpointer sodata)
{
	PurpleSslConnection *gsc;
	struct fetion_account_data *sip;
	sip = sodata;
	sip->registerstatus = 0;	//avoid reconnected error
	purple_debug_info("Fetion:", "LoginToSsiPortal\n");

	gsc = purple_ssl_connect(sip->account, sip->SsicServer,
				 PURPLE_SSL_DEFAULT_PORT,
				 (PurpleSslInputFunction) Ssi_cb, NULL, sip);
	g_return_if_fail(gsc != NULL);

	purple_debug_info("Fetion:", "SSL connected\n");

}

/* ret:  0  ok
 * 	-1  no file
 *	-2  error in parse node
 *	-3  NULL mobile && NULL sid
 */
gint ParseCfg(struct fetion_account_data *sip)
{
	xmlnode *root, *son_node, *item;
	gchar *cur, *tail;
	gchar *msg_server, *ssic_server, *por_server, *upload_server;
	gchar *server_ver;
	gchar *cfg_filename;
	if (sip->mobileno != NULL)
		cfg_filename = g_strdup_printf("%s-SysCfg.xml", sip->mobileno);
	else if (sip->username != NULL)
		cfg_filename = g_strdup_printf("%s-SysCfg.xml", sip->username);
	else
		return -3;

	root = purple_util_read_xml_from_file(cfg_filename, "SysCfg.xml");
	if (root == NULL)
		return -1;
	son_node = xmlnode_get_child(root, "servers");
	g_return_val_if_fail(son_node != NULL, -2);
	server_ver = xmlnode_get_attrib(son_node, "version");
	sip->ServerVersion = g_strdup(server_ver);
	purple_debug_info("fetion", "systemconfig:cfg_ver[%s]\n",
			  sip->ServerVersion);
	item = xmlnode_get_child(son_node, "sipc-proxy");
	g_return_val_if_fail(item != NULL, -2);
	msg_server = g_strdup(xmlnode_get_data(item));
	item = xmlnode_get_child(son_node, "ssi-app-sign-in");
	g_return_val_if_fail(item != NULL, -2);
	ssic_server = g_strdup(xmlnode_get_data(item));

	item = xmlnode_get_child(root, "http-applications/get-portrait");
	g_return_val_if_fail(item != NULL, -2);
	por_server = g_strdup(xmlnode_get_data(item));

	item = xmlnode_get_child(root, "http-applications/set-portrait");
	g_return_val_if_fail(item != NULL, -2);
	upload_server = g_strdup(xmlnode_get_data(item));

	cur = strstr(msg_server, ":");
	*cur = '\0';
	cur++;
	sip->MsgServer = g_strdup(msg_server);
	sip->MsgPort = atoi(cur);

	cur = strstr(ssic_server, "/ssiportal");
	*cur = '\0';
	cur = ssic_server + 8;
	sip->SsicServer = g_strdup(cur);

	cur = strstr(por_server, "/HDS");
	*cur = '\0';
	tail = cur + 1;
	cur = por_server + 7;
	sip->PortraitServer = g_strdup(cur);
	cur = strstr(por_server, "/");
	*cur = '\0';
	sip->PortraitPrefix = g_strdup(tail);

	cur = strstr(upload_server, "/HDS");
	*cur = '\0';
	tail = cur + 1;
	cur = upload_server + 7;
	sip->UploadServer = g_strdup(cur);
	cur = strstr(upload_server, "/");
	*cur = '\0';
	sip->UploadPrefix = g_strdup(tail);

	son_node = xmlnode_get_child(root, "service-no");
	g_return_val_if_fail(son_node != NULL, -2);
	sip->ServiceNoVersion =
	    g_strdup(xmlnode_get_attrib(son_node, "version"));
	son_node = xmlnode_get_child(root, "parameters");
	g_return_val_if_fail(son_node != NULL, -2);
	sip->ParaVersion = g_strdup(xmlnode_get_attrib(son_node, "version"));
	son_node = xmlnode_get_child(root, "hints");
	g_return_val_if_fail(son_node != NULL, -2);
	sip->HintsVersion = g_strdup(xmlnode_get_attrib(son_node, "version"));
	son_node = xmlnode_get_child(root, "http-applications");
	g_return_val_if_fail(son_node != NULL, -2);
	sip->HttpAppVersion = g_strdup(xmlnode_get_attrib(son_node, "version"));
	son_node = xmlnode_get_child(root, "client-config");
	g_return_val_if_fail(son_node != NULL, -2);
	sip->ClientCfgVersion =
	    g_strdup(xmlnode_get_attrib(son_node, "version"));

	//LoginToSsiPortal(sip);
	xmlnode_free(root);
	g_free(msg_server);
	g_free(ssic_server);
	g_free(por_server);
	g_free(cfg_filename);

	return 0;
}

void RetriveSysCfg_cb(gpointer sodata, gint source, const gchar * error_message)
{
	gchar buf[10240];
	gchar *cur, *tail;
	gchar *msg_server, *ssic_server, *por_server, *upload_server;
	gchar *cfg_size = NULL;
	gchar *cfg_filename = NULL;
	struct fetion_account_data *sip = sodata;
	gint len, rcv_len;
	xmlnode *root, *son_node, *item;
	memset(buf, 0, 10240);
	rcv_len = read(source, buf, 10240);
	if (rcv_len > 0) {
		if ((cur = strstr(buf, "\r\n\r\n"))) {
			if (strncmp(buf, "HTTP/1.1 200 OK\r\n", 17) != 0)
				purple_connection_error_reason(sip->gc,
							       PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
							       _
							       ("Invalid Password or Mobileno"));
			cfg_size = get_token(buf, "Content-Length: ", "\r\n");
			if (cfg_size == NULL)
				return;
			cur += 4;
			sip->SysCfg.size = atoi(cfg_size);
			sip->SysCfg.buf = g_malloc(sip->SysCfg.size);
			len = rcv_len - (cur - buf);
			sip->SysCfg.rcv_len = len;
			memcpy((sip->SysCfg.buf), cur, len);

		} else {
			cur = sip->SysCfg.buf + sip->SysCfg.rcv_len;
			if ((sip->SysCfg.rcv_len) + rcv_len >
			    (sip->SysCfg.size))
				memcpy(cur, buf,
				       (sip->SysCfg.size) -
				       (sip->SysCfg.rcv_len));
			else
				memcpy(cur, buf, rcv_len);
			sip->SysCfg.rcv_len += rcv_len;
		}
	} else {
		purple_input_remove(sip->SysCfg.inpa);
		if (sip->mobileno != NULL)
			cfg_filename =
			    g_strdup_printf("%s-SysCfg.xml", sip->mobileno);
		else if (sip->username != NULL)
			cfg_filename =
			    g_strdup_printf("%s-SysCfg.xml", sip->username);
		else
			cfg_filename = g_strdup_printf("SysCfg.xml");

		root = xmlnode_from_str(sip->SysCfg.buf, sip->SysCfg.size);
		g_return_if_fail(root != NULL);
		son_node = xmlnode_get_child(root, "servers");
		if (son_node == NULL) {
			LoginToSsiPortal(sip);	//fixme
			return;
		}
		purple_debug_info("fetion", "systemconfig:after servers[%s]",
				  sip->SysCfg.buf);
		item = xmlnode_get_child(son_node, "sipc-proxy");
		g_return_if_fail(item != NULL);
		msg_server = g_strdup(xmlnode_get_data(item));
		item = xmlnode_get_child(son_node, "ssi-app-sign-in");
		g_return_if_fail(item != NULL);
		ssic_server = g_strdup(xmlnode_get_data(item));

		item =
		    xmlnode_get_child(root, "http-applications/get-portrait");
		g_return_if_fail(item != NULL);
		por_server = g_strdup(xmlnode_get_data(item));

		item =
		    xmlnode_get_child(root, "http-applications/set-portrait");
		g_return_if_fail(item != NULL);
		upload_server = g_strdup(xmlnode_get_data(item));

		cur = strstr(msg_server, ":");
		*cur = '\0';
		cur++;
		sip->MsgServer = g_strdup(msg_server);
		sip->MsgPort = atoi(cur);

		cur = strstr(ssic_server, "/ssiportal");
		*cur = '\0';
		cur = ssic_server + 8;
		sip->SsicServer = g_strdup(cur);

		cur = strstr(por_server, "/HDS");
		*cur = '\0';
		tail = cur + 1;
		cur = por_server + 7;
		sip->PortraitServer = g_strdup(cur);
		cur = strstr(por_server, "/");
		*cur = '\0';
		sip->PortraitPrefix = g_strdup(tail);

		cur = strstr(upload_server, "/HDS");
		*cur = '\0';
		tail = cur + 1;
		cur = upload_server + 7;
		sip->UploadServer = g_strdup(cur);
		cur = strstr(upload_server, "/");
		*cur = '\0';
		sip->UploadPrefix = g_strdup(tail);

		LoginToSsiPortal(sip);

		purple_util_write_data_to_file(cfg_filename, sip->SysCfg.buf,
					       sip->SysCfg.size);

		g_free(msg_server);
		g_free(ssic_server);
		g_free(por_server);
		g_free(upload_server);

	}

}

gint RetriveSysCfg(gpointer sodata, gint source, const gchar * error_message)
{
	gchar *data, *body;
	gint body_len, header_len, writed_len;
	gint fd;
	struct fetion_account_data *sip = sodata;

	if (sip->ServerVersion == NULL)
		sip->ServerVersion = g_strdup("0");
	if (sip->ServiceNoVersion == NULL)
		sip->ServiceNoVersion = g_strdup("0");
	if (sip->ParaVersion == NULL)
		sip->ParaVersion = g_strdup("0");
	if (sip->HintsVersion == NULL)
		sip->HintsVersion = g_strdup("0");
	if (sip->HttpAppVersion == NULL)
		sip->HttpAppVersion = g_strdup("0");
	if (sip->ClientCfgVersion == NULL)
		sip->ClientCfgVersion = g_strdup("0");

	fd = source;
	body_len = 75;
	if (sip->mobileno != NULL) {
		body =
		    g_strdup_printf
		    ("<config><user mobile-no=\"%s\" /><client type=\"PC\" version=\"3.3.0370\" platform=\"W5.1\" /><servers version=\"%s\" /><service-no version=\"%s\" /><parameters version=\"%s\" /><hints version=\"%s\" /><http-applications version=\"%s\" /><client-config version=\"%s\" /></config>\r\n\r\n",
		     sip->mobileno, sip->ServerVersion, sip->ServiceNoVersion,
		     sip->ParaVersion, sip->HintsVersion, sip->HttpAppVersion,
		     sip->ClientCfgVersion);
	} else {
		body =
		    g_strdup_printf
		    ("<config><user sid=\"%s\" /><client type=\"PC\" version=\"3.3.0370\" platform=\"W5.1\" /><servers version=\"%s\" /><service-no version=\"%s\" /><parameters version=\"%s\" /><hints version=\"%s\" /><http-applications version=\"%s\" /><client-config version=\"%s\" /></config>\r\n\r\n",
		     sip->username, sip->ServerVersion, sip->ServiceNoVersion,
		     sip->ParaVersion, sip->HintsVersion, sip->HttpAppVersion,
		     sip->ClientCfgVersion);
	}
	body_len = strlen(body);
	data = g_strdup_printf("POST /nav/getsystemconfig.aspx HTTP/1.1\r\n"
			       "User-Agent: IIC2.0/pc 3.3.0370\r\n"
			       "Host: %s\r\n"
			       "Content-Length: %d\r\n"
			       "Connection: Close\r\n\r\n",
			       sip->SysCfgServer, (int)body_len);
	header_len = strlen(data);
	data = g_realloc(data, header_len + body_len);
	memcpy(data + header_len, body, body_len);

	(sip->SysCfg).inpa =
	    purple_input_add(fd, PURPLE_INPUT_READ,
			     (PurpleInputFunction) RetriveSysCfg_cb, sip);
	writed_len = write(fd, data, header_len + body_len);

	//purple_debug_info("Fetion:","send:%s\n",data);

	g_free(data);
	g_free(body);

	return 0;
}

void fetion_login(PurpleAccount * account)
{
	PurpleConnection *gc;
	struct fetion_account_data *sip;
	gchar **userserver;
	gint ret;

	const char *username = purple_account_get_username(account);
	gc = purple_account_get_connection(account);
	gc->proto_data = sip = g_new0(struct fetion_account_data, 1);
	sip->gc = gc;
	sip->tg = 0;		//temp group chat id
	sip->cseq = 0;
	sip->account = account;
	sip->registerexpire = 400;
	sip->reregister = time(NULL) + 100;
	sip->txbuf = purple_circ_buffer_new(0);
	sip->impresa = NULL;
	sip->icon_buf = purple_circ_buffer_new(0);
	sip->GetContactFlag = 0;

	purple_debug_info("Fetion:", "shit\n");
	userserver = g_strsplit(username, "@", 2);
	purple_connection_set_display_name(gc, userserver[0]);
	if (IsCMccNo(userserver[0])) {
		sip->username = NULL;
		sip->mobileno = g_strdup(userserver[0]);
	} else {
		sip->mobileno = NULL;
		sip->username = g_strdup(userserver[0]);
	}
	//      sip->servername = g_strdup(userserver[1]);
	sip->SysCfgServer = g_strdup("nav.fetion.com.cn");
	sip->password = g_strdup(purple_connection_get_password(gc));
	g_strfreev(userserver);

	sip->buddies =
	    g_hash_table_new((GHashFunc) fetion_ht_hash_nick,
			     (GEqualFunc) fetion_ht_equals_nick);
	sip->tempgroup =
	    g_hash_table_new((GHashFunc) fetion_ht_hash_nick,
			     (GEqualFunc) fetion_ht_equals_nick);
	sip->group =
	    g_hash_table_new((GHashFunc) fetion_ht_hash_nick,
			     (GEqualFunc) fetion_ht_equals_nick);
	sip->group2id =
	    g_hash_table_new((GHashFunc) fetion_ht_hash_nick,
			     (GEqualFunc) fetion_ht_equals_nick);

	purple_connection_update_progress(gc, _("Connecting"), 1, 2);

	/* TODO: Set the status correctly. */
	sip->status = g_strdup("available");
	sip->registertimeout =
	    purple_timeout_add(60000, (GSourceFunc) LoginToSsiPortal, sip);
	//Try to get systemconfig
	sip->ServerVersion = NULL;
	sip->ServiceNoVersion = NULL;
	sip->ParaVersion = NULL;
	sip->HttpAppVersion = NULL;
	sip->ClientCfgVersion = NULL;
	sip->HintsVersion = NULL;
	ret = ParseCfg(sip);
	//if(ret!=0)
	sip->SysCfg.conn =
	    purple_proxy_connect(NULL, sip->account, sip->SysCfgServer, 80,
				 (PurpleProxyConnectFunction) RetriveSysCfg,
				 sip);

}
