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
#include "f_util.h"

extern gint g_callid;

gchar * gencnonce(void)
{
	return g_strdup_printf("%04X%04X%04X%04X%04X%04X%04X%04X",rand() & 0xFFFF,rand() & 0xFFFF,rand() & 0xFFFF,rand() & 0xFFFF,rand() & 0xFFFF,rand() & 0xFFFF,rand() & 0xFFFF,rand() & 0xFFFF);
}


gchar * gencallid(void)
{
	return g_strdup_printf("%d",++g_callid);
}

gchar * get_token(const gchar *str, const gchar *start, const gchar *end)
{
	const char *c, *c2; 

	if ((c = strstr(str, start)) == NULL)
		return NULL;

	c += strlen(start);

	if (end != NULL)
	{
		if ((c2 = strstr(c, end)) == NULL)
			return NULL;

		return g_strndup(c, c2 - c);
	}
	else
	{
		/* This has to be changed */
		return g_strdup(c);
	}

}


gchar *fetion_cipher_digest_calculate_response(
		const gchar *sid,
		const gchar *domain,
		const gchar *password,
		const gchar *nonce,
		const gchar *cnonce)
{
	PurpleCipher *cipher;
	PurpleCipherContext *context;
	gchar *hash1; /* We only support MD5. */
	gchar *hash2; /* We only support MD5. */
	gchar temp[33];
	gchar *response; /* We only support MD5. */
	guchar digest[16];

	g_return_val_if_fail(sid != NULL, NULL);
	g_return_val_if_fail(domain    != NULL, NULL);
	g_return_val_if_fail(password != NULL, NULL);
	g_return_val_if_fail(nonce    != NULL, NULL);
	g_return_val_if_fail(cnonce    != NULL, NULL);


	cipher = purple_ciphers_find_cipher("md5");
	g_return_val_if_fail(cipher != NULL, NULL);

	context = purple_cipher_context_new(cipher, NULL);

	purple_cipher_context_append(context, (guchar *)sid, strlen(sid));
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)domain, strlen(domain));
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)password, strlen(password));

	purple_cipher_context_digest(context, sizeof(digest), digest, NULL);
	purple_cipher_context_destroy(context);

	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, digest, 16);
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)nonce, strlen(nonce));
	purple_cipher_context_append(context, (guchar *)":", 1);
	purple_cipher_context_append(context, (guchar *)cnonce, strlen(cnonce));
	purple_cipher_context_digest_to_str(context, sizeof(temp), temp, NULL);
	purple_cipher_context_destroy(context);
	hash1=g_ascii_strup(temp,32);


	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context,(guchar *)"REGISTER",8 );
	purple_cipher_context_append(context,(guchar *)":",1 );
	purple_cipher_context_append(context,(guchar *)sid, strlen(sid) );
	purple_cipher_context_digest_to_str(context, sizeof(temp), temp, NULL);

	hash2=g_ascii_strup(temp,32);

	purple_cipher_context_destroy(context);
	context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context,(guchar *)hash1,strlen(hash1) );
	purple_cipher_context_append(context,(guchar *)":",1 );
	purple_cipher_context_append(context, (guchar *)nonce, strlen(nonce));
	purple_cipher_context_append(context,(guchar *)":",1 );
	purple_cipher_context_append(context,(guchar *)hash2,strlen(hash2) );
	purple_cipher_context_digest_to_str(context, sizeof(temp), temp, NULL);
	purple_cipher_context_destroy(context);

	response=g_ascii_strup(temp,32);
	return g_strdup(response);
}

gboolean IsCMccNo(gchar *name)
{
	gint  mobileNo;
	gint head;
	gchar *szMobile;
	szMobile=g_strdup(name);
	szMobile[7]='\0';
	mobileNo = atoi(szMobile);

	head = mobileNo / 10000;
	purple_debug_info("fetion:","IsCMccNo:[%d]\n",mobileNo);
	g_free(szMobile);
	if ((mobileNo <= 1300000) || (mobileNo >= 1600000))
	{
		return FALSE;
	}
	if (((head < 134) || (head > 139)) && (((head != 159) && (head != 158)) && (head != 157)))
	{   
		return (head == 150);
	}   
	return TRUE;

}

gboolean IsUnicomNo(gchar *name)
{
	gint mobileNo;
	gint head;
	gchar *szMobile;
	szMobile=g_strdup(name);
	szMobile[7]='\0';
	mobileNo = atoi(szMobile);
	head = mobileNo / 10000;
	g_free(szMobile);
	if ((mobileNo <= 1300000) || (mobileNo >= 1600000))
	{
		return FALSE;
	}
	if (((head>=130 ) && (head <=133))||head==153)
	{   
		return TRUE;
	}   

	return FALSE;

}

gchar *auth_header(struct fetion_account_data *sip,
		struct sip_auth *auth, const gchar *method, const gchar *target)
{
	gchar *ret;
	ret = g_strdup_printf("Digest response=\"%s\",cnonce=\"%s\"",auth->digest_session_key,auth->cnonce );
	return ret;
}

gchar *parse_attribute(const gchar *attrname, const gchar *source)
{
	const char *tmp ;
	char *retval = NULL;
	int len = strlen(attrname);
	tmp = strstr(source,attrname);

	if(tmp)
		retval = g_strdup(tmp+len);

	return retval;
}

 void fill_auth(struct fetion_account_data *sip, const gchar *hdr, struct sip_auth *auth)
{
	gchar *tmp;

	if(!hdr)
	{
		purple_debug_error("fetion", "fill_auth: hdr==NULL\n");
		return;
	}

	auth->type = 1;
	auth->cnonce = gencnonce();
	auth->domain = g_strdup("fetion.com.cn");
	if((tmp = parse_attribute("nonce=\"", hdr))) 
		auth->nonce = g_ascii_strup(tmp,32);
	purple_debug(PURPLE_DEBUG_MISC, "fetion", "nonce: %s domain: %s\n", auth->nonce ? auth->nonce : "(null)", auth->domain ? auth->domain : "(null)");
	if(auth->domain) 
		auth->digest_session_key = fetion_cipher_digest_calculate_response(
				sip->username, auth->domain, sip->password, auth->nonce, auth->cnonce);

}

gchar *parse_from(const gchar *hdr)
{
	gchar *from;
	const gchar *tmp, *tmp2 = hdr;

	if(!hdr) return NULL;
	purple_debug_info("fetion", "parsing address out of %s\n", hdr);
	tmp = strchr(hdr, '<');

	/* i hate the different SIP UA behaviours... */
	if(tmp)
	{ /* sip address in <...> */
		tmp2 = tmp + 1;
		tmp = strchr(tmp2, '>');
		if(tmp)
		{
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			purple_debug_info("fetion", "found < without > in From\n");
			return NULL;
		}
	} else {
		tmp = strchr(tmp2, ';');
		if(tmp)
		{
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			from = g_strdup(tmp2);
		}
	}
	purple_debug_info("fetion", "got %s\n", from);
	return from;
}
