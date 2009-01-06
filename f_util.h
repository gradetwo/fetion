#ifndef _F_UTIL_H_
#define  _F_UTIL_H_
#include "fetion.h"
#include "f_buddy.h"
#include "f_chat.h"
#include "f_group.h"
#include "f_login.h"
#include "f_sysmsg.h"
#include "f_portrait.h"
#include "f_user.h"

gchar * gencnonce(void);
gchar * gencallid(void);
gchar * get_token(const gchar *str, const gchar *start, const gchar *end);
gchar *fetion_cipher_digest_calculate_response(
		const gchar *sid,
		const gchar *domain,
		const gchar *password,
		const gchar *nonce,
		const gchar *cnonce);
gboolean IsCMccNo(gchar *name);
gboolean IsUnicomNo(gchar *name);
gchar *auth_header(struct fetion_account_data *sip,
		struct sip_auth *auth, const gchar *method, const gchar *target);
gchar *parse_attribute(const gchar *attrname, const gchar *source);
 void fill_auth(struct fetion_account_data *sip, const gchar *hdr, struct sip_auth *auth);
gchar *parse_from(const gchar *hdr);
#endif
