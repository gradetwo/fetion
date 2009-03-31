/**
 * @file sipmsg.c
 *
 * purple
 *
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "internal.h"

#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "debug.h"
#include "notify.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"

#include "fetion.h"
#include "sipmsg.h"

struct sipmsg *sipmsg_parse_msg(const gchar * msg)
{
	const char *tmp = strstr(msg, "\r\n\r\n");
	char *line;
	struct sipmsg *smsg;

	if (!tmp)
		return NULL;

	line = g_strndup(msg, tmp - msg);

	smsg = sipmsg_parse_header(line);
	smsg->body = g_strdup(tmp + 4);

	g_free(line);
	return smsg;
}

struct sipmsg *sipmsg_parse_header(const gchar * header)
{
	struct sipmsg *msg = g_new0(struct sipmsg, 1);
	gchar **lines = g_strsplit(header, "\r\n", 0);
	gchar **parts;
	gchar *dummy;
	gchar *dummy2;
	gchar *tmp;
	const gchar *tmp2;
	int i = 1;
	if (!lines[0])
		return NULL;
	parts = g_strsplit(lines[0], " ", 3);
	if (!parts[0] || !parts[1] || !parts[2]) {
		g_strfreev(parts);
		g_strfreev(lines);
		g_free(msg);
		return NULL;
	}
	if (strstr(parts[0], "SIP-C/2.0")) {	/* numeric response */
		//fix me
		msg->method = g_strdup(parts[2]);
		msg->response = strtol(parts[1], NULL, 10);
	} else {		/* request */
		msg->method = g_strdup(parts[0]);
		msg->target = g_strdup(parts[1]);
		msg->response = 0;
	}
	g_strfreev(parts);
	for (i = 1; lines[i] && strlen(lines[i]) > 2; i++) {
		parts = g_strsplit(lines[i], ": ", 2);
		if (!parts[0] || !parts[1]) {
			g_strfreev(parts);
			g_strfreev(lines);
			g_free(msg);
			return NULL;
		}
		dummy = parts[1];
		dummy2 = 0;
		while (*dummy == ' ' || *dummy == '\t')
			dummy++;
		dummy2 = g_strdup(dummy);
		while (lines[i + 1]
		       && (lines[i + 1][0] == ' ' || lines[i + 1][0] == '\t')) {
			i++;
			dummy = lines[i];
			while (*dummy == ' ' || *dummy == '\t')
				dummy++;
			tmp = g_strdup_printf("%s %s", dummy2, dummy);
			g_free(dummy2);
			dummy2 = tmp;
		}
		//purple_debug_info("parse:","head:[%s] data[%s]\n",parts[0],dummy2);
		sipmsg_add_header(msg, parts[0], dummy2);
		g_strfreev(parts);
	}
	g_strfreev(lines);
	tmp2 = sipmsg_find_header(msg, "L");	//Content-Length
	if (tmp2 != NULL)
		msg->bodylen = strtol(tmp2, NULL, 10);
	if (msg->response) {
		tmp2 = sipmsg_find_header(msg, "Q");	//CSeq
		if (!tmp2) {
			/* SHOULD NOT HAPPEN */
			msg->method = 0;
		} else {
			parts = g_strsplit(tmp2, " ", 2);
			msg->method = g_strdup(parts[1]);
			g_strfreev(parts);
		}
	}
	return msg;
}

void sipmsg_print(const struct sipmsg *msg)
{
	GSList *cur;
	struct siphdrelement *elem;
	purple_debug(PURPLE_DEBUG_MISC, "fetion", "SIP MSG\n");
	purple_debug(PURPLE_DEBUG_MISC, "fetion",
		     "response: %d\nmethod: %s\nbodylen: %d\n", msg->response,
		     msg->method, msg->bodylen);
	if (msg->target)
		purple_debug(PURPLE_DEBUG_MISC, "fetion", "target: %s\n",
			     msg->target);
	cur = msg->headers;
	while (cur) {
		elem = cur->data;
		purple_debug(PURPLE_DEBUG_MISC, "fetion",
			     "name: %s value: %s\n", elem->name, elem->value);
		cur = g_slist_next(cur);
	}
}

char *sipmsg_to_string(const struct sipmsg *msg)
{
	GSList *cur;
	GString *outstr = g_string_new("");
	struct siphdrelement *elem;

	if (msg->response)
		g_string_append_printf(outstr, "SIP-C/2.0 %d Unknown\r\n",
				       msg->response);
	else
		g_string_append_printf(outstr, "%s %s SIP-C/2.0\r\n",
				       msg->method, msg->target);

	cur = msg->headers;
	while (cur) {
		elem = cur->data;
		g_string_append_printf(outstr, "%s: %s\r\n", elem->name,
				       elem->value);
		cur = g_slist_next(cur);
	}

	g_string_append_printf(outstr, "\r\n%s", msg->bodylen ? msg->body : "");

	return g_string_free(outstr, FALSE);
}

void
sipmsg_add_header(struct sipmsg *msg, const gchar * name, const gchar * value)
{
	struct siphdrelement *element = g_new0(struct siphdrelement, 1);
	element->name = g_strdup(name);
	element->value = g_strdup(value);
	msg->headers = g_slist_append(msg->headers, element);
}

void sipmsg_free(struct sipmsg *msg)
{
	struct siphdrelement *elem;
	while (msg->headers) {
		elem = msg->headers->data;
		msg->headers = g_slist_remove(msg->headers, elem);
		g_free(elem->name);
		g_free(elem->value);
		g_free(elem);
	}
	g_free(msg->method);
	g_free(msg->target);
	g_free(msg->body);
	g_free(msg);
}

void sipmsg_remove_header(struct sipmsg *msg, const gchar * name)
{
	struct siphdrelement *elem;
	GSList *tmp = msg->headers;
	while (tmp) {
		elem = tmp->data;
		if (g_ascii_strcasecmp(elem->name, name) == 0) {
			msg->headers = g_slist_remove(msg->headers, elem);
			g_free(elem->name);
			g_free(elem->value);
			g_free(elem);
			return;
		}
		tmp = g_slist_next(tmp);
	}
	return;
}

const gchar *sipmsg_find_header(struct sipmsg *msg, const gchar * name)
{
	GSList *tmp;
	struct siphdrelement *elem;
	tmp = msg->headers;
	while (tmp) {
		elem = tmp->data;
		if (g_ascii_strcasecmp(elem->name, name) == 0) {
			return elem->value;
		}
		tmp = g_slist_next(tmp);
	}
	return NULL;
}
