/** $Id: match.c 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 * 
 * @file match.c
 * 
 * The different match functions, for proxy destinations, 
 * aliases (proxy_pass_reverse) and cache times are in here.
 * The functions in this file are mostly copied directly from match.c from the
 * original Wodan for Apache 1.3
 */

#include "datatypes.h"
#include "match.h"

#include "httpd.h"
#include "apr_tables.h"
#include <string.h>

wodan2_proxy_alias_t* alias_longest_match(wodan2_config_t *config, char *uri)
{
	wodan2_proxy_alias_t *longest, *list;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan2_proxy_alias_t *) config->proxy_passes_reverse->elts;
	for(i=0; i < config->proxy_passes_reverse->nelts; i++)
	{
		int l = (int) strlen(list[i].path);

		if(l > length && strncmp(list[i].path, uri, l) == 0)
		{
			longest = &list[i];
			length = l;
		}
	}
	return longest;
}

wodan2_proxy_destination_t* destination_longest_match(wodan2_config_t *config, 
	char *uri)
{
	wodan2_proxy_destination_t *longest, *list;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan2_proxy_destination_t *) config->proxy_passes->elts;
	for(i=0; i < config->proxy_passes->nelts; i++)
	{
		int l = (int) strlen(list[i].path);

		if(l > length && strncmp(list[i].path, uri, l) == 0)
		{
			longest = &list[i];
			length = l;
		}
	}
	return longest;	
}

wodan2_default_cachetime_t* default_cachetime_longest_match(wodan2_config_t *config,
	char *uri)
{
	wodan2_default_cachetime_t *longest, *list;
	int length, i;

	longest = NULL;
	length = 0;
	list = (wodan2_default_cachetime_t*) config->default_cachetimes->elts;
	for(i=0; i < config->default_cachetimes->nelts; i++)
	{
		int l = (int) strlen(list[i].path);

		if(l > length && strncmp(list[i].path, uri, l) == 0)
		{
			longest = &list[i];
			length = l;
		}
	}
	return longest;
} 

wodan2_default_cachetime_regex_t* 
default_cachetime_regex_match(wodan2_config_t *config, char *uri)
{
	wodan2_default_cachetime_regex_t *list;
	int i;
	
	list = (wodan2_default_cachetime_regex_t*) 
		config->default_cachetimes_regex->elts;
	for (i = 0; i < config->default_cachetimes_regex->nelts; i++) {
		if (ap_regexec(list[i].uri_pattern, uri, 0, NULL, 0) == 0)
			return &list[i];
	}
	return NULL;
}
	
wodan2_default_cachetime_header_t*
default_cachetime_header_match(wodan2_config_t *config, apr_table_t *headers)
{
	wodan2_default_cachetime_header_t *list;
	const char *header;
	char *header_value;
	int i;

	
	list = (wodan2_default_cachetime_header_t*)
		config->default_cachetimes_header->elts;
	for (i = 0; i < config->default_cachetimes_header->nelts; i++) {
		header = list[i].header;
		header_value = (char*) apr_table_get(headers, header);
		
		if (header_value != NULL)
			if (ap_regexec(list[i].header_value_pattern, header_value, 0, 
				    NULL, 0) == 0)
				return &list[i];
	}
	return NULL;
}
		
