/**
 * (c) 2000-2006 IC&S, The Netherlands
 * @file util.c
 *
 * Implements different utility functions that are used by Wodan2
 */
 
#include "datatypes.h"
#include "match.h"
#include "util.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include "apr_date.h"
#include "apr_file_info.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_user.h"

#ifndef APR_HAS_USER
#define APR_HAS_USER
#endif

#define SECONDS_IN_MINUTE 60
#define SECONDS_IN_HOUR (60 * SECONDS_IN_MINUTE)
#define SECONDS_IN_DAY (24 * SECONDS_IN_HOUR)
#define SECONDS_IN_WEEK (7 * SECONDS_IN_DAY)

/**
 * this function functions like apr_table_overlay(). Perhaps it does exactly
 * the same, in which case this function can be safely removed!
 */
static int wodan_table_disjunction(apr_table_t *base, apr_table_t *overlay);

/**
 * apply "proxy pass reverse". This changes all "Location", "URI",
 * and "Content-Location" headers to the one configured in the config file
 * @param config wodan configuration
 * @param headers current headers (received from backend)
 * @param r request record (new headers will be placed here)
 */ 
void apply_proxy_pass_reverse(wodan2_config_t *config, apr_table_t* headers,
	request_rec *r);

/** 
 * do reverse mapping of location. 
 */
const char* wodan_location_reverse_map(wodan2_proxy_alias_t* alias, const char *url,
	request_rec *r);
/**
 * checks if the user wodan is running as (e.g. 'nobody') is owner of the
 * file 'path' and also had write access to it.
 */
int util_file_is_writable(apr_pool_t *p, const char *path)
{
	apr_finfo_t file_info;
	apr_uid_t user_id;
	apr_gid_t group_id;
	
	apr_stat(&file_info, path, APR_FINFO_USER | APR_FINFO_GROUP |
		APR_FINFO_PROT, p);
	apr_uid_current(&user_id, &group_id, p);
	
	if (file_info.protection & APR_UWRITE)
	 	return 1;
	 return 0;
}

int util_string_is_number(const char *the_string)
{
	while (*the_string != '\0')
	if (!apr_isdigit(*(the_string++)))
		return 0;
	return 1;
}

apr_int32_t util_timestring_to_seconds(char *string)
{
	
	char *character;
	apr_int32_t number = 0;

	if (string == NULL)		
		return 0;

	character = string;
	
	/* calculate number */
	while (apr_isdigit(*character) || apr_isspace(*character)) {
		if (apr_isdigit(*character)) {
			/* translate to number */
			unsigned digit = (unsigned) *character - (unsigned) '0';
			ap_assert(digit < 10);
			number = (number * (apr_int32_t) 10) + (apr_int32_t) digit; 
		}
		character += 1;
	}
	
	if (*character != '\0') {
		switch(*character) {
			case 'w':
			case 'W':
				number = number * SECONDS_IN_WEEK;
				break;
			case 'd':
			case 'D':
				number = number * SECONDS_IN_DAY;
				break;
			case 'h':
			case 'H':
				number = number * SECONDS_IN_HOUR;
				break;
			case 'm':
			case 'M':
				number = number * SECONDS_IN_MINUTE;
				break;
			case 's':
			case 'S':
			default:
				/* this is only here for clarity */
				number = number;
				break;
		}
	}
	
	if (number > MAX_CACHE_TIMEOUT)
		number = MAX_CACHE_TIMEOUT;
	return number;
}

char* util_skipspaces (char* input)
{
	while(*input == ' ')
	{
		input++;
	}
	return input;
}

void adjust_headers_for_sending(wodan2_config_t *config, request_rec *r, 
	httpresponse_t *httpresponse)
{
	/* do more adjustments to the headers. This used to be in 
	   mod_reverseproxy.c */
	apr_table_unset(httpresponse->headers, "X-Wodan");
	wodan_table_disjunction(httpresponse->headers, r->headers_out);
	apply_proxy_pass_reverse(config, httpresponse->headers, r);
	
	r->headers_out = httpresponse->headers;
	r->content_type = apr_table_get(httpresponse->headers, "Content-Type");
	r->status = httpresponse->response;
}

/* TODO cleanup this function. It's not clear why it's called 'table_disjuction'.
 * Perhaps the function apr_table_overlay can be used, although that might 
 * overwrite some keys in the value that it shouldn't overwrite
 */
int wodan_table_disjunction(apr_table_t *base, apr_table_t *overlay)
{
	const apr_array_header_t *overlay_array = apr_table_elts(overlay);
	apr_table_entry_t *elts = (apr_table_entry_t *)overlay_array->elts;
	int i, q = 0;
	const char *val;
	
	for (i = 0; i < overlay_array->nelts; ++i) 
    	{
        	val = apr_table_get(base, elts[i].key);
		if(!val)
		{
			apr_table_add(base, elts[i].key, elts[i].val);
			q = 1;
		}
	}
	return q;
}

void apply_proxy_pass_reverse(wodan2_config_t *config, apr_table_t* headers,
	request_rec *r)
{
	const char* url;
	wodan2_proxy_alias_t *alias;

	alias = alias_longest_match(config, r->uri);

	if(alias == NULL)
		return;
	
	if((url = apr_table_get(headers, "Location")) != NULL)
		apr_table_set(headers, "Location", 
			wodan_location_reverse_map(alias, url, r));
	if((url = apr_table_get(headers, "URI")) != NULL)
		apr_table_set(headers, "URI", wodan_location_reverse_map(alias, url, r));
	if((url = apr_table_get(headers, "Content-Location")) != NULL)
		apr_table_set(headers, "Content-Location", 
			wodan_location_reverse_map(alias, url, r));
}

const char* wodan_location_reverse_map(wodan2_proxy_alias_t* alias, const char *url,
	request_rec *r)
{
	int url_len;
	int alias_len;
	
	url_len = strlen(url);
	alias_len = strlen(alias->alias);
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		"Replacing %s with %s", url, alias->alias);
	if (url_len >= alias_len && 
		strncmp(alias->alias, url, alias_len) == 0) {
		char *constructed_url;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, "Replacing");
		constructed_url = apr_pstrcat(r->pool, alias->path, &url[alias_len], NULL);
		return ap_construct_url(r->pool, constructed_url, r);
	}
	else return url;

}
const char* wodan_date_canon(apr_pool_t *p, 
	const char *input_date_string)
{
	apr_time_t the_time;
	char *rfc822_date_string;
	
	the_time = apr_date_parse_rfc(input_date_string);
	if (the_time == APR_DATE_BAD)
		return input_date_string;
	
	rfc822_date_string = apr_pcalloc(p, APR_RFC822_DATE_LEN);
	apr_rfc822_date(rfc822_date_string, the_time);
	
	return rfc822_date_string;
}
