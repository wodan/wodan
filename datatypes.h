/** $Id: datatypes.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2005 IC&S, The Netherlands
 */
#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#define MAX_CACHE_PATH_SIZE 1024
#define DEFAULT_CACHEDIR_LEVELS 2

#include "apr_tables.h"
#include "apr_time.h"
#include "apr_strmatch.h"

/**
 * Structure that contains the config elements of wodan
 */
typedef struct wodan_reverseproxy_config {
	unsigned cachedir_set; /* 1 if the cache dir is set */
	char cachedir[MAX_CACHE_PATH_SIZE + 1];/* The dir where cache files 
					    should be stored */
	unsigned runoncache; /* 1 if RunOnCache is set. This will make sure
				  that the backend is never contacted, which
				  is useful if there is scheduled downtime on
				  the backend */
	unsigned cache404s; /* Cache 404s as well or not? */
	apr_interval_time_t backend_timeout; /* timeout for the backend 
					 connection. If a connection has not 
					 been made within this time, the 
					 backend is assumed to be down */
	apr_array_header_t *reverseproxypasses;
	apr_array_header_t *reverseproxypassesreverse;
	apr_array_header_t *defaultcachetimes;
	apr_array_header_t *defaultcachetimes_regex;
	apr_array_header_t *defaultcachetimes_header;
	int cachedir_levels;
} wodan_reverseproxy_config_t;

/**
 * Structure containing info about a ReverseProxyPass directive
 */
typedef struct wodan_proxy_destination {
	const char *path;
	const char *host;
} wodan_proxy_destination_t;

/**
 * Structure containting info about a ReverseProxyPassReverse directive
 */
typedef struct wodan_proxy_alias {
	const char *path;
	const char *alias;
} wodan_proxy_alias_t;

/**
 * Structure containting info about a DefaultCacheTime directive
 */
typedef struct wodan_default_cachetime {
	const char *path;
	int cachetime;
} wodan_default_cachetime_t;

/**
 * Structure containting info for the DefaultCacheTimeRegex directive
 */
typedef struct wodan_default_cachetime_regex {
	apr_strmatch_pattern uri_pattern;
	int cachetime;
} wodan_default_cachetime_regex_t;

/**
 * Structure containing info for the DefaultCacheTimeHeader directive
 */
typedef struct wodan_default_cachetime_header {
	const char *header;
	apr_strmatch_pattern header_value_pattern;
	int cachetime;
} wodan_default_cachetime_header_t;
#endif //_DATATYPES_H_
