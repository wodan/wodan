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
typedef struct wodan2_config {
	unsigned is_cachedir_set; /* 1 if the cache dir is set */
	char cachedir[MAX_CACHE_PATH_SIZE + 1];/* The dir where cache files 
					    should be stored */
	unsigned run_on_cache; /* 1 if RunOnCache is set. This will make sure
				  that the backend is never contacted, which
				  is useful if there is scheduled downtime on
				  the backend */
	unsigned cache_404s; /* Cache 404s as well or not? */
	apr_interval_time_t backend_timeout; /* timeout for the backend 
					 connection. If a connection has not 
					 been made within this time, the 
					 backend is assumed to be down */
	apr_array_header_t *proxy_passes;
	apr_array_header_t *proxy_passes_reverse;
	apr_array_header_t *default_cachetimes;
	apr_array_header_t *default_cachetimes_regex;
	apr_array_header_t *default_cachetimes_header;
	int cachedir_levels;
} wodan2_config_t;

/**
 * Structure containing info about a ReverseProxyPass directive
 */
typedef struct wodan2_proxy_destination {
	const char *path;
	const char *url;
} wodan2_proxy_destination_t;

/**
 * Structure containting info about a ReverseProxyPassReverse directive
 */
typedef struct wodan2_proxy_alias {
	const char *path;
	const char *alias;
} wodan2_proxy_alias_t;

/**
 * Structure containting info about a DefaultCacheTime directive
 */
typedef struct wodan2_default_cachetime {
	const char *path;
	int cachetime;
} wodan2_default_cachetime_t;

/**
 * Structure containting info for the DefaultCacheTimeRegex directive
 */
typedef struct wodan2_default_cachetime_regex {
	apr_strmatch_pattern uri_pattern;
	int cachetime;
} wodan2_default_cachetime_regex_t;

/**
 * Structure containing info for the DefaultCacheTimeHeader directive
 */
typedef struct wodan2_default_cachetime_header {
	const char *header;
	apr_strmatch_pattern header_value_pattern;
	int cachetime;
} wodan2_default_cachetime_header_t;
#endif //_DATATYPES_H_
