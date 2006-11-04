/** $Id: datatypes.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2000-2006 IC&S, The Netherlands
 */
#ifndef _DATATYPES_H_
#define _DATATYPES_H_

#define MAX_CACHE_PATH_SIZE 1024
#define DEFAULT_CACHEDIR_LEVELS 2
#define MAX_CACHEDIR_LEVELS 8
#define MAX_BACKEND_TIMEOUT_SEC 59

/** Maximum cache timeout in seconds. Max timeout is 365 days (as if
 * you'd ever want to use that long a timeout) */ 
#define MAX_CACHE_TIMEOUT 60 * 60 * 24 * 365

#define BUFFERSIZE 2048

#define DEFAULT_CACHETIME 3600

#ifdef __GNUC__
#define WODAN_UNUSED_PARAMETER __attribute__((__unused__))
#else
#define WODAN_UNUSED_PARAMETER
#endif

#include "httpd.h"
#include "apr_network_io.h"
#include "apr_tables.h"
#include "apr_time.h"
#include "apr_strmatch.h"
#include "apr_version.h"

/* detect if APR > 1.0 is used */
#if APR_MAJOR_VERSION < 1
#define ap_regex_t        regex_t
#define ap_regmatch_t     regmatch_t
#define ap_regcomp(a,b,c) regcomp((a),(b),(c))
#define ap_regfree(a)     regfree(a)
#define AP_REG_ICASE      REG_ICASE
#define AP_REG_NEWLINE    REG_NEWLINE
#define AP_REG_NOTBOL     REG_NOTBOL
#define AP_REG_NOTEOL     REG_NOTEOL
#define AP_REG_EXTENDED   REG_EXTENDED
#define AP_REG_NOSUB      REG_NOSUB
#define apr_socket_create(a,b,c,d,e) apr_socket_create(a,b,c,e)
#endif

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
 * Structure containing info about a ReverseProxyPassReverse directive
 */
typedef struct wodan2_proxy_alias {
	const char *path;
	const char *alias;
} wodan2_proxy_alias_t;

/**
 * Structure containing info about a DefaultCacheTime directive
 */
typedef struct wodan2_default_cachetime {
	const char *path;	
	apr_int32_t cachetime;
} wodan2_default_cachetime_t;

/**
 * Structure containing info for the DefaultCacheTimeRegex directive
 */
typedef struct wodan2_default_cachetime_regex {
	ap_regex_t *uri_pattern;
	apr_int32_t cachetime;
} wodan2_default_cachetime_regex_t;

/**
 * Structure containing info for the DefaultCacheTimeHeader directive
 */
typedef struct wodan2_default_cachetime_header {
	const char *header;
	ap_regex_t *header_value_pattern;
	apr_int32_t cachetime;
} wodan2_default_cachetime_header_t;

/**
 * Structure representing an httpresponse
 */
typedef struct httpresponse {
	char* content_type;//The content type of the data
	apr_table_t* headers;//A table containing the headers
	int response;//The response code
} httpresponse_t;

typedef struct network_connection {
	apr_socket_t *socket;
} network_connection_t;
#endif //_DATATYPES_H_
