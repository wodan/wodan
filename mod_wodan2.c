/* 
 * (c) 2000-2006 IC&S, The Netherlands
 */ 

#define WODAN_NAME "Wodan2"
#define WODAN_VERSION "0.1"

/* constants identifying the source of the returned (to the client) object */
#define LOG_SOURCE_CACHED "Cached"
#define LOG_SOURCE_BACKEND "Backend"
#define LOG_SOURCE_CACHED_BACKEND_ERROR "CachedBackendError"

/* local includes */
#include "cache.h"
#include "datatypes.h"
#include "httpclient.h"
#include "match.h"
#include "util.h"

/* Apache includes */
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include <string.h>
#include <time.h>

/*
 * Function prototypes.
 */
 
/* initializer for Wodan2 */
static int wodan2_init_handler(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
	server_rec *s);
/* create initial server configuration. */
static void *wodan2_create_server_config(apr_pool_t *p, server_rec *s);
/* create per-dir server configuration */
static void *wodan2_create_dir_config(apr_pool_t *p, char *dir);
/* merge two config structures. */
static void *wodan2_merge_config(apr_pool_t *p, void *base_config_p, 
	void *new_config_p);
/* add a WodanPass config to the configuration */
static const char *add_pass(cmd_parms *cmd, void *dummy, const char *path,
	const char *url);
/* add a WodanPassReverse config to the configuration */
static const char *add_pass_reverse(cmd_parms *cmd, void *dummy, const char *path,
	const char *url);
/* add cachedir */	
static const char *add_cachedir(cmd_parms *cmd, void *dummy, const char *path);
/* set level of cachedir nesting */
static const char *add_cachedir_levels(cmd_parms *cmd, void *dummy, 
	const char *level);
/* add a default cachetime for a path */
static const char *add_default_cachetime(cmd_parms *cmd, void *dummy,
	const char *path, const char *time_string);
/* add a default cachetime for a path matching a regular expression */
static const char* add_default_cachetime_regex(cmd_parms *cmd, 
	void *dummy, const char *regex_pattern, const char *time_string);
/* add a default cachetime for a header whose value matches a regular expression */
static const char* add_default_cachetime_header(cmd_parms *cmd, void *dummy, 
	const char *http_header, const char *regex_pattern, const char *time_string);
/* add a flag to run completely on the cache (i.e. do not try to contact the 
 * backend */
static const char* add_run_on_cache(cmd_parms *cmd, void *dummy, int flag);
/* add a flag to cache 404 pages. */
static const char* add_cache_404s(cmd_parms *cmd, void *dummy, int flag);
/* add a backend timeout */
static const char *add_backend_timeout(cmd_parms *cmd, void *dummy,
	const char *timeout_string);

/* hook registering function */
static void wodan2_register_hooks(apr_pool_t *p);
	
/* The content handler function. This is the main function of Wodan2 */
static int wodan2_handler(request_rec *r);

/**
 * The configuration directives and their setup functions.
 */
static const command_rec wodan2_commands[] = 
{
	AP_INIT_TAKE12("WodanPass", add_pass, NULL, RSRC_CONF, "A path and a URL"),
	AP_INIT_TAKE12("WodanPassReverse", add_pass_reverse, 
		NULL, RSRC_CONF, "A path and a URL"),
	AP_INIT_TAKE1("WodanCacheDir", add_cachedir, NULL, RSRC_CONF, "A path"),
	AP_INIT_TAKE1("WodanCacheDirLevels", add_cachedir_levels, NULL, RSRC_CONF, 
		"A Number (> 0)"),
	AP_INIT_TAKE2("WodanDefaultCacheTime", add_default_cachetime, NULL, RSRC_CONF,
		"A path and a time string"),
	AP_INIT_TAKE2("WodanDefaultCacheTimeMatch", add_default_cachetime_regex,
		NULL, RSRC_CONF, "A regex pattern and a time string"),
	AP_INIT_TAKE3("WodanDefaultCacheTimeHeaderMatch", 
		add_default_cachetime_header, NULL, RSRC_CONF, 
		"A header, a regex pattern and a time string"),
	AP_INIT_FLAG("WodanRunOnCache", add_run_on_cache, NULL, RSRC_CONF,
		"run completely on cache"),
	AP_INIT_FLAG("WodanCache404s", add_cache_404s, NULL, RSRC_CONF,
		"cache 404 pages"),
	AP_INIT_TAKE1("WodanBackendTimeout", add_backend_timeout, NULL, RSRC_CONF,
		"a number, which represents a time in miliseconds"),
	{NULL}
};
/* The module. Apache uses this information to initialise and hook up
 * the module into the webserver. */
module AP_MODULE_DECLARE_DATA wodan2_module = {
    STANDARD20_MODULE_STUFF, 
    wodan2_create_dir_config,   /* create per-dir    config structures */
    wodan2_merge_config,        /* merge  per-dir    config structures */
    wodan2_create_server_config,/* create per-server config structures */
    wodan2_merge_config,        /* merge  per-server config structures */
    wodan2_commands,            /* table of config file commands       */
    wodan2_register_hooks       /* register hooks                      */
};

/* initialize Wodan2 */
static int wodan2_init_handler(apr_pool_t *p, 
	apr_pool_t *plog WODAN_UNUSED_PARAMETER, 
	apr_pool_t *ptemp WODAN_UNUSED_PARAMETER,
	server_rec *s WODAN_UNUSED_PARAMETER)
{
	const char *identifier_string;
	
	identifier_string = apr_psprintf(p, "%s/%s", WODAN_NAME, WODAN_VERSION);
	ap_add_version_component(p, identifier_string);
	
	return OK;
}                          

static void *wodan2_create_config(apr_pool_t *p)
{
	wodan2_config_t* config = (wodan2_config_t *) 
		apr_pcalloc(p, sizeof(wodan2_config_t));
	
	config->cachedir_levels = DEFAULT_CACHEDIR_LEVELS;
	config->proxy_passes = apr_array_make(p, 0, 
		sizeof(wodan2_proxy_destination_t));
	config->proxy_passes_reverse = apr_array_make(p, 0,
		sizeof(wodan2_proxy_alias_t));
	config->default_cachetimes = apr_array_make(p, 0,
		sizeof(wodan2_default_cachetime_t));
	config->default_cachetimes_regex = apr_array_make(p, 0,
		sizeof(wodan2_default_cachetime_regex_t));
	config->default_cachetimes_header = apr_array_make(p, 0,
		sizeof(wodan2_default_cachetime_header_t));	
	return config;		
}

static void *wodan2_create_server_config(apr_pool_t *p, 
	server_rec *s WODAN_UNUSED_PARAMETER)
{
	return wodan2_create_config(p);
}

static void *wodan2_create_dir_config(apr_pool_t *p, 
	char *dir WODAN_UNUSED_PARAMETER)
{
	return wodan2_create_config(p);
}
	          
static void *wodan2_merge_config(apr_pool_t *p, void *base_config_p, 
	void *new_config_p)
{
	wodan2_config_t *config = (wodan2_config_t *)
		apr_pcalloc(p, sizeof(wodan2_config_t));
	wodan2_config_t *base_config = (wodan2_config_t *) base_config_p;
	wodan2_config_t *new_config = (wodan2_config_t *) new_config_p;
	
	if (strlen(new_config->cachedir) > 0) 
		apr_cpystrn(config->cachedir, new_config->cachedir, 
			MAX_CACHE_PATH_SIZE + 1);
	else 
		apr_cpystrn(config->cachedir, base_config->cachedir,
			MAX_CACHE_PATH_SIZE + 1);
	
	config->cachedir_levels = new_config->cachedir_levels;
	if (new_config->is_cachedir_set == 1 || base_config->is_cachedir_set == 1)
		config->is_cachedir_set = 1;
	if (new_config->run_on_cache == 1 || base_config->run_on_cache == 1)
		config->run_on_cache = 1;
	if (new_config->cache_404s == 1 || base_config->cache_404s == 1)
		config->cache_404s = 1;
	if (new_config->backend_timeout != (apr_interval_time_t) 0)
		config->backend_timeout = new_config->backend_timeout;
	else
		config->backend_timeout = base_config->backend_timeout;
		
	config->proxy_passes = apr_array_append(p, 
		base_config->proxy_passes, new_config->proxy_passes);
	config->proxy_passes_reverse = apr_array_append(p,
		base_config->proxy_passes_reverse, 
		new_config->proxy_passes_reverse);
	config->default_cachetimes = apr_array_append(p,
		base_config->default_cachetimes, new_config->default_cachetimes);
	config->default_cachetimes_regex = apr_array_append(p,
		base_config->default_cachetimes_regex, 
		new_config->default_cachetimes_regex);
	config->default_cachetimes_header = apr_array_append(p,
		base_config->default_cachetimes_header, 
		new_config->default_cachetimes_header);
		
	return config;
}               
/* The sample content handler */

static const char *add_pass(cmd_parms *cmd, void *dummy WODAN_UNUSED_PARAMETER, 
	const char *path, const char *url)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	wodan2_proxy_destination_t *proxy_destination;
	char *proxy_url;
	
	if(path[0] != '/' || path[(int) strlen(path) - 1] != '/')
	        return "First argument of WodanPass should be a dir e.g. /dir/";
	if (strncasecmp(url, "http://", 7) != 0) 
		return "Second argument of WodanPass should be a "
			"http:// url, e.g. http://www.ic-s.nl";
	
	proxy_url = apr_pstrdup(cmd->pool, url);
	/* strip final '/' of proxy_url */
	if (proxy_url[(int) strlen(proxy_url) - 1] == '/')
		proxy_url[(int) strlen(proxy_url) - 1] = '\0';
	
	proxy_destination = apr_array_push(config->proxy_passes);
	proxy_destination->path = path;
	proxy_destination->url = proxy_url;
	return NULL;
}

static const char *add_pass_reverse(cmd_parms *cmd,
	void *dummy WODAN_UNUSED_PARAMETER, const char *path, const char *url)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	wodan2_proxy_destination_t *proxy_alias;
	
	if(path[0] != '/' || path[(int) strlen(path) - 1] != '/')
	        return "First argument of WodanPassReverse should be a dir e.g. /dir/";
	if (strncasecmp(url, "http://", 7) != 0) 
		return "Second argument of WodanPassReverse should be a "
			"http:// url, e.g. http://www.ic-s.nl";
	
	proxy_alias = apr_array_push(config->proxy_passes_reverse);
	proxy_alias->path = path;
	proxy_alias->url = url;
	return NULL;
}

static const char *add_cachedir(cmd_parms *cmd, void *dummy WODAN_UNUSED_PARAMETER, 
	const char *path)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	
	/* prepend server root path */
	const char *fname = ap_server_root_relative(cmd->pool, path);
	
	if (!ap_is_directory(cmd->pool, fname)) {
		char *error_message = apr_psprintf(cmd->pool, 
			"WodanCacheDir %s is not a directory!", fname);
		return error_message;
	}
	
	if (!util_file_is_writable(cmd->pool, fname))
	{
		
		char *error_message = apr_psprintf(cmd->pool,
			"WodanCachedir %s should be owned by Wodan user and should be writable!"
			"by that user!", fname);
		return error_message;
	}
	
	apr_cpystrn(config->cachedir, fname, MAX_CACHE_PATH_SIZE + 1);
	config->is_cachedir_set = 1;
	
	return NULL;
}	

static const char *add_cachedir_levels(cmd_parms *cmd, 
	void *dummy WODAN_UNUSED_PARAMETER, const char *level)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	apr_int64_t levels;

	if (!util_string_is_number(level)) {
		char *error_message = apr_psprintf(cmd->pool, 
			"Argument to WodanCacheDirLevels should be a number, it is %s now",
			level);
		return error_message;
	}
	
	levels = apr_strtoi64(level, NULL, 10);
	if (levels < 0 || levels > (apr_int64_t) MAX_CACHEDIR_LEVELS) {
		char *error_message = apr_psprintf(cmd->pool, 
			"WodanCacheDirLevels must have a value between 0 and %d",
			(int) MAX_CACHEDIR_LEVELS);
		return error_message;
	}
	
	config->cachedir_levels = (int) levels;
	return NULL;
}	

static const char *add_default_cachetime(cmd_parms *cmd, 
	void *dummy WODAN_UNUSED_PARAMETER, const char *path, const char *time_string)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	wodan2_default_cachetime_t *new_default_cachetime;
	
	if(path[0] != '/' || path[(int) strlen(path) - 1] != '/')
		return "First argument of WodanDefaultCacheTime "
	    		"should be a path, e.g. /dir/";
	 
	new_default_cachetime = apr_array_push(config->default_cachetimes);
	new_default_cachetime->path = path;
	if (strncmp(time_string, "no", 2 ) == 0 )
		new_default_cachetime->cachetime = (apr_int32_t) -1;
	else { 
	 	new_default_cachetime->cachetime = 
	 		util_timestring_to_seconds(apr_pstrdup(cmd->pool, time_string));
	}
	return NULL;
}

static const char* add_default_cachetime_regex(cmd_parms *cmd, 
	void *dummy WODAN_UNUSED_PARAMETER, const char *regex_pattern, 
	const char *time_string)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	wodan2_default_cachetime_regex_t *new_default_cachetime_regex;
	ap_regex_t *compiled_pattern = NULL;

	new_default_cachetime_regex = 
		apr_array_push(config->default_cachetimes_regex);
	
	compiled_pattern = ap_pregcomp(cmd->pool, regex_pattern, 
		AP_REG_EXTENDED | AP_REG_NOSUB);
	if (compiled_pattern == NULL) {
		char *error_message = apr_psprintf(cmd->pool, 
			"Failure compiling regex pattern \"%s\"", regex_pattern);
		return error_message;
	}	
	new_default_cachetime_regex->uri_pattern = compiled_pattern;
	
	if (strncmp(time_string, "no", 2) == 0)
		new_default_cachetime_regex->cachetime = (apr_int32_t) -1;
	else
		new_default_cachetime_regex->cachetime = 
			util_timestring_to_seconds(apr_pstrdup(cmd->pool, time_string));

	return NULL;
}

static const char* add_default_cachetime_header(cmd_parms *cmd, 
	void *dummy WODAN_UNUSED_PARAMETER, const char *http_header, 
	const char *regex_pattern, const char *time_string)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	wodan2_default_cachetime_header_t *new_default_cachetime_header;
	ap_regex_t *compiled_pattern;
	
	new_default_cachetime_header = 
		apr_array_push(config->default_cachetimes_header);
	
	new_default_cachetime_header->header = apr_pstrdup(cmd->pool, http_header);
	compiled_pattern = ap_pregcomp(cmd->pool, regex_pattern, 
		AP_REG_EXTENDED | AP_REG_NOSUB);
	if (compiled_pattern == NULL) {
		char *error_message = apr_psprintf(cmd->pool, 
			"Failure compiling regex pattern \"%s\"", regex_pattern);
		return error_message;
	}
	new_default_cachetime_header->header_value_pattern = compiled_pattern;
	if (strncmp(time_string, "no", 2) == 0) 
		new_default_cachetime_header->cachetime = (apr_int32_t) -1;
	else
		new_default_cachetime_header->cachetime = 
			util_timestring_to_seconds(apr_pstrdup(cmd->pool, time_string));
			
	return NULL;
}

static const char* add_run_on_cache(cmd_parms *cmd, 
	void *dummy WODAN_UNUSED_PARAMETER, int flag)
{
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(cmd->server->module_config, &wodan2_module);
      
	config->run_on_cache = (unsigned) flag;
	
	return NULL;
}

static const char *add_cache_404s(cmd_parms *cmd, 
	void *dummy WODAN_UNUSED_PARAMETER, int flag)
{
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(cmd->server->module_config, &wodan2_module);
	
	config->cache_404s = (unsigned) flag;
	
	return NULL;
}

static const char *add_backend_timeout(cmd_parms *cmd,
	void *dummy WODAN_UNUSED_PARAMETER, const char *timeout_string)
{
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(cmd->server->module_config, &wodan2_module);
	apr_int64_t timeout;
	
	if (!util_string_is_number(timeout_string)) {
		char *error_message = apr_psprintf(cmd->pool,
			"argument should be number, it is \"%s\" now", timeout_string);
		return error_message;
	}
	timeout = apr_strtoi64(timeout_string, NULL, 10);
	
	// timeout is a number in milliseconds, so it needs to be multiplied by 1000
	timeout *= 1000;
	
	if (timeout > apr_time_from_sec(MAX_BACKEND_TIMEOUT_SEC))
		config->backend_timeout = apr_time_from_sec(MAX_BACKEND_TIMEOUT_SEC);
	else
		config->backend_timeout = timeout;
	
	return NULL;
}

static void wodan2_register_hooks(apr_pool_t *p WODAN_UNUSED_PARAMETER)
{
	ap_hook_post_config(wodan2_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(wodan2_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static int wodan2_handler(request_rec *r)
{
	wodan2_config_t* config;
	httpresponse_t httpresponse;
	WodanCacheStatus_t cache_status;
	int response = HTTP_BAD_GATEWAY;
	apr_time_t cache_file_time;
	
	config = (wodan2_config_t *)
		ap_get_module_config(r->server->module_config, &wodan2_module);
	
	// TODO: check if is is perhaps a better idea to create a table of a certain size
	httpresponse.headers = apr_table_make(r->pool, 0);
	
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "Processing new request: %s", r->unparsed_uri);

	// see if the request can be handled from the cache.
	cache_status = cache_get_status(config, r, &cache_file_time);

	if (config->cache_404s) {
		if (cache_status == WODAN_CACHE_404) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
			             r->server, "URL is cached as 404");
			return HTTP_NOT_FOUND;
		}
	}
	
	if (cache_status != WODAN_CACHE_PRESENT) {
		/* attempt to get data from backend */
		wodan2_proxy_destination_t *proxy_destination =
			destination_longest_match(config, r->uri);

		if(proxy_destination != NULL)//FIXME what if destination is NULL
		{
			char* newpath;
			int l = (int) strlen(proxy_destination->path);
			newpath = &(r->unparsed_uri[l - 1]);
			
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, 
				     "No cache, getting content from remote "
				     "url: %s path: %s", 
				     proxy_destination->url, newpath);
			
			//Get the httpresponse from remote server	
			response = http_proxy(config, proxy_destination->url, newpath, 
					      &httpresponse, r, cache_file_time);
			/* If 404 are to be cached, then already return
			 * default 404 page here in case of a 404. */
			if (config->cache_404s)
				if (response == HTTP_NOT_FOUND)
					return HTTP_NOT_FOUND;

			/* if nothing can be received from backend, and
			   nothing in cache, NOT_FOUND is the only option
			   left... */
			if ((response == HTTP_NOT_FOUND || response == HTTP_BAD_GATEWAY ||
					response == HTTP_GATEWAY_TIME_OUT) &&
					cache_status != WODAN_CACHE_PRESENT_EXPIRED) {
			    	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			    		"return HTTP_NOT_FOUND");
			    	return HTTP_NOT_FOUND;
			} else if (response != HTTP_BAD_GATEWAY &&
				 response != HTTP_GATEWAY_TIME_OUT &&
				 response != HTTP_NOT_MODIFIED) {
				ap_log_error(APLOG_MARK, 
					     APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
					     "Got response from gateway");
			} 
		}
	}

	if (cache_status == WODAN_CACHE_PRESENT) {
	  	cache_read_from_cache(config, r, &httpresponse);
		apr_table_set(r->notes, "WodanSource", LOG_SOURCE_CACHED);
	} else if (cache_status == WODAN_CACHE_PRESENT_EXPIRED &&
		   (response == HTTP_BAD_GATEWAY || 
		    response == HTTP_GATEWAY_TIME_OUT ||
		    response == HTTP_NOT_MODIFIED)) {
	  	cache_read_from_cache(config, r, &httpresponse);
		cache_update_expiry_time(config, r);
		apr_table_set(r->notes, "WodanSource", LOG_SOURCE_CACHED_BACKEND_ERROR);
	} else {
		apr_table_set(r->notes, "WodanSource", LOG_SOURCE_BACKEND);
	}

	//Return some response code
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "returning: %d",  httpresponse.response);
	
	return OK; 
}




