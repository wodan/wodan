/* 

*/ 

#define WODAN_NAME "Wodan2"
#define WODAN_VERSION "0.1"

/* local includes */
#include "datatypes.h"
#include "util.h"

/* Apache includes */
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"

module AP_MODULE_DECLARE_DATA wodan2_module;

/* initialize Wodan2 */
static int wodan2_init_handler(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
	server_rec *s)
{
	const char *identifier_string;
	
	identifier_string = apr_psprintf(p, "%s/%s", WODAN_NAME, WODAN_VERSION);
	ap_add_version_component(p, identifier_string);
	
	return OK;
}                          

/* create a new config struct. We keep it very simple, by initializing 
 * everything to zero. Only create some arrays, because we'll need them
 * later on
 */
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

static void *wodan2_create_server_config(apr_pool_t *p, server_rec *s)
{
	return wodan2_create_config(p);
}

static void *wodan2_create_dir_config(apr_pool_t *p, char *dir)
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
	if (new_config->backend_timeout > 0) 
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

static const char *add_pass(cmd_parms *cmd, void *dummy, const char *path,
	const char *url)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	wodan2_proxy_destination_t *proxy_destination;
	char *proxy_url;
	
	if(path[0] != '/' || path[strlen(path) - 1] != '/')
	        return "First argument of WodanPass should be a dir e.g. /dir/";
	if (strncasecmp(url, "http://", 7) != 0) 
		return "Second argument of WodanPass should be a "
			"http:// url, e.g. http://www.ic-s.nl";
	
	proxy_url = apr_pstrdup(cmd->pool, url);
	/* strip final '/' of proxy_url */
	if (proxy_url[strlen(proxy_url) - 1] == '/')
		proxy_url[strlen(proxy_url) - 1] = '\0';
	
	proxy_destination = apr_array_push(config->proxy_passes);
	proxy_destination->path = path;
	proxy_destination->url = proxy_url;
	return NULL;
}

static const char *add_pass_reverse(cmd_parms *cmd, void *dummy, const char *path,
	const char *url)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	wodan2_proxy_destination_t *proxy_alias;
	
	if(path[0] != '/' || path[strlen(path) - 1] != '/')
	        return "First argument of WodanPassReverse should be a dir e.g. /dir/";
	if (strncasecmp(url, "http://", 7) != 0) 
		return "Second argument of WodanPassReverse should be a "
			"http:// url, e.g. http://www.ic-s.nl";
	
	proxy_alias = apr_array_push(config->proxy_passes_reverse);
	proxy_alias->path = path;
	proxy_alias->url = url;
	return NULL;
}

static const char *add_cachedir(cmd_parms *cmd, void *dummy, const char *path)
{
	server_rec *s = cmd->server;
	wodan2_config_t *config = (wodan2_config_t *)
		ap_get_module_config(s->module_config, &wodan2_module);
	
	if (!ap_is_directory(cmd->pool, path)) {
		char *error_message = apr_psprintf(cmd->pool, 
			"CacheDir %s is not a directory!", path);
		return error_message;
	}
	
	if (!util_file_is_writable(cmd->pool, path))
	{
		char *error_message = apr_psprintf(cmd->pool,
			"Cachedir %s is not writable!", path);
		return error_message;
	}
	
	apr_cpystrn(config->cachedir, path, MAX_CACHE_PATH_SIZE + 1);
	config->is_cachedir_set = 1;
	
	return NULL;
}	
	
		

static int wodan2_handler(request_rec *r)
{
    if (strcmp(r->handler, "wodan2")) {
        return DECLINED;
    }
    r->content_type = "text/html";      

    if (!r->header_only)
        ap_rputs("The sample page from mod_wodan2.c\n", r);
    return OK;
}

static void wodan2_register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(wodan2_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(wodan2_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec wodan2_commands[] = 
{
	AP_INIT_TAKE12("WodanPass", add_pass, NULL, RSRC_CONF, "A path and a URL"),
	AP_INIT_TAKE12("WodanPassReverse", add_pass_reverse, 
		NULL, RSRC_CONF, "A path and a URL"),
	AP_INIT_TAKE1("WodanCacheDir", add_cachedir, NULL, RSRC_CONF, "A path"),
	{NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA wodan2_module = {
    STANDARD20_MODULE_STUFF, 
    wodan2_create_dir_config,   /* create per-dir    config structures */
	wodan2_merge_config,                  /* merge  per-dir    config structures */
    wodan2_create_server_config,/* create per-server config structures */
    wodan2_merge_config,                  /* merge  per-server config structures */
    wodan2_commands,                  /* table of config file commands       */
    wodan2_register_hooks  /* register hooks                      */
};

