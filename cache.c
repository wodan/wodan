/** $Id: cache.c 162 2005-02-16 15:36:06Z ilja $
 *(c) 2000-2005 IC&S, The Netherlands
 */

#include <sys/stat.h>
#include <string.h>

#include "cache.h"
#include "datatypes.h"
#include "match.h"
#include "util.h"

#include "httpd.h"
#include "http_log.h"
#include "apr.h"
#include "apr_date.h"
#include "apr_md5.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "util_md5.h"

#include <string.h>

/**
 * \brief check if the CacheDir directive is set
 * \param config the server configuration
 * \return 
 *     - 0 if not set
 *     - 1 if set
 */
static int is_cachedir_set(wodan2_config_t *config);

/**
 * Return whether the http result code is cacheable
 * @param httpcode The http code to check
 * @param cache404s Specifies if 404s are treated as cacheable
 * @retval 1 if return code is cachable
 * @retval 0 if return code is not cachable
 */
static int is_response_cacheable (int httpcode, int cache404s);

/**
 * return the name of the (nested) subdirectory used for
 * the cache file. The name of the directory is determined
 * by the name of the cache file and the number of levels
 * the directory has to be nested. A nesting depth of 
 * 2 and a cachefile of the name "abcdef" will result in
 * a name like: "a/b/" for the directory. The nr parameter
 * determines which part of the nested subdirectory will
 * be returned, counting from 0. In the above example, if
 * nr is 0, 'a' will be returned.
 * @param r request record
 * @param config the wodan configuration
 * @param cachefilename name of cachefile
 * @param nr which part of the complete directory to return.
 */
static char *get_cache_file_subdir(wodan2_config_t *config, request_rec *r,
	char *cachefilename, int nr);
	
/**
 * return the name of the cachefile
 * @param r request record
 * @param config the wodan configuration
 * @param unparsed_uri the unparsed URI
 * @param[out] filename will hold the filename
 * @retval 0 on error
 * @retval 1 on success 
 */
static int get_cache_filename(wodan2_config_t *config, request_rec *r,
	char *unparsed_uri, char **filename);
	
WodanCacheStatus_t cache_get_status(wodan2_config_t *config, request_rec *r, 
	apr_time_t *cache_file_time)
{
	char* cachefilename;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int status;
	int interval_time;

	*cache_file_time = (apr_time_t) 0;
	
	if(r->method_number != M_GET && !r->header_only)
		return WODAN_CACHE_NOT_CACHEABLE;

	// if the CacheDir directive is not set, we cannot read from cache
	if (!is_cachedir_set(config))
		return WODAN_CACHE_NOT_PRESENT;

	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);
	if (apr_file_open(&cachefile, cachefilename, APR_READ, APR_OS_DEFAULT, r->pool)
		!= APR_SUCCESS) {
		return WODAN_CACHE_NOT_PRESENT;
	}

    /* Read url field, but we don't do anything with it */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* read expire interval field, but don't do anything with it */
	interval_time = 0;
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		interval_time = atoi(buffer);
	}
	if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		apr_time_t cachefile_expire_time;
		
		/* Parses a date in RFC 822  */
		if ((cachefile_expire_time = apr_date_parse_http(buffer)) == APR_DATE_BAD) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server,
			"Cachefile date not parsable. Returning \"Expired status\"");
			return WODAN_CACHE_PRESENT_EXPIRED;
		}
		
		/* time - interval_time = time that file was created */
		*cache_file_time = cachefile_expire_time - apr_time_from_sec(interval_time);
		
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Cachefile expires %s (%ld), now %s (%ld)",
			     ap_ht_time(r->pool,cachefile_expire_time, "%a %d %b %Y %T %Z",1),
			     (long int) cachefile_expire_time, 
			     ap_ht_time(r->pool, (r->request_time), 
					"%a %d %b %Y %T %Z",1), 
			     (long int) r->request_time);

		if((r->request_time > cachefile_expire_time) && (!config->run_on_cache))
		{
			apr_file_close(cachefile);
	         return WODAN_CACHE_PRESENT_EXPIRED;
		}

		/* Read empty line before status line */
		apr_file_gets(buffer, BUFFERSIZE, cachefile);
		if (apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
			status = atoi(buffer);
			if (status == HTTP_NOT_FOUND) {
				ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,
				             r->server, "File in cache has status 404");
				apr_file_close(cachefile);
				return WODAN_CACHE_404;
			}
		}
		
		apr_file_close(cachefile);
		return WODAN_CACHE_PRESENT;
   	}
	apr_file_close(cachefile);
	return WODAN_CACHE_NOT_PRESENT;
}

int cache_read_from_cache (wodan2_config_t *config, request_rec *r,
	struct httpresponse* httpresponse)
{
	char* cachefilename;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	int write_error;
	int content_length = 0;
	int body_bytes_written = 0;
	
	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);
	apr_file_open(&cachefile, cachefilename, APR_READ, APR_OS_DEFAULT, r->pool);
    /* Read url field, but we don't do anything with it */
    apr_file_gets(buffer, BUFFERSIZE, cachefile);
		
	/* same for expire interval field */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* same for expire field */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	if(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		httpresponse->response = atoi(buffer);
	}
	else {
		//Remove file and return 0
		apr_file_close(cachefile);
		apr_file_remove(cachefilename, r->pool);
		return 0;
	}

    while(apr_file_gets(buffer, BUFFERSIZE, cachefile) == APR_SUCCESS) {
		int counter = 0;
		char* key;
		char* bufferpointer;
			if(strcasecmp(buffer, CRLF) == 0)
	         	break;
             bufferpointer = &buffer[0];
             key = ap_getword(r->pool, (const char**) &bufferpointer, ':');
             bufferpointer = util_skipspaces(bufferpointer);
             while(bufferpointer[counter]) {
	         	if(bufferpointer[counter] == CR || 
	                bufferpointer[counter] == LF || 
	                bufferpointer[counter] == '\n') {
	             	bufferpointer[counter] = '\0';
	                 break;
             	}
                 counter++;
			}
             apr_table_add(httpresponse->headers, key, bufferpointer);
		if (strcasecmp(key, "Content-Length") == 0) {
			content_length = atoi(bufferpointer);
		}
	}
	adjust_headers_for_sending(config, r, httpresponse);
	
   	if(r->header_only) {
		return 1;
	}
	
	write_error = 0;
	/* TODO add checking of errors in reading from file */
	while(!apr_file_eof(cachefile) && !write_error) {
		apr_size_t bytes_read;
		int bytes_written;

		apr_file_read_full(cachefile, buffer, BUFFERSIZE, &bytes_read);
		
		bytes_written = ap_rwrite(buffer, bytes_read, r);
		body_bytes_written += bytes_written;
		if (((int) bytes_read != bytes_written) || bytes_written == -1) {
			write_error = 1;
		}
		if(bytes_read < BUFFERSIZE)
	                break;
	}
	
	/* TODO add error checking for file reading */
	if (write_error) {
		const char *user_agent;

		user_agent = apr_table_get(r->headers_in, "User-Agent");
		if (user_agent == NULL) 
			user_agent = "unknown";
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			     "error writing to socket. "
			     "Bytes written/Body length = %d/%d, "
			     "User-Agent: %s",
			     body_bytes_written, content_length, user_agent);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		"Returned answer from cache");
		
	return 1;
}

static int find_cache_time(wodan2_config_t *config,
			 request_rec *r,
			 struct httpresponse *httpresponse)
{
	int cachetime;
	wodan2_default_cachetime_header_t *default_cachetime_header_config;
	wodan2_default_cachetime_regex_t *default_cachetime_regex_config;
	wodan2_default_cachetime_t *default_cachetime_config;
	
	if (httpresponse != NULL) {
		default_cachetime_header_config = 
			default_cachetime_header_match(config, httpresponse->headers);
		if (default_cachetime_header_config != NULL) {
			cachetime = default_cachetime_header_config->cachetime;
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
			       r->server,
			       "Got cachetime from header match! "
			       "cachetime = %d",
			       cachetime);
		  return cachetime;
		}
	}

	default_cachetime_regex_config =
		default_cachetime_regex_match(config, r->uri);
	if (default_cachetime_regex_config != NULL) {
		cachetime = 
			default_cachetime_regex_config->cachetime;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Got cachetime from regex match! cachetime = %d",
			     cachetime);
		return cachetime;
	}
	
	default_cachetime_config = 
		default_cachetime_longest_match(config, r->uri);
	if (default_cachetime_config != NULL) {
		cachetime = default_cachetime_config->cachetime;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
			     r->server,"Got cachetime from normal match "
			     "cachetime = %d", cachetime);
		return cachetime;
	}
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server, 
		     "Using normal cachetime %d", DEFAULT_CACHETIME);
	return DEFAULT_CACHETIME;
}

static apr_time_t parse_xwodan_expire(request_rec *r,
				  char *xwodan, int cachetime, 
				  int *cachetime_interval) 
{
	apr_time_t expire_time;
	char *c;

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);
	*cachetime_interval = 0;
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "Parsing expire header: "
		     "\"%s\"", util_skipspaces(&xwodan[6]));
	c = util_skipspaces(&xwodan[6]);
	if ( *c >= '0' && *c <= '9' ) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Expire header is numeric. Assuming addition of "
			     "interval to current time." );
		*cachetime_interval = util_timestring_to_seconds(c);
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			"cachetime_interval = %d", *cachetime_interval);
		expire_time = r->request_time + apr_time_from_sec(*cachetime_interval);
	} else {
		/* IB 2004-12-07: there's no information on this next 
		 * piece of code
		 * in  the README.. Is it safe to delete this or 
		 * is there code that relies on it? */
		expire_time = apr_date_parse_http(util_skipspaces(&xwodan[6]));
		if (expire_time == APR_DATE_BAD) { 
			expire_time = r->request_time + apr_time_from_sec(cachetime);
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, "Received 0 expire time, "
				     "using default cache time" );
		}	
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Time: %ld", (long int) expire_time);
		if(r->request_time > expire_time) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, "Expire date is before "
				     "request time, won't cache response");
			return 0;
		} else 
			*cachetime_interval = 
				apr_time_sec((apr_time_from_sec(expire_time) - r->request_time));

	}

	return expire_time;
}

static char *get_expire_time(wodan2_config_t *config,
		      request_rec *r, struct httpresponse *httpresponse,
		      int *cachetime_interval)
{
	int cachetime;
	char *expire_time_rfc822_string = NULL;
	char *xwodan;
	apr_time_t expire_time = 0;
	

	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "entering %s", __func__);
	
	*cachetime_interval = 0;
	cachetime = find_cache_time(config, r, httpresponse);
	/* check X-Wodan header */
	if (httpresponse && 
	    (xwodan = (char *) apr_table_get(httpresponse->headers, "X-Wodan"))
	    != NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "Found an X-Wodan header \"%s\"", xwodan);
		if (strcasecmp(xwodan, "no-cache") == 0) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
				     r->server, "Header is 'no-cache'. "
				     "Not caching..." );
			return NULL;
		} else if (strncasecmp(xwodan, "expire", 6) == 0) {
			expire_time = parse_xwodan_expire(r, xwodan, 
							  cachetime,
							  cachetime_interval);
			if (expire_time == 0)
				return NULL;
			expire_time_rfc822_string = apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
			apr_rfc822_date(expire_time_rfc822_string, expire_time);
		} else {
			if (cachetime == -1) {
				ap_log_error(APLOG_MARK, 
					     APLOG_NOERRNO|APLOG_DEBUG, 0,
					     r->server, 
					     "WodanDefaultCacheTime in httpd.conf "
					     "is 'no-cache'. Not caching..." );
				return NULL;
			}
		}
	}

	if (expire_time_rfc822_string == NULL) {
		expire_time = r->request_time + cachetime;
		*cachetime_interval = cachetime;
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			     "No expire-header found. Using default cache "
			     " time" );
		expire_time_rfc822_string = apr_pcalloc(r->pool, APR_RFC822_DATE_LEN);
		apr_rfc822_date(expire_time_rfc822_string, expire_time);
	}
	return expire_time_rfc822_string;
}

static apr_file_t *open_cachefile(wodan2_config_t *config, request_rec *r)
{
	apr_file_t *cachefile = NULL;
	char *cachefilename;
	int i;
	char *subdir;
	int result;
	struct stat dir_status;

	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);	
	for (i = 0; i < config->cachedir_levels; i++) {
		subdir = get_cache_file_subdir(config, r, cachefilename, i);
		
		result = stat( subdir, &dir_status );
		if ( ( result != 0 ) || ( ! S_ISDIR( dir_status.st_mode ) ) )
			mkdir( subdir, 0770 );
	}

	apr_file_open(&cachefile, cachefilename, 
		APR_WRITE | APR_CREATE | APR_TRUNCATE, APR_OS_DEFAULT,
		r->pool);
	if(cachefile == NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "Error opening cache file, filename = %s, config->cachedir = %s", 
			     cachefilename, config->cachedir);
		return NULL;
	}
	return cachefile;
}

/**
 * @param cachefile the cache file
 * @param r request record
 * @param httpresponse httpresponse record
 * @param expire_time_string time at which cache expires.
 * @param expire_interval time interval between request and expire
 */
static int write_preamble(apr_file_t *cachefile, request_rec *r,
			  httpresponse_t *httpresponse, 
			  char *expire_time_string,
			  int expire_interval)
{
	apr_file_printf(cachefile, "%s%s", r->unparsed_uri, CRLF);
	apr_file_printf(cachefile, "%d%s", expire_interval, CRLF);
	apr_file_printf(cachefile, "%s%s", expire_time_string, CRLF);
	apr_file_printf(cachefile, "%d%s", httpresponse->response, CRLF);
	/* TODO add error checking */
	//Write headers
	{
		int i;
		const apr_array_header_t *headers_array = apr_table_elts(httpresponse->headers);
		apr_table_entry_t *headers_elts = (apr_table_entry_t *) headers_array->elts;
		
		for(i = 0; i < headers_array->nelts; i++)
	        {
			apr_file_printf(cachefile, "%s: %s%s", headers_elts[i].key, 
				headers_elts[i].val, CRLF);
			/* TODO add error checking */
		}
	}
	//Write end of headers line
	apr_file_printf(cachefile, "%s", CRLF);
	/* TODO add  eror checking */
	return 0;
}

apr_file_t *cache_get_cachefile(wodan2_config_t *config, request_rec *r, 
	struct httpresponse *httpresponse)
{
	apr_file_t *cache_file = NULL;
	char *expire = NULL;
	int expire_interval = 0;
	char *tempfile_template;
	char *temp_dir;	
	
	if(!is_cachedir_set(config)) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0,
		     r->server, "%s: cachedir not set.", __func__);

		return NULL;
	}

	if (r->method_number != M_GET ||
	    r->header_only ||
	    !is_response_cacheable(httpresponse->response, 
				   config->cache_404s)) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,
			     r->server, "Response isn't cacheable");
		return NULL;
	}
	
	if ((char *) ap_strcasestr(r->unparsed_uri, "cache=no") != NULL)
		return NULL;
	if ((expire = get_expire_time(config, r, httpresponse,
				      &expire_interval)) == NULL)
		return NULL;
	
	if (apr_temp_dir_get((const char **) &temp_dir, r->pool) != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0,
			r->server, "unable to find temp dir");
		return NULL;
	}
	tempfile_template = apr_psprintf(r->pool, "%s/wodan_temp_XXXXXX", temp_dir);
	if (apr_file_mktemp(&cache_file, tempfile_template, 0, r->pool) != APR_SUCCESS)
		return NULL;
	
	/* write url, expire, cache constraint and headers */
	if (write_preamble(cache_file, r, httpresponse, expire,
			   expire_interval) == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			     "error writing preamble to tempcachefile");
		apr_file_close(cache_file);
		return NULL;
	}
	return cache_file;
}

void cache_close_cachefile(wodan2_config_t *config, request_rec *r,
	apr_file_t *temp_cachefile)
{
	apr_file_t *real_cachefile;
	char buffer[BUFFERSIZE];
	apr_size_t bytes_read, bytes_written;
	apr_off_t START_OF_FILE_OFFSET = 0; /* this cannot be declared constant because
	* it will be passed by reference to apr_file_seek */

	/* open the real cache file (until now, only a temporary file
	   was openened) */
	if (!temp_cachefile) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
			"no temp cachefile");
	}
	if (temp_cachefile) {
		if ((real_cachefile = open_cachefile(config, r)) == NULL) {
			apr_file_close(temp_cachefile);
			return;
		}
		apr_file_seek(temp_cachefile, APR_SET, (apr_off_t *) &START_OF_FILE_OFFSET);
		/* TODO add error checking */
		while(!apr_file_eof(temp_cachefile)) {
			apr_file_read_full(temp_cachefile, buffer, BUFFERSIZE, &bytes_read);
			apr_file_write_full(real_cachefile, buffer, bytes_read, &bytes_written);
			if (bytes_read != bytes_written) {
				// TODO: What now This is an error. The read_full and write_full
				// functions should block until everything's read and written 
			}
			if(bytes_read < BUFFERSIZE)
				break;
		}
		/* TODO add error checking for file reads and writes */		
		apr_file_close(temp_cachefile);
		apr_file_flush(real_cachefile);
		apr_file_close(real_cachefile);
	}
}		

int cache_update_expiry_time(wodan2_config_t *config, request_rec *r) 
{
	char *cachefilename;
	int expire_interval;
	char *expire_time_string;
	apr_file_t *cachefile;
	char buffer[BUFFERSIZE];
	apr_size_t bytes_written;

	get_cache_filename(config, r, r->unparsed_uri, &cachefilename);
	(void) get_expire_time(config, r, NULL, &expire_interval);
       
    if (apr_file_open(&cachefile, cachefilename, APR_WRITE, APR_OS_DEFAULT,
    		r->pool) != APR_SUCCESS) 
    		return -1;   
	
	/* skip URL field */
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	apr_file_gets(buffer, BUFFERSIZE, cachefile);
	/* calculate new expire_time */
	expire_interval = (int) strtol(buffer, NULL, 10);
	expire_time_string = ap_ht_time(r->pool, 
					(r->request_time + expire_interval), 
					"%a %d %b %Y %T %Z",1);
	/* write new expire time field in cachefile */
	apr_file_write_full(cachefile, expire_time_string, strlen(expire_time_string),
		&bytes_written);
	if (bytes_written != strlen(expire_time_string)) {
		ap_log_error(APLOG_MARK, 
			APLOG_NOERRNO|APLOG_DEBUG, 0,
			r->server, 
			"%s: error writing to cachefile", __func__);
	
		apr_file_close(cachefile);
		return -1;
	}
	apr_file_flush(cachefile);
	apr_file_close(cachefile);
	return 0;
}

/** static functions down here */

static int get_cache_filename(wodan2_config_t *config, request_rec *r,
	char *unparsed_uri, char **filename )
{
	char *md5_checksum;
	char dir[MAX_CACHEFILE_PATH_LENGTH + 1];
	char *ptr;
	int i;

	md5_checksum = ap_md5(r->pool, unparsed_uri);
	/* If cachedir + subdirs + md5sum don't fit in buffer, 
	 * we have a problem */
	if (strlen(config->cachedir) > 
	     (MAX_CACHEFILE_PATH_LENGTH - 32 - (2 * MAX_CACHEDIR_LEVELS))) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
			     "Cachefile pathname doesn't fit into buffer.");
		*filename = NULL;
		return 0;
	}

	apr_cpystrn(dir, config->cachedir, MAX_CACHEFILE_PATH_LENGTH + 1);
	ptr = &dir[0] + (int) strlen(dir);
	
	if (*ptr == '/')
		ptr--;

	for (i = 0; i < config->cachedir_levels; i++) {
		ptr[0] = '/';
		ptr[1] = md5_checksum[i];
		ptr += 2;
	}
	*ptr = '\0';

	*filename = ap_make_full_path(r->pool, dir, md5_checksum);
	ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r->server,
		     "Cachefile pathname: %s", *filename);	
	return 1;
}

static char *get_cache_file_subdir(wodan2_config_t *config, request_rec *r, 
				   char *cachefilename, int nr)
{
	int count;
	char *ptr;
	char *buffer;

	buffer = apr_pstrdup(r->pool, cachefilename);

	/* We count back (from the end of the path) just enough parts 
	   to get the desired subdir */
	count = config->cachedir_levels - nr;
	ptr = buffer + (int) strlen(buffer);

	while ( ( count > 0 ) && ( ptr > buffer ) ) {
		if ( *ptr == '/' ) {
			*ptr = '\0';
			count--;
		}
		ptr--;
	}

	return buffer;
}

static int is_response_cacheable (int httpcode, int cache404s)
{
	if (cache404s)
		if (httpcode == 404)
			return 1;

	if(httpcode >= 200 && httpcode < 400)
		return 1;
	else return 0;
}

static int is_cachedir_set(wodan2_config_t* config)
{
     if (config->is_cachedir_set)
		return 1;
	else 
		return 0;
}
