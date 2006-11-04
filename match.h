/** $Id: match.h 162 2005-02-16 15:36:06Z ilja $
 * (c) 2005-2006 IC&S, The Netherlands 
 */

/** \file match.h
 * functions for performing matches of URI's against destinations,
 * aliases and defaultcachetimes defined in the config.
 */

#ifndef _MATCH_H
#define _MATCH_H

#include "datatypes.h"

#include "apr_tables.h"

/**
 * Find the longest match in config directives for aliases
 * @param config the configuration for Wodan
 * @param uri the uri to check
 * @return a proxy alias, or NULL if none found
 */
wodan2_proxy_alias_t* alias_longest_match(wodan2_config_t *config,
	char *uri);

/**
 * find the longest match in config directives for destinations
 * @param config the configuration for Wodan
 * @param uri the uri to check
 */
wodan2_proxy_destination_t * destination_longest_match(wodan2_config_t *config,
	char *uri);

/**
 * find the longest match in config directives for defaultcachetimes
 */
wodan2_default_cachetime_t* default_cachetime_longest_match(wodan2_config_t *config,
	char *uri);

/**
 * find a match for the regular expression in the defaultcachetimes_regex
 */
wodan2_default_cachetime_regex_t* 
default_cachetime_regex_match(wodan2_config_t *config, char *uri);

/**
 * find a match for the regular expression against the http headers
 */
wodan2_default_cachetime_header_t*
default_cachetime_header_match(wodan2_config_t *config, apr_table_t *headers);

#endif
