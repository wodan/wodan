#ifndef _UTIL_H_
#define _UTIL_H_

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"

/**
 * determines if a file or directory is writable
 * @param p memory pool
 * @param path the path to check
 * @retval 1 if writable
 * @retval 0 if not writable
 */
int util_file_is_writable(apr_pool_t *p, const char *path);

/**
 * determines if a string is a number (contains only digits)
 * @param the_string
 * @retval 1 if it is a number
 * @retval 0 if it's not a number
 * @note make sure the string is NUL-terminated!
 */
int util_string_is_number(const char *the_string);

/**
 * translates the string to seconds. The string can be of the format:
 * [0-9]*[wWdDhHmMsS]{0,1}
 * Where w/W is Week, d/D is day, h/H is hour, m/M is minute, s/S is second.
 * The number before the modifier will be multiplied by the number of seconds
 * int a week/day/hour/minute/second. Without a modifier, the number is in seconds.
 * @param string the string containing the time.
 * @retval 0 if not parsable.
 * @retval MAX_CACHE_TIMEOUT if number to big
 * @retval number of seconds otherwise.
 */
apr_int32_t util_timestring_to_seconds(char *string);

#endif //_UTIL_H_
