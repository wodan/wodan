#ifndef TIMEOUT_H
#define TIMEOUT_H

#include "httpd.h"
#include <sys/time.h>

/**
 * set a new timeout. SIGALRM will be set when the timeout is reached.
 * @param r request record.
 * @param timeout the values for the timeout
 * @retval -1 on error
 * @retval  1 on succes
 * @note The previous sigaction for SIGALRM is stored and is only restored
 * if timeout_unset_timeout() is called. 
 */
int timeout_set_timeout(request_rec *r, struct timeval timeout);

/**
 * reset the timeout. This restores the old signal handler
 */
void timeout_reset_timeout(void);
#endif /* TIMEOUT_H */
