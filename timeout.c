/** $Id: timeout.c 164 2005-02-25 14:17:25Z ilja $
* (c) 2000-2005 IC&S, The Netherlands
*/

#include "timeout.h"

#include "httpd.h"
#include "http_log.h"

#include <signal.h>
#include <sys/time.h>
#include <errno.h>

/* a dummy signal handler for the connect() time out */
static void timeout_handler(int signo __attribute__((__unused__))) {}

static struct itimerval conn_timer;

static struct sigaction old_action;

/* set a timeout (used for setting timeouts on connections) */
int timeout_set_timeout(request_rec *r, struct timeval timeout) 
{
	conn_timer.it_interval.tv_usec = 0;
	conn_timer.it_interval.tv_sec = 0;
	conn_timer.it_value.tv_usec = timeout.tv_usec;
	conn_timer.it_value.tv_sec = timeout.tv_sec;

	/* get the old timeout handler */
	sigaction(SIGALRM, NULL, &old_action);
	
	signal(SIGALRM, timeout_handler);
	if (setitimer(ITIMER_REAL, &conn_timer, NULL) < 0) {
		/* reset old timeout handler */
		sigaction(SIGALRM, &old_action, NULL);
		if (errno == EFAULT) 
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, 
				     ":badd addres");
		if (errno == EINVAL)
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
				     "EINVAL, timeout = %ld, %ld", 
				     (long) timeout.tv_sec, 
				     (long) timeout.tv_usec);

		return -1;

	}
	return 1;
}

void timeout_reset_timeout(void)
{
	timerclear(&(conn_timer.it_value));
	
	/* make sure that SIGALRM triggers the action it was supposed to 
	 * trigger before we set our timeout. This needs to be, for instance
	 * for making sure that timeouts still work. */
	sigaction(SIGALRM, &old_action, NULL);
}

