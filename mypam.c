#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>

#define MODULE_NAME   "pamshi_auth"

typedef struct Params{
	int debug;
} Params;

static void log_message(int priority, pam_handle_t *pamh,
				const char* format, ...) {
	char * service = NULL;
	if (pamh)
		pam_get_item(pamh, PAM_SERVICE, (void *)&service);
	if(!service)
		service = "";
	char logname[80];
	snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

	va_list args;
	va_start(args, format);

	openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
	vsyslog(priority, format, args);
	closelog();

	va_end(args);

	if(priority == LOG_EMERG) {
		_exit(1);
	}
	return;
}


static const char* get_user_name(pam_handle_t *pamh, const Params *params){
	const char* username;
	if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
		!username || !*username){
		log_message(LOG_ERR, pamh, "pam_get_user() failed to get a user name"
				" when checkign verification code");
		return NULL;
	}
	if (params->debug){
		log_message(LOG_INFO, pamh, "debug: start of pamshi authenticator for \"%s\"", username);
	}
	return username;
}

#ifndef UNUSED_ATTR
# if __GNUC__ >=3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
# define UNUSED_ATTR __attribute__((__unused__))
# else
# define UNUSED_ATTR
# endif
# endif


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR,
				   int argc, const char **argv) {
	Params params = { 0 } ;
	int rc = PAM_AUTH_ERR;
	params.debug = 1;
	const char* const username = get_user_name(pamh, &params);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh UNUSED_ATTR,
			       int flags UNUSED_ATTR,
			       int argc UNUSED_ATTR,
			       const char **argv UNUSED_ATTR) {
	return PAM_SUCCESS;
}


#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
	MODULE_NAME,
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif
