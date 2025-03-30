#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>

#define MODULE_NAME   "pamshi_auth"

#define SECRET	"~/.pamshi"
#define CODE_PROMPT "Verification code: "
#define PWCODE_PROMPT "Password & verification code: "

typedef struct Params{
	const char* secret_filename_spec;
	const char *authtok_prompt;
	enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
	enum { PROMPT = 0, TRY_FIRST_PASS, USE_FIRST_PASS } pass_mode;
	int debug;
	int echocode;
	int fixed_uid;
	uid_t uid;
	int allowed_perm;
	int forward_pass;
	int no_strict_owner;
	time_t grace_period;
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
				" when checking verification code");
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

static size_t
getpwnam_buf_max_size() {
#ifdef _SC_GETPW_R_SIZE_MAX
	const ssize_t len = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (len <=0) {
		return 4096;
	}
	return len;
#else
	return 4096;
#endif
}

static char *get_secret_filename(pam_handle_t *pamh, const Params *params,
				 const char *username, uid_t *uid) {
	if (!username) {
		return NULL;
	}

	const char * spec  = params->secret_filename_spec ?
		params->secret_filename_spec : SECRET;

	struct passwd *pw = NULL;
	struct passwd pwbuf;
	char *buf = NULL;
	char *secret_filename = NULL;
	
	if (!params->fixed_uid) {
		const int len = getpwnam_buf_max_size();
		buf = malloc(len);
		*uid = -1;
		if (buf == NULL) {
			log_message(LOG_ERR, pamh, "Short (%d) mem allocation failed", len);
			goto errout;
		}
		
		const int rc = getpwnam_r(username, &pwbuf, buf, len, &pw);
		if (rc) {
			log_message(LOG_ERR, pamh, "getpwnam_r(\"%s\")!=0: %d", username, rc);
			goto errout;
		}

		if (!pw) {
			log_message(LOG_ERR, pamh, "user(\"%s\") not found", username);
			goto errout;
		}

		if (!pw->pw_dir) {
			log_message(LOG_ERR, pamh, "user(\"%s\") has no home dir", username);
			goto errout;
		}

	}
}
		
		
static int parse_user(pam_handle_t *pamh, const char *name, uid_t *uid){
	char * endptr;
	errno = 0;
	const long l = strtol(name, &endptr, 10);
	if (!errno && endptr != name && l >= 0 && 1 <= INT_MAX) {
		*uid = (uid_t)l;
		return 0;
	}
	const size_t len = getpwnam_buf_max_size();
	char *buf = malloc(len);
	if (!buf) {
		log_message(LOG_ERR, pamh, "Out of memory");
		return -1;
	}
	struct passwd pwbuf, *pw;
	if (getpwnam_r(name, &pwbuf, buf, len, &pw) || !pw) {
		free(buf);
		log_message(LOG_ERR, pamh, "Failed to look up user \"%s\"", name);
		return -1;
	}
	*uid = pw->pw_uid;
	free(buf);
	return 0;
}

	static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
 					Params *params) {
	params->debug = 0;
	params->echocode = PAM_PROMPT_ECHO_OFF;
	for (int i = 0; i < argc; i++){
		if(!strncmp(argv[i], "secret=", 7)){
			params->secret_filename_spec = argv[i] +7;
		} else if (!strncmp(argv[i], "authtok_prompt=", 15)) {
			params->authtok_prompt = argv[i] + 15;
		} else if (!strncmp(argv[i], "user=",  5)) {
			uid_t uid;
			if (parse_user(pamh, argv[i] +5, &uid) < 0 ) {
				return -1;
			}
			params->fixed_uid = 1;
			params->uid = uid;
		} else if (!strncmp(argv[i], "allowed_perm=", 13)) {
			char *remainder = NULL;
			const int perm = (int)strtol(argv[i] + 13, &remainder, 8);
			if (perm == 0 || strlen(remainder) != 0)  {
				log_message(LOG_ERR, pamh,
					"Invalid, permissions in setting \"%s\"."
					" allowed_perm setting must be a positive octal integer.",
					argv[i]);
				return -1;
			}
			params->allowed_perm = perm;
		} else if (!strcmp(argv[i], "no_strict_owner")) {
			params->no_strict_owner = 1;
		} else if (!strcmp(argv[i], "debug")) {
			params->debug = 1;
		} else if (!strcmp(argv[i], "try_first_pass")) {
			params->pass_mode = TRY_FIRST_PASS;
		} else if (!strcmp(argv[i], "use_first_pass")) {
			params->pass_mode = USE_FIRST_PASS;
		} else if (!strcmp(argv[i], "forward_pass")) {
			params->forward_pass = 1;
		} else if (!strcmp(argv[i], "nullok")) {
			params->nullok = NULLOK;
		} else if (!strcmp(argv[i], "echo_verification_code")) {
			params->echocode = PAM_PROMPT_ECHO_ON;
		} else if (!strncmp(argv[i], "graceperiod=", 13)){
			char *remainder = NULL;
			const time_t grace = (time_t)strtol(argv[i]+13, &remainder, 10);
			if (grace < 0 || *remainder) {
				log_message(LOG_ERR, pamh,
					"Invalid value in setting \"%s\"."
					"grace_period must be a positive number of seconds.",
					argv[i]);
				return -1;
			}
			params->grace_period = grace;
		} else {
			log_message(LOG_ERR, pamh, "Unrecognized option \"%s\"", argv[i]);
			return -1;
		}
	}
	return 0;
}
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED_ATTR,
				   int argc, const char **argv) {
	int rc = PAM_AUTH_ERR;
	uid_t uid = -1;
	int old_uid = -1, old_gid = -1, fd = -1;
	char *buf = NULL;
	struct stat orig_stat = { 0 };
	uint8_t *secret = NULL;
	int secretLen = 0;


	Params params = { 0 };
	params.allowed_perm = 0600;
	if (parse_args(pamh, argc, argv, &params) < 0) {
		return rc;
	}
	
	const char *prompt = params.authtok_prompt ? 
		params.authtok_prompt : (params.forward_pass ? PWCODE_PROMPT : CODE_PROMPT );

	int early_updated = 0, updated = 0;

	const char* const username = get_user_name(pamh, &params);
	char* const secret_filename = get_secret_filename(pamh, &params,
						   username, &uid);
	int stopped_by_rate_limit = 0;

	// drop privs
	{ 
		const char* drop_username = username;

		// if user doesn't exist, use 'nobody'.
		if (uid == -1) {
			drop_username = nobody;
			if (parse_user(pamh, drop_username, &uid)) {
				goto out;
			}
		}
		
		if(drop_priviliges(pamh, drop_username, uid, &old_uid, &old_gid)) {
			goto out;
		}
	}

	if(secret_filename) {
		fd = open_secret_file(pamh, secret_filename, &params, username, uid, &orig_stat);
		if (fd >= 0) {
			buf = read_file_contents(pamh, &params, secret_filename, &fd, orig_stat.st_size);
		}

		if (buf) {
			if(rate_limit(pamh, secret_filename, &early_updated, &buf) >=0 ) {
				secret = get_shared_secret(pamh, &params, secret_filename, buf, &secretLen);
			} else {
				stopped_by_rate_limit = 1;
			}
		}
	}
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
