#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <fcntl.h>
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
#include <config.h>
#include <curl/curl.h>
#include "base32.h"
#include "cJSON.h"
#include "qrcode.h"
#ifdef HAVE_SYS_FSUID_H
// We much rather prefer to use setfsuid(), but this function is unfortunately
// not available on all systems.
#include <sys/fsuid.h>
#endif

#define MODULE_NAME   "pamshi_auth"

#define SECRET	"/etc/pamshi/.config"
#define DEVICE_AUTHORIZATION_ENDPOINT "/oauth/device_authorization"
#define DEVICE_ACCESS_TOKEN_ENDPOINT "/oauth/token"
#define DEVICE_ACCESS_TOKEN_GRANT_TYPE "urn:ietf:params:oauth:grant-type:device_code"

typedef struct Params{
	const char* secret_filename_spec;
	const char * authtok_prompt;
  const char * auth_server_url;
  const char * username;
	enum { NULLERR=0, NULLOK, SECRETNOTFOUND } nullok;
	int debug;
	int echocode;
	int fixed_uid;
	uid_t uid;
	int allowed_perm;
	int forward_pass;
	int no_strict_owner;
	time_t grace_period;
} Params;

static char oom;

static const char* nobody = "nobody";

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

static int converse(pam_handle_t *pamh, int nargs,
                    PAM_CONST struct pam_message **message,
                    struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
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

/*
 * Return rhost as a string. Return value must not be free()ed.
 * Returns NULL if PAM_RHOST is not known.
 */
static const char *
get_rhost(pam_handle_t *pamh, const Params *params) {
  // Get the remote host
  PAM_CONST void *rhost;
  if (pam_get_item(pamh, PAM_RHOST, &rhost) != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "pam_get_rhost() failed to get the remote host");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: pamshi for host \"%s\"",
                rhost);
  }
  return (const char *)rhost;
}

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

		if (*pw->pw_dir != '/') {
			log_message(LOG_ERR, pamh, "User \"%s\" home dir not absolute", username);
			goto errout;
		}
	}


	// Expand filename specification to an actual filename.
	if ((secret_filename = strdup(spec)) == NULL) {
		log_message(LOG_ERR, pamh, "Short (%d) mem allocation failed", strlen(spec));
		goto errout;
	}
	int allow_tilde = 1;
	for (int offset = 0; secret_filename[offset];) {
		char *cur = secret_filename + offset;
		char *var = NULL;
		size_t var_len = 0;
		const char *subst = NULL;
		if (allow_tilde && *cur == '~') {
		var_len = 1;
		if (!pw) {
			log_message(LOG_ERR, pamh,
						"Home dir in 'secret' not implemented when 'user' set");
			goto errout;
		}
		subst = pw->pw_dir;
		var = cur;
		} else if (secret_filename[offset] == '$') {
		if (!memcmp(cur, "${HOME}", 7)) {
			var_len = 7;
			if (!pw) {
			log_message(LOG_ERR, pamh,
						"Home dir in 'secret' not implemented when 'user' set");
			goto errout;
			}
			subst = pw->pw_dir;
			var = cur;
		} else if (!memcmp(cur, "${USER}", 7)) {
			var_len = 7;
			subst = username;
			var = cur;
		}
		}
		if (var) {
		const size_t subst_len = strlen(subst);
		if (subst_len > 1000000) {
			log_message(LOG_ERR, pamh, "Unexpectedly large path name: %d", subst_len);
			goto errout;
		}
		const int varidx = var - secret_filename;
		char *resized = realloc(secret_filename,
								strlen(secret_filename) + subst_len + 1);
		if (!resized) {
			log_message(LOG_ERR, pamh, "Short mem allocation failed");
			goto errout;
		}
		var = resized + varidx;
		secret_filename = resized;
		memmove(var + subst_len, var + var_len, strlen(var + var_len) + 1);
		memmove(var, subst, subst_len);
		offset = var + subst_len - resized;
		allow_tilde = 0;
		} else {
		allow_tilde = *cur == '/';
		++offset;
		}
	}

	*uid = params->fixed_uid ? params->uid : pw->pw_uid;
	free(buf);
	return secret_filename;

	errout:
	free(secret_filename);
	free(buf);
	return NULL;
}


static int setuser(int uid) {
#ifdef HAVE_SETFSUID
  // The semantics for setfsuid() are a little unusual. On success, the
  // previous user id is returned. On failure, the current user id is returned.
  int old_uid = setfsuid(uid);
  if (uid != setfsuid(uid)) {
    setfsuid(old_uid);
    return -1;
  }
#else
#ifdef linux
#error "Linux should have setfsuid(). Refusing to build."
#endif
  int old_uid = geteuid();
  if (old_uid != uid && seteuid(uid)) {
    return -1;
  }
#endif
  return old_uid;
}

static int setgroup(int gid) {
#ifdef HAVE_SETFSGID
  // The semantics of setfsgid() are a little unusual. On success, the
  // previous group id is returned. On failure, the current groupd id is
  // returned.
  int old_gid = setfsgid(gid);
  if (gid != setfsgid(gid)) {
    setfsgid(old_gid);
    return -1;
  }
#else
  int old_gid = getegid();
  if (old_gid != gid && setegid(gid)) {
    return -1;
  }
#endif
  return old_gid;
}

// Drop privileges and return 0 on success.
static int drop_privileges(pam_handle_t *pamh, const char *username, int uid,
                           int *old_uid, int *old_gid) {
  // Try to become the new user. This might be necessary for NFS mounted home
  // directories.

  // First, look up the user's default group
  #ifdef _SC_GETPW_R_SIZE_MAX
  int len = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (len <= 0) {
    len = 4096;
  }
  #else
  int len = 4096;
  #endif
  char *buf = malloc(len);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  struct passwd pwbuf, *pw;
  if (getpwuid_r(uid, &pwbuf, buf, len, &pw) || !pw) {
    log_message(LOG_ERR, pamh, "Cannot look up user id %d", uid);
    free(buf);
    return -1;
  }
  gid_t gid = pw->pw_gid;
  free(buf);
  int gid_o = setgroup(gid);
  int uid_o = setuser(uid);
  if (uid_o < 0) {
    if (gid_o >= 0) {
      if (setgroup(gid_o) < 0 || setgroup(gid_o) != gid_o) {
        // Inform the caller that we were unsuccessful in resetting the group.
        *old_gid = gid_o;
      }
    }

    log_message(LOG_ERR, pamh, "Failed to change user id to \"%s\"",
                username);
    return -1;
  }
  if (gid_o < 0 && (gid_o = setgroup(gid)) < 0) {
    // In most typical use cases, the PAM module will end up being called
    // while uid=0. This allows the module to change to an arbitrary group
    // prior to changing the uid. But there are many ways that PAM modules
    // can be invoked and in some scenarios this might not work. So, we also
    // try changing the group _after_ changing the uid. It might just work.
    if (setuser(uid_o) < 0 || setuser(uid_o) != uid_o) {
      // Inform the caller that we were unsuccessful in resetting the uid.
      *old_uid = uid_o;
    }
    log_message(LOG_ERR, pamh,
                "Failed to change group id for user \"%s\" to %d", username,
                (int)gid);
    return -1;
  }

  *old_uid = uid_o;
  *old_gid = gid_o;
  return 0;
}

// open secret file, return fd on success, or <0 on error.
static int open_secret_file(pam_handle_t *pamh, const char *secret_filename,
                            struct Params *params, const char *username,
                            int uid, struct stat *orig_stat) {
  // Try to open "pamshi config"
  const int fd = open(secret_filename, O_RDONLY);
  if (fd < 0 ||
      fstat(fd, orig_stat) < 0) {
    if (params->nullok != NULLERR && errno == ENOENT) {
      // The user doesn't have a state file, but the administrator said
      // that this is OK. We still return an error from open_secret_file(),
      // but we remember that this was the result of a missing state file.
      params->nullok = SECRETNOTFOUND;
    } else {
      log_message(LOG_ERR, pamh, "Failed to read \"%s\" for \"%s\": %s",
                  secret_filename, username, strerror(errno));
    }
 error:
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  if (params->debug) {
    log_message(LOG_INFO, pamh,
                "debug: Secret file permissions are %04o."
                " Allowed permissions are %04o",
                orig_stat->st_mode & 03777, params->allowed_perm);
  }

  // Check permissions on "pamshi config".
  if (!S_ISREG(orig_stat->st_mode)) {
    log_message(LOG_ERR, pamh, "Secret file \"%s\" is not a regular file",
                secret_filename);
    goto error;
  }
  if (orig_stat->st_mode & 03777 & ~params->allowed_perm) {
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" permissions (%04o)"
                " are more permissive than %04o", secret_filename,
                orig_stat->st_mode & 03777, params->allowed_perm);
    goto error;
  }

  if (!params->no_strict_owner && (orig_stat->st_uid != (uid_t)uid)) {
    char buf[80];
    if (params->fixed_uid) {
      snprintf(buf, sizeof buf, "user id %d", params->uid);
      username = buf;
    }
    log_message(LOG_ERR, pamh,
                "Secret file \"%s\" must be owned by \"%s\"",
                secret_filename, username);
    goto error;
  }

  // Sanity check for file length
  if (orig_stat->st_size < 1 || orig_stat->st_size > 64*1024) {
    log_message(LOG_ERR, pamh,
                "Invalid file size for \"%s\"", secret_filename);
    goto error;
  }

  return fd;
}


// Read secret file contents.
// If there's an error the file is closed, NULL is returned, and errno set.
static char *read_file_contents(pam_handle_t *pamh,
                                const Params *params,
                                const char *secret_filename, int *fd,
                                off_t filesize) {
  // Arbitrary limit to prevent integer overflow.
  if (filesize > 1000000) {
    close(*fd);
    errno = E2BIG;
    return NULL;
  }

  // Read file contents
  char *buf = malloc(filesize + 1);
  if (!buf) {
    log_message(LOG_ERR, pamh, "Failed to malloc %d+1", filesize);
    goto out;
  }

  if (filesize != read(*fd, buf, filesize)) {
    log_message(LOG_ERR, pamh, "Could not read \"%s\"", secret_filename);
    goto out;
  }
  close(*fd);
  *fd = -1;

  // The rest of the code assumes that there are no NUL bytes in the file.
  if (memchr(buf, 0, filesize)) {
    log_message(LOG_ERR, pamh, "Invalid file contents in \"%s\"",
                secret_filename);
    goto out;
  }

  // Terminate the buffer with a NUL byte.
  buf[filesize] = '\000';

  if(params->debug) {
    log_message(LOG_INFO, pamh, "debug: \"%s\" read", secret_filename);
  }
  return buf;

out:
  // If we have any data, erase it.
  if (buf) {
    explicit_bzero(buf, filesize);
  }
  free(buf);
  if (*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
  return NULL;
}


// Wrap write() making sure that partial writes don't break everything.
// Return 0 on success, errno otherwise.
static int
full_write(int fd, const char* buf, size_t len) {
  const char* p = buf;
  int errors = 0;
  for (;;) {
    const ssize_t left = len - (p - buf);
    const ssize_t rc = write(fd, p, left);
    if (rc == left) {
      return 0;
    }
    if (rc < 0) {
      switch (errno) {
      case EAGAIN:
      case EINTR:
        if (errors++ < 3) {
          continue;
        }
      }
      return errno;
    }
    p += rc;
  }
}

// Safely overwrite the old secret file.
// Return 0 on success, errno otherwise.
static int write_file_contents(pam_handle_t *pamh,
                               const Params *params,
                               const char *secret_filename,
                               struct stat *orig_stat,
                               const char *buf) {
  int err = 0;
  int fd = -1;
  const size_t fnlength = strlen(secret_filename) + 1 + 6 + 1;

  char *tmp_filename = malloc(fnlength);
  if (tmp_filename == NULL) {
    err = errno;
    goto cleanup;
  }

  if (fnlength - 1 != snprintf(tmp_filename, fnlength,
                               "%s~XXXXXX", secret_filename)) {
    err = ERANGE;
    goto cleanup;
  }
  const mode_t old_mask = umask(077);
  fd = mkstemp(tmp_filename);
  umask(old_mask);
  if (fd < 0) {
    err = errno;
    log_message(LOG_ERR, pamh, "Failed to create tempfile \"%s\": %s",
                tmp_filename, strerror(err));

    // Couldn't open file; don't try to delete it later.
    free(tmp_filename);
    tmp_filename = NULL;
    goto cleanup;
  }
  if (fchmod(fd, 0400)) {
    err = errno;
    goto cleanup;
  }

  // Make sure the secret file is still the same. This prevents attackers
  // from opening a lot of pending sessions and then reusing the same
  // scratch code multiple times.
  //
  // (except for the brief race condition between this stat and the
  // `rename` below)
  {
    struct stat sb;
    if (stat(secret_filename, &sb) != 0) {
      err = errno;
      log_message(LOG_ERR, pamh, "stat(): %s", strerror(err));
      goto cleanup;
    }

    if (sb.st_ino != orig_stat->st_ino ||
        sb.st_size != orig_stat->st_size ||
        sb.st_mtime != orig_stat->st_mtime) {
      err = EAGAIN;
      log_message(LOG_ERR, pamh,
                  "Secret file \"%s\" changed while trying to use "
                  "scratch code\n", secret_filename);
      goto cleanup;
    }
  }

  // Write the new file contents.
  if ((err = full_write(fd, buf, strlen(buf)))) {
    log_message(LOG_ERR, pamh, "write(): %s", strerror(err));
    goto cleanup;
  }
  if (fsync(fd)) {
    err = errno;
    log_message(LOG_ERR, pamh, "fsync(): %s", strerror(err));
    goto cleanup;
  }
  if (close(fd)) {
    err = errno;
    log_message(LOG_ERR, pamh, "close(): %s", strerror(err));
    goto cleanup;
  }
  fd = -1; // Prevent double-close.

  // Double-check that the file size is correct.
  {
    struct stat st;
    if (stat(tmp_filename, &st)) {
      err = errno;
      log_message(LOG_ERR, pamh, "stat(%s): %s", tmp_filename, strerror(err));
      goto cleanup;
    }
    const off_t want = strlen(buf);
    if (st.st_size == 0 || (want != st.st_size)) {
      err = EAGAIN;
      log_message(LOG_ERR, pamh, "temp file size %d. Should be non-zero and %d", st.st_size, want);
      goto cleanup;
    }
  }
  
  if (rename(tmp_filename, secret_filename) != 0) {
    err = errno;
    log_message(LOG_ERR, pamh, "rename(): %s", strerror(err));
    goto cleanup;
  }
  free(tmp_filename);
  tmp_filename = NULL; // Prevent unlink & double-free.

  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: \"%s\" written", secret_filename);
  }

cleanup:
  if (fd >= 0) {
    close(fd);
  }
  if (tmp_filename) {
    if (unlink(tmp_filename)) {
      log_message(LOG_ERR, pamh, "Failed to delete tempfile \"%s\": %s",
                  tmp_filename, strerror(errno));
    }
  }
  free(tmp_filename);

  if (err) {
    log_message(LOG_ERR, pamh, "Failed to update secret file \"%s\": %s",
                secret_filename, strerror(err));
    return err;
  }
  return 0;
}

// given secret file content (buf), extract the secret and base32 decode it.
//
// Return pointer to `malloc()`'d secret on success (caller frees),
// NULL on error. Length of secret stored in *secretLen.
static uint8_t *get_shared_secret(pam_handle_t *pamh,
                                  const Params *params,
                                  const char *secret_filename,
                                  const char *buf, int *secretLen) {
  if (!buf) {
    return NULL;
  }
  // Decode secret key
  const int base32Len = strcspn(buf, "\n");

  // Arbitrary limit to prevent integer overflow.
  if (base32Len > 100000) {
    return NULL;
  }

  *secretLen = (base32Len*5 + 7)/8;
  uint8_t *secret = malloc(base32Len + 1);
  if (secret == NULL) {
    *secretLen = 0;
    return NULL;
  }
  memcpy(secret, buf, base32Len);
  secret[base32Len] = '\000';
  if ((*secretLen = base32_decode(secret, secret, base32Len)) < 1) {
    log_message(LOG_ERR, pamh,
                "Could not find a valid BASE32 encoded secret in \"%s\"",
                secret_filename);
    explicit_bzero(secret, base32Len);
    free(secret);
    return NULL;
  }
  memset(secret + *secretLen, 0, base32Len + 1 - *secretLen);

  if(params->debug) {
    log_message(LOG_INFO, pamh, "debug: shared secret in \"%s\" processed", secret_filename);
  }
  return secret;
}


#ifdef TESTING
static time_t current_time;
void set_time(time_t t) __attribute__((visibility("default")));
void set_time(time_t t) {
  current_time = t;
}

static time_t get_time(void) {
  return current_time;
}
#else
static time_t get_time(void) {
  return time(NULL);
}
#endif

static int comparator(const void *a, const void *b) {
  return *(unsigned int *)a - *(unsigned int *)b;
}

static char *get_cfg_value(pam_handle_t *pamh, const char *key,
                           const char *buf) {
  const size_t key_len = strlen(key);
  for (const char *line = buf; *line; ) {
    const char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !strncmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      ptr += strspn(ptr, " \t");
      size_t val_len = strcspn(ptr, "\r\n");
      char *val = malloc(val_len + 1);
      if (!val) {
        log_message(LOG_ERR, pamh, "Out of memory");
        return &oom;
      } else {
        memcpy(val, ptr, val_len);
        val[val_len] = '\000';
        return val;
      }
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }
  return NULL;
}

static int set_cfg_value(pam_handle_t *pamh, const char *key, const char *val,
                         char **buf) {
  const size_t key_len = strlen(key);
  char *start = NULL;
  char *stop = NULL;

  // Find an existing line, if any.
  for (char *line = *buf; *line; ) {
    char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !strncmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      start = line;
      stop  = start + strcspn(start, "\r\n");
      stop += strspn(stop, "\r\n");
      break;
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }

  // If no existing line, insert immediately after the first line.
  if (!start) {
    start  = *buf + strcspn(*buf, "\r\n");
    start += strspn(start, "\r\n");
    stop   = start;
  }

  // Replace [start..stop] with the new contents.
  const size_t val_len = strlen(val);
  const size_t total_len = key_len + val_len + 4;
  if (total_len <= stop - start) {
    // We are decreasing out space requirements. Shrink the buffer and pad with
    // NUL characters.
    const size_t tail_len = strlen(stop);
    memmove(start + total_len, stop, tail_len + 1);
    memset(start + total_len + tail_len, 0, stop - start - total_len + 1);
  } else {
    // Must resize existing buffer. We cannot call realloc(), as it could
    // leave parts of the buffer content in unused parts of the heap.
    const size_t buf_len = strlen(*buf);
    const size_t tail_len = buf_len - (stop - *buf);
    char *resized = malloc(buf_len - (stop - start) + total_len + 1);
    if (!resized) {
      log_message(LOG_ERR, pamh, "Out of memory");
      return -1;
    }
    memcpy(resized, *buf, start - *buf);
    memcpy(resized + (start - *buf) + total_len, stop, tail_len + 1);
    memset(*buf, 0, buf_len);
    free(*buf);
    start = start - *buf + resized;
    *buf = resized;
  }

  // Fill in new contents.
  start[0] = '"';
  start[1] = ' ';
  memcpy(start + 2, key, key_len);
  start[2+key_len] = ' ';
  memcpy(start+3+key_len, val, val_len);
  start[3+key_len+val_len] = '\n';

  // Check if there are any other occurrences of "value". If so, delete them.
  for (char *line = start + 4 + key_len + val_len; *line; ) {
    char *ptr;
    if (line[0] == '"' && line[1] == ' ' && !strncmp(line+2, key, key_len) &&
        (!*(ptr = line+2+key_len) || *ptr == ' ' || *ptr == '\t' ||
         *ptr == '\r' || *ptr == '\n')) {
      start = line;
      stop = start + strcspn(start, "\r\n");
      stop += strspn(stop, "\r\n");
      size_t tail_len = strlen(stop);
      memmove(start, stop, tail_len + 1);
      memset(start + tail_len, 0, stop - start);
      line = start;
    } else {
      line += strcspn(line, "\r\n");
      line += strspn(line, "\r\n");
    }
  }

  return 0;
}

static int rate_limit(pam_handle_t *pamh, const char *secret_filename,
                      int *updated, char **buf) {
  const char *value = get_cfg_value(pamh, "RATE_LIMIT", *buf);
  if (!value) {
    // Rate limiting is not enabled for this account
    return 0;
  } else if (value == &oom) {
    // Out of memory. This is a fatal error.
    return -1;
  }

  // Parse both the maximum number of login attempts and the time interval
  // that we are looking at.
  const char *endptr = value, *ptr;
  int attempts, interval;
  errno = 0;
  if (((attempts = (int)strtoul(ptr = endptr, (char **)&endptr, 10)) < 1) ||
      ptr == endptr ||
      attempts > 100 ||
      errno ||
      (*endptr != ' ' && *endptr != '\t') ||
      ((interval = (int)strtoul(ptr = endptr, (char **)&endptr, 10)) < 1) ||
      ptr == endptr ||
      interval > 3600 ||
      errno) {
    free((void *)value);
    log_message(LOG_ERR, pamh, "Invalid RATE_LIMIT option. Check \"%s\".",
                secret_filename);
    return -1;
  }

  // Parse the time stamps of all previous login attempts.
  const unsigned int now = get_time();
  unsigned int *timestamps = malloc(sizeof(int));
  if (!timestamps) {
  oom:
    free((void *)value);
    log_message(LOG_ERR, pamh, "Out of memory");
    return -1;
  }
  timestamps[0] = now;
  int num_timestamps = 1;
  while (*endptr && *endptr != '\r' && *endptr != '\n') {
    unsigned int timestamp;
    errno = 0;
    if ((*endptr != ' ' && *endptr != '\t') ||
        ((timestamp = (int)strtoul(ptr = endptr, (char **)&endptr, 10)),
         errno) ||
        ptr == endptr) {
      free((void *)value);
      free(timestamps);
      log_message(LOG_ERR, pamh, "Invalid list of timestamps in RATE_LIMIT. "
                  "Check \"%s\".", secret_filename);
      return -1;
    }
    num_timestamps++;
    unsigned int *tmp = (unsigned int *)realloc(timestamps,
                                                sizeof(int) * num_timestamps);
    if (!tmp) {
      free(timestamps);
      goto oom;
    }
    timestamps = tmp;
    timestamps[num_timestamps-1] = timestamp;
  }
  free((void *)value);
  value = NULL;

  // Sort time stamps, then prune all entries outside of the current time
  // interval.
  qsort(timestamps, num_timestamps, sizeof(int), comparator);
  int start = 0, stop = -1;
  for (int i = 0; i < num_timestamps; ++i) {
    if (timestamps[i] < now - interval) {
      start = i+1;
    } else if (timestamps[i] > now) {
      break;
    }
    stop = i;
  }

  // Error out, if there are too many login attempts.
  int exceeded = 0;
  if (stop - start + 1 > attempts) {
    exceeded = 1;
    start = stop - attempts + 1;
  }

  // Construct new list of timestamps within the current time interval.
  char* list;
  {
    const size_t list_size = 25 * (2 + (stop - start + 1)) + 4;
    list = malloc(list_size);
    if (!list) {
      free(timestamps);
      goto oom;
    }
    snprintf(list, list_size, "%d %d", attempts, interval);
    char *prnt = strchr(list, '\000');
    for (int i = start; i <= stop; ++i) {
      prnt += snprintf(prnt, list_size-(prnt-list), " %u", timestamps[i]);
    }
    free(timestamps);
  }

  // Try to update RATE_LIMIT line.
  if (set_cfg_value(pamh, "RATE_LIMIT", list, buf) < 0) {
    free(list);
    return -1;
  }
  free(list);

  // Mark the state file as changed.
  *updated = 1;

  // If necessary, notify the user of the rate limiting that is in effect.
  if (exceeded) {
    log_message(LOG_ERR, pamh,
                "Too many concurrent login attempts (\"%s\"). Please try again.", secret_filename);
    return -1;
  }

  return 0;
}


// Show error message to the user.
static void
conv_error(pam_handle_t *pamh, const char* text) {
  PAM_CONST struct pam_message msg = {
    .msg_style = PAM_ERROR_MSG,
    .msg       = text,
  };
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  const int retval = converse(pamh, 1, &msgs, &resp);
  if (retval != PAM_SUCCESS) {
    log_message(LOG_ERR, pamh, "Failed to inform user of error");
  }
  free(resp);
}

/*
 * Return non-zero if the last login from the same host as this one was
 * successfully authenticated within the grace period.
 */
int within_grace_period(pam_handle_t *pamh, const Params *params,
                    const char *buf) {
  const char *rhost = get_rhost(pamh, params);
  const time_t now = get_time();
  const time_t grace = params->grace_period;
  unsigned long when = 0;
  char match[128];
  if (rhost == NULL) {
    return 0;
  }
  snprintf(match, sizeof match, " %s %%lu ", rhost);

  for (int i = 0; i < 10; i++) {
    static char name[] = "LAST0";
    name[4] = i + '0';
    char* line = get_cfg_value(pamh, name, buf);

    if (line == &oom) {
      /* Fatal! */
      return 0;
    }
    if (!line) {
      continue;
    }
    if (sscanf(line, match, &when) == 1) {
      free(line);
      break;
    }
    free(line);
  }

  if (when == 0) {
    /* No match */
    return 0;
  }

  return (when + grace > now);
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
    } else if (!strncmp(argv[i], "auth_server_url=", 16)) {
      params->auth_server_url = argv[i] + 16;
		} else if (!strncmp(argv[i], "user=",  5)) {
			uid_t uid;
			if (parse_user(pamh, argv[i] +5, &uid) < 0 ) {
				return -1;
			}
			params->fixed_uid = 1;
			params->uid = uid;
      params->username = argv[i] + 5;
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
		} else if (!strcmp(argv[i], "nullok")) {
			params->nullok = NULLOK;
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

// Callback function to capture the response data
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    char **response_ptr = (char **)userp;

    // Reallocate memory to append the new data
    char *temp = realloc(*response_ptr, strlen(*response_ptr) + total_size + 1);
    if (!temp) {
        return 0; // Memory allocation failed
    }

    *response_ptr = temp;
    strncat(*response_ptr, (char *)contents, total_size);

    return total_size;
}


static CURLcode perform_device_authorization(pam_handle_t *pamh, CURL *curl, Params *params, const char *client_id, const char *scope, char** output) {
    CURLcode res = CURLE_FAILED_INIT;

    // Allocate and build the full URL
    size_t url_len = strlen(params->auth_server_url) + strlen(DEVICE_AUTHORIZATION_ENDPOINT) + 1;
    char *url = malloc(url_len);
    if (!url) {
        return CURLE_OUT_OF_MEMORY;
    }
    snprintf(url, url_len, "%s%s", params->auth_server_url, DEVICE_AUTHORIZATION_ENDPOINT);
    // Initialize response buffer
    *output = calloc(1, sizeof(char)); // Start with an empty string
    if (!output) {
        free(url);
        return CURLE_OUT_OF_MEMORY;
    }

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

        struct curl_slist *headers = NULL;
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part;

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "client_id");
        curl_mime_data(part, client_id, CURL_ZERO_TERMINATED);

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "scope");
        curl_mime_data(part, scope, CURL_ZERO_TERMINATED);

        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // Set the callback function to capture the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, output);

        res = curl_easy_perform(curl);
        curl_mime_free(mime);
        curl_slist_free_all(headers);
    }
    if (res != CURLE_OK) {
        free(output); 
        output = NULL;
    }
    free(url);
    return res;
}


static int parse_device_auth_json_response(pam_handle_t *pamh, const char *response, char **device_code,
      char **user_code, char **verification_uri, char **verification_uri_complete, int *expires_in, int *interval) {
    cJSON *json = cJSON_Parse(response);
    if (!json) {
        log_message(LOG_ERR, pamh, "Failed to parse JSON response");
        return -1;
    }

    // Extract "device_code"
    cJSON *device_code_item = cJSON_GetObjectItemCaseSensitive(json, "device_code");
    if (cJSON_IsString(device_code_item) && (device_code_item->valuestring != NULL)) {
        *device_code = strdup(device_code_item->valuestring);
    } else {
        log_message(LOG_ERR, pamh, "Missing or invalid 'device_code' in JSON");
        cJSON_Delete(json);
        return -1;
    }

    // Extract "user_code"
    cJSON *user_code_item = cJSON_GetObjectItemCaseSensitive(json, "user_code");
    if (cJSON_IsString(user_code_item) && (user_code_item->valuestring != NULL)) {
        *user_code = strdup(user_code_item->valuestring);
    } else {
        log_message(LOG_ERR, pamh, "Missing or invalid 'user_code' in JSON");
        cJSON_Delete(json);
        return -1;
    }

    // Extract "verification_uri"
    cJSON *verification_uri_item = cJSON_GetObjectItemCaseSensitive(json, "verification_uri");
    if (cJSON_IsString(verification_uri_item) && (verification_uri_item->valuestring != NULL)) {
        *verification_uri = strdup(verification_uri_item->valuestring);
    } else {
        log_message(LOG_ERR, pamh, "Missing or invalid 'verification_uri' in JSON");
        cJSON_Delete(json);
        return -1;
    }

    cJSON *verification_uri_complete_item = cJSON_GetObjectItemCaseSensitive(json, "verification_uri_complete");
    if (cJSON_IsString(verification_uri_complete_item) && (verification_uri_complete_item->valuestring != NULL)) {
        *verification_uri_complete = strdup(verification_uri_complete_item->valuestring);
    } else {
        log_message(LOG_INFO, pamh, "field 'verification_uri_complete' is missing in JSON");
        cJSON_Delete(json);
        return -1;
    }

    cJSON *expires_in_item = cJSON_GetObjectItemCaseSensitive(json, "expires_in");
    if (cJSON_IsNumber(expires_in_item)) {
        *expires_in = expires_in_item->valueint;
    } else {
        log_message(LOG_ERR, pamh, "Missing or invalid 'expires_in' in JSON");
        cJSON_Delete(json);
        return -1;
    }

    cJSON *interval_item = cJSON_GetObjectItemCaseSensitive(json, "interval");
    if (cJSON_IsNumber(interval_item)) {
        *interval = interval_item->valueint;
    } else {
        log_message(LOG_ERR, pamh, "Missing or invalid 'interval' in JSON");
        cJSON_Delete(json);
        return -1;
    }

    cJSON_Delete(json);
    return 0;
}

static CURLcode perform_token_request(pam_handle_t *pamh, CURL *curl, Params *params, 
        const char *client_id, const char *device_code, char **output, long *http_code) {
    CURLcode res = CURLE_FAILED_INIT;

    // Allocate and build the full URL
    size_t url_len = strlen(params->auth_server_url) + strlen(DEVICE_ACCESS_TOKEN_ENDPOINT) + 1;
    char *url = malloc(url_len);
    if (!url) {
        return CURLE_OUT_OF_MEMORY;
    }
    snprintf(url, url_len, "%s%s", params->auth_server_url, DEVICE_ACCESS_TOKEN_ENDPOINT);

    // Initialize response buffer
    *output = calloc(1, sizeof(char)); // Start with an empty string
    if (!*output) {
        free(url);
        return CURLE_OUT_OF_MEMORY;
    }

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

        // Set headers
        struct curl_slist *headers = NULL;
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Set MIME data
        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part;

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "client_id");
        curl_mime_data(part, client_id, CURL_ZERO_TERMINATED);

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "grant_type");
        curl_mime_data(part, DEVICE_ACCESS_TOKEN_GRANT_TYPE, CURL_ZERO_TERMINATED);

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "device_code");
        curl_mime_data(part, device_code, CURL_ZERO_TERMINATED);

        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // Set the callback function to capture the response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, output);

        // Perform the request
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            // Get the HTTP response code
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
        } else {
            *http_code = 0; // Set to 0 on error
        } 
        // Free resources
        curl_mime_free(mime);
        curl_slist_free_all(headers);
    }

    free(url);
    return res;
}


static int parse_token_json_response(pam_handle_t *pamh, const char *response, char **error,
    char **error_description, char **client_id) {
    cJSON *json = cJSON_Parse(response);
    if (!json) {
        log_message(LOG_ERR, pamh, "Failed to parse JSON response");
        return -1;
    }
    // Extract "error" optional
    cJSON *error_item = cJSON_GetObjectItemCaseSensitive(json, "error");
    if (cJSON_IsString(error_item) && (error_item->valuestring != NULL)) {
        *error = strdup(error_item->valuestring);
    } else {
        *error = NULL;
    }

    // Extract "error" optional
    cJSON *error_description_item = cJSON_GetObjectItemCaseSensitive(json, "error_description");
    if (cJSON_IsString(error_description_item) && (error_description_item->valuestring != NULL)) {
        *error_description = strdup(error_description_item->valuestring);
    } else {
        *error_description = NULL;
    }
    // Extract "client_id" optional
    cJSON *client_id_item = cJSON_GetObjectItemCaseSensitive(json, "client_id");
    if (cJSON_IsString(client_id_item) && (client_id_item->valuestring != NULL)) {
        *client_id = strdup(client_id_item->valuestring);
    } else {
        *client_id = NULL;
    }
    cJSON_Delete(json);
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
	int early_updated = 0, updated = 0;
	const char* const username = get_user_name(pamh, &params);
	char* const secret_filename = get_secret_filename(pamh, &params,
						   username, &uid);
	int stopped_by_rate_limit = 0;


	// drop privs
	{ 
    
		const char* drop_username = username;
    if(params.fixed_uid){
      drop_username = params.username;
    }
		// if user doesn't exist, use 'nobody'.
		if (uid == -1) {
			drop_username = nobody;
			if (parse_user(pamh, drop_username, &uid)) {
				goto out;
			}
		}
		
		if(drop_privileges(pamh, drop_username, uid, &old_uid, &old_gid)) {
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

	/*
	* Check to see if a successful login from the same host happened
	* within the grace period. If it did, then allow login without
	* an additional code.
	*/
	if (buf && within_grace_period(pamh, &params, buf)) {
		rc = PAM_SUCCESS;
		log_message(LOG_INFO, pamh,
					"within grace period: \"%s\"", username);
		goto out;
	}

  if (secret){
      CURL *curl = curl_easy_init();
      CURLcode res = CURLE_FAILED_INIT;
      const char *scope = "user:user";
      char* output = NULL;

      for (int mode = 0; mode < 3; mode++) {
          res = perform_device_authorization(pamh, curl, &params, secret, scope, &output);
          if (res == CURLE_OK) {
            break;
          }
          if (mode ==2 ) {
              goto out;
          }
      }

      char *device_code = NULL, *user_code = NULL, *verification_uri = NULL, *verification_uri_complete = NULL;
      int * expires_in = malloc(sizeof(int)), *interval = malloc(sizeof(int));
      if (!expires_in || !interval) {
          log_message(LOG_ERR, pamh, "Out of memory");
          rc = PAM_BUF_ERR;
          goto out;
      }
      if (parse_device_auth_json_response(pamh, output, &device_code, &user_code,
             &verification_uri, &verification_uri_complete , expires_in, interval) == 0) {
          free(output);
      } else {
        log_message(LOG_ERR, pamh, "Failed to parse JSON response");
        goto out;
      }
      log_message(LOG_INFO, pamh, "Device code: %s", device_code);
      time_t expires_at = get_time() + *expires_in;
      log_message(LOG_INFO, pamh, "Expires at: %ld", expires_at);
      // Dynamically allocate memory for the prompt message
      static char* qrcode = NULL;
      enum QRMode qr_mode = QR_UTF8;
      int qr_gen = displayQRCode(verification_uri_complete, qr_mode, &qrcode);
      if (qr_gen == 0) {
          log_message(LOG_ERR, pamh, "Failed to generate QR code %d", qr_gen);
          goto out;
      }
      size_t prompt_len = strlen(verification_uri_complete) + strlen(qrcode) + strlen(user_code) + 200; // Extra space for static text

      char *prompt_message = malloc(prompt_len + 200);
      if (!prompt_message) {
          log_message(LOG_ERR, pamh, "Out of memory while creating prompt message");
          rc = PAM_BUF_ERR;
          goto out;
      }
      // Create the prompt message
      snprintf(prompt_message, prompt_len,
              "This Device is protected by Pam Shi(t)\nVisit: %s \nAnd enter the user code: %s\nOr Scan the below QR Code:\n%s",
              verification_uri, user_code, qrcode);
      free(qrcode);
      // Prepare the PAM message
      struct pam_message msg = {
          .msg_style = PAM_PROMPT_ECHO_OFF,
          .msg = prompt_message
      };
      struct pam_message *msgp = &msg;
      struct pam_response *resp = NULL;

      // Use the converse function to display the prompt
      if (converse(pamh, 1, (PAM_CONST struct pam_message **)&msgp, &resp) != PAM_SUCCESS) {
          log_message(LOG_ERR, pamh, "Failed to display prompt to user");
          rc = PAM_CONV_ERR;
          free(prompt_message);
          goto out;
      }


      if (resp) {
          free(resp); // Free the response if allocated
      }

      free(prompt_message); // Free the dynamically allocated prompt message

      sleep(*((unsigned int*)interval));
      for(;;){
        if(expires_at > get_time()) {
        char *error = NULL, *error_description = NULL, *client_id = NULL;
          char* token_req_output = NULL;
          long http_code = 0;
          // Check if the user has completed the authorization
          res = perform_token_request(pamh, curl, &params, secret, device_code, &token_req_output, &http_code);
          if (res == CURLE_OK) {
            if (parse_token_json_response(pamh, token_req_output, &error, &error_description, &client_id) != 0) {
              log_message(LOG_ERR, pamh, "Failed to parse token response, Let's try requesting again");
              continue;
            }
            if (http_code==200) {
              if ((client_id!=NULL) && strcmp(client_id,(char *)secret)==0) {
                if (params.debug) log_message(LOG_INFO, pamh, "Access granted for client_id: %s", client_id);
                rc = PAM_SUCCESS;
              } else {
                if (params.debug) log_message(LOG_ERR, pamh, "Client ID not found in response");
              }
            } else if(http_code==400 && error!=NULL) {
              if (strcmp(error,"authorization_pending")==0 || strcmp(error,"slow_down")==0){
                if(strcmp(error,"slow_down")==0)*interval = ((*(unsigned int*)interval)+5);
                log_message(LOG_DEBUG, pamh, "Retrying after waiting for %d seconds", *interval);
                sleep(*((unsigned int*)interval));
                free(error);
                free(error_description);
                free(client_id);
                continue;
              } if(strcmp(error,"expired_token")==0 || strcmp(error,"access_denied")==0){
                if (params.debug) log_message(LOG_ERR, pamh, "Access denied or expired token");
              } else if (strcmp(error,"invalid_request")==0 || strcmp(error,"invalid_client")==0 || strcmp(error,"invalid_grant")==0) {
                if (params.debug) log_message(LOG_ERR, pamh, "Unknown error in the backend: %s", error);
              }
            } else {
              if (params.debug) log_message(LOG_ERR, pamh, "Unexpected HTTP code: %ld", http_code);
                sleep(*((unsigned int*)interval));
                free(error);
                free(error_description);
                free(client_id);
                continue;
            }
          } else {
            if (params.debug) log_message(LOG_ERR, pamh, "Error occurred while requesting access token");
            sleep(*((unsigned int*)interval));
          }
          free(error);
          free(error_description);
          free(client_id);
          if(token_req_output){
            free(token_req_output);
          }
          break;
        } else {
          log_message(LOG_ERR, pamh, "Device code expired");
          rc = PAM_AUTH_ERR;
          break;
        }
      }
  }


	// If the user has not created a state file with a shared secret, and if
	// the administrator set the "nullok" option, this PAM module completes
	// without saying success or failure, without ever prompting the user.
	// It's not a failure since "nullok" was specified, and it's not a success
	// because it must be distinguishable from "good credentials given" in
	// case the PAM config considers this module "sufficient".
	// (or more complex equivalents)
	if (params.nullok == SECRETNOTFOUND) {
	rc = PAM_IGNORE;
	}

	// Persist the new state.
	if (early_updated || updated) {
	int err;
	if ((err = write_file_contents(pamh, &params, secret_filename, &orig_stat, buf))) {
		// Inform user of error if the error is clearly a system error
		// and not an auth error.
		char s[1024];
		switch (err) {
		case EPERM:
		case ENOSPC:
		case EROFS:
		case EIO:
		case EDQUOT:
		snprintf(s, sizeof(s), "Error \"%s\" while writing config", strerror(err));
		conv_error(pamh, s);
		}

		// If allow_readonly parameter is defined than ignore write errors and
		// allow user to login.

		// Could not persist new state. Deny access.
		rc = PAM_AUTH_ERR;
	}
	}

	out:
	if (params.debug) {
		log_message(LOG_INFO, pamh,
					"debug: end of pamshi for \"%s\". Result: %s",
					username, pam_strerror(pamh, rc));
	}
	if (fd >= 0) {
		close(fd);
	}
	if (old_gid >= 0) {
		if (setgroup(old_gid) >= 0 && setgroup(old_gid) == old_gid) {
		old_gid = -1;
		}
	}
	if (old_uid >= 0) {
		if (setuser(old_uid) < 0 || setuser(old_uid) != old_uid) {
		log_message(LOG_EMERG, pamh, "We switched users from %d to %d, "
					"but can't switch back", old_uid, uid);
		}
	}
	free(secret_filename);

	// Clean up
	if (buf) {
		explicit_bzero(buf, strlen(buf));
		free(buf);
	}
	if (secret) {
		explicit_bzero(secret, secretLen);
		free(secret);
	}
	return rc;
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
