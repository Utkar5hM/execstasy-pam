# Execstasy - Linux PAM Module for OAuth 2.0 Device Authorization Grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628))

> Built to be used with [Execstacy - An IAM for Linux Instances](https://github.com/Utkar5hM/Execstasy).
>
> NOTE: It's currently a private repository. :D

![screenshot](image.png)

Project Status: `WIP` (mvp)

## Usage Instruction

### Dependencies

Figure it out for now. As far as I remember, libcurl is required.

### Build & Install

The below command will install the PAM into the PAM installation directory `/lib64/security/`:

```sh
make install
```

You need to add the following line to your application's respective PAM configuration file:

```sh
# for sshd ( /etc/pam.d/sshd )
# for pamtester ( /etc/pam.d/pamtester )

auth sufficient execstasy.so debug user=root auth_server_url=http://localhost:4000
```

> In `user=username`, the username specifies the user with which the secrets file containing encoded clientId will be opened. The file needs to have `0600` perm and owned by that user. 
>
> The secret (client-id obtained from the Execstasy site) is by default read from `/etc/execstasy/.config`, is base32 encoded without the `=`. 
>
> debug parameter is not necessary

### test

```sh
# test using pamtester with sshd service
make test
# or below command to test with pamtester service
make test TEST_SERVICE=pamtester
```

### cleanup
Run a cleanup before `make install` everytime to make sure it does build everytime.

```sh
make clean
```

### debugging
replace `service` with the service you will be using the PAM module with.
```sh
journalctl -f SYSLOG_IDENTIFIER="service(execstasy_auth)"
# ex- for sshd
journalctl -f SYSLOG_IDENTIFIER="sshd(execstasy_auth)"
```

### Configuring sshd

Make sure you have the following set in sshd's config (`/etc/ssh/sshd_config`). change as required but make sure to also check files in `/etc/ssh/sshd_config.d/` directory for conflicting configuration.
 
```
UsePAM yes
ChallengeResponseAuthentication yes
PasswordAuthentication yes
PubkeyAuthentication yes
KbdInteractiveAuthentication yes
PermitTTY yes

```
------------


This project is heavily inspired from [google-authenticator-libpam)](https://github.com/google/google-authenticator-libpam). Hence, it can be used as an example on how to configure this PAM Module.