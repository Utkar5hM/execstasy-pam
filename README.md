# pamshi - Linux PAM Module for Device Authorization Framework (RFC 8628)

> Built to be used with [delulufam - An IAM for Linux Instances](https://github.com/Utkar5hM/delulufam).
>
> NOTE: It's a repurposed project for now and so the name, it will be changed later someday.

![screenshot](image.png)

Project Status: `WIP` (mvp)

## Usage Instruction

### Dependencies
Figure it out for now. As far as I remember, libcurl is required.

### Build
```sh
make install
```

### test
```sh
# test using pamtester with sshd service
make test
# or below command to test with pamtester service
make test TEST_SERVICE=pamtester
```

### cleanup
```sh
make clean
```


------------


This project is heavily inspired (`blatantly copied`) from [google-authenticator-libpam)](https://github.com/google/google-authenticator-libpam).