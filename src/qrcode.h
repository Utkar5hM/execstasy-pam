#ifndef _QRCODE_H_
#define _QRCODE_H_

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum QRMode { QR_ANSI, QR_UTF8 };

int displayQRCode(const char* url, enum QRMode mode, char **buf);

#endif