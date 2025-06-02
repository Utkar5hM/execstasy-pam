#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qrcode.h"

#define ANSI_RESET        "\x1B[0m"
#define ANSI_BLACKONGREY  "\x1B[30;47;27m"
#define ANSI_WHITE        "\x1B[27m"
#define ANSI_BLACK        "\x1B[7m"
#define UTF8_BOTH         "\xE2\x96\x88"
#define UTF8_TOPHALF      "\xE2\x96\x80"
#define UTF8_BOTTOMHALF   "\xE2\x96\x84"

// Display QR code visually. If not possible, return 0.
int displayQRCode(const char* url, enum QRMode mode, char **buf) {
    void *qrencode = dlopen("libqrencode.so.2", RTLD_NOW | RTLD_LOCAL);
    if (!qrencode) {
    qrencode = dlopen("libqrencode.so.3", RTLD_NOW | RTLD_LOCAL);
    }
    if (!qrencode) {
    qrencode = dlopen("libqrencode.so.4", RTLD_NOW | RTLD_LOCAL);
    }
    if (!qrencode) {
    qrencode = dlopen("libqrencode.3.dylib", RTLD_NOW | RTLD_LOCAL);
    }
    if (!qrencode) {
    qrencode = dlopen("libqrencode.4.dylib", RTLD_NOW | RTLD_LOCAL);
    }
    if (!qrencode) {
    return 0;
    }
    typedef struct {
    int version;
    int width;
    unsigned char *data;
    } QRcode;
    QRcode *(*QRcode_encodeString8bit)(const char *, int, int) =
        (QRcode *(*)(const char *, int, int))
        dlsym(qrencode, "QRcode_encodeString8bit");
    void (*QRcode_free)(QRcode *qrcode) =
        (void (*)(QRcode *))dlsym(qrencode, "QRcode_free");
    if (!QRcode_encodeString8bit || !QRcode_free) {
    dlclose(qrencode);
    return 0;
    }
    QRcode *qrcode = QRcode_encodeString8bit(url, 0, 1);
    //   int buf_length = (qrcode->width + 4) * (qrcode->width + 4) * 4;
    int w = qrcode->width;
    size_t border_size = strlen(ANSI_BLACKONGREY) + (w + 4) + strlen(ANSI_RESET) + 1; // One border line
    size_t row_size = strlen(ANSI_BLACKONGREY) + 2 + (w * (strlen(ANSI_BLACK) + 2)) + 2 + strlen(ANSI_RESET) + 1; // One QR row
    size_t buf_length = 2 * border_size + (w * row_size); // Top + Bottom borders + QR rows

    *buf = (char *)malloc(buf_length);
    if (!*buf) {
    QRcode_free(qrcode);
    dlclose(qrencode);
    return 0;
    }
    const char *ptr = (char *)qrcode->data;
    // Output QRCode using ANSI colors. Instead of black on white, we
    // output black on grey, as that works independently of whether the
    // user runs their terminal in a black on white or white on black color
    // scheme.
    // But this requires that we print a border around the entire QR Code.
    // Otherwise readers won't be able to recognize it.
    size_t offset = 0;
    if (mode != QR_UTF8) {
    for (int i = 0; i < 1; ++i) {
        offset += snprintf(*buf + offset, buf_length - offset, ANSI_BLACKONGREY);
        for (int x = 0; x < (qrcode->width + 4); ++x) printf(" ");
        offset += snprintf(*buf + offset, buf_length - offset, ANSI_RESET"\n");
    }
    for (int y = 0; y < qrcode->width; ++y) {
        offset += snprintf(*buf + offset, buf_length - offset, ANSI_BLACKONGREY"  ");
        int isBlack = 0;
        for (int x = 0; x < qrcode->width; ++x) {
        if (*ptr++ & 1) {
            if (!isBlack) {
            offset += snprintf(*buf + offset, buf_length - offset, ANSI_BLACK);
            }
            isBlack = 1;
        } else {
            if (isBlack) {
            offset += snprintf(*buf + offset, buf_length - offset, ANSI_WHITE);
            }
            isBlack = 0;
        }
        offset += snprintf(*buf + offset, buf_length - offset, "  ");
        }
        if (isBlack) {
        printf(ANSI_WHITE);
        }
        offset += snprintf(*buf + offset, buf_length - offset, "  "ANSI_RESET"\n");
    }
    for (int i = 0; i < 1; ++i) {
        offset += snprintf(*buf + offset, buf_length - offset, ANSI_BLACKONGREY);
        for (int x = 0; x < qrcode->width + 4; ++x) printf(" ");
        offset += snprintf(*buf + offset, buf_length - offset, ANSI_RESET);
    }
    } else {
    // Drawing the QRCode with Unicode block elements is desirable as
    // it makes the code much smaller, which is often easier to scan.
    // Unfortunately, many terminal emulators do not display these
    // Unicode characters properly.
    offset += snprintf(*buf + offset, buf_length - offset, ANSI_BLACKONGREY);
    for (int i = 0; i < qrcode->width + 4; ++i) {
        offset += snprintf(*buf + offset, buf_length - offset, " ");
    }
    offset += snprintf(*buf + offset, buf_length - offset, ANSI_RESET"\n");
    for (int y = 0; y < qrcode->width; y += 2) {
        offset += snprintf(*buf + offset, buf_length - offset, ANSI_BLACKONGREY"  ");
        for (int x = 0; x < qrcode->width; ++x) {
        const int top = qrcode->data[y*qrcode->width + x] & 1;
        int bottom = 0;
        if (y+1 < qrcode->width) {
            bottom = qrcode->data[(y+1)*qrcode->width + x] & 1;
        }
        if (top) {
            if (bottom) {
            offset += snprintf(*buf + offset, buf_length - offset, UTF8_BOTH);
            } else {
            offset += snprintf(*buf + offset, buf_length - offset, UTF8_TOPHALF);
            }
        } else {
            if (bottom) {
            offset += snprintf(*buf + offset, buf_length - offset, UTF8_BOTTOMHALF);
            } else {
            offset += snprintf(*buf + offset, buf_length - offset, " ");
            }
        }
        }
        offset += snprintf(*buf + offset, buf_length - offset, "  "ANSI_RESET"\n");
    }
    offset += snprintf(*buf + offset, buf_length - offset, ANSI_BLACKONGREY);
    for (int i = 0; i < qrcode->width + 4; ++i) {
        offset += snprintf(*buf + offset, buf_length - offset, " ");
    }
    offset += snprintf(*buf + offset, buf_length - offset, ANSI_RESET);
    }
    offset += snprintf(*buf + offset, buf_length - offset, "\n\000");
    QRcode_free(qrcode);
    dlclose(qrencode);
    return 1;
}

