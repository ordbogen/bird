#ifndef HMAC_H
#define HMAC_H

void hmac_md5(const unsigned char *text, int text_len, const unsigned char *key, int key_len, unsigned char digest[16]);

#endif /* HMAC_H */
