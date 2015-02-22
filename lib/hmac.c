#include "nest/bird.h"
#include "lib/md5.h"

#include <string.h>

void hmac_md5(const unsigned char *text, int text_len, const unsigned char *key, int key_len, unsigned char digest[16])
{
  struct MD5Context ctx;
  unsigned char k_ipad[64];
  unsigned char k_opad[64];
  unsigned char tk[16];
  int i;

  if (key_len > 64) {
    MD5Init(&ctx);
    MD5Update(&ctx, key, key_len);
    MD5Final(tk, &ctx);

    key = tk;
    key_len = 16;
  }

  memset(k_ipad, 0x36, sizeof(k_ipad));
  memset(k_opad, 0x5c, sizeof(k_opad));

  for (i = 0; i != key_len; ++i) {
    k_ipad[i] = key[i] ^ 0x36;
    k_opad[i] = key[i] ^ 0x5c;
  }

  MD5Init(&ctx);
  MD5Update(&ctx, k_ipad, 64);
  MD5Update(&ctx, text, text_len);
  MD5Final(digest, &ctx);

  MD5Init(&ctx);
  MD5Update(&ctx, k_opad, 64);
  MD5Update(&ctx, digest, 16);

  MD5Final(digest, &ctx);
}
