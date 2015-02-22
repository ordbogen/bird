#include "snmp.h"

#include "lib/md5.h"

#include <stdio.h>

void snmp_encode_password(struct snmp_params *params)
{
  struct MD5Context ctx;
  int len = 0;
  int pwd_len = strlen(params->password);
  unsigned char digest[16];

  MD5Init(&ctx);
  while (len != 1048576) {
    int chunkSize = pwd_len;
    if (len + chunkSize > 1048576)
      chunkSize = 1048576 - len;

    MD5Update(&ctx, params->password, chunkSize);

    len += chunkSize;
  }
  MD5Final(digest, &ctx);

  MD5Init(&ctx);
  MD5Update(&ctx, digest, 16);
  MD5Update(&ctx, params->auth_engine_id, 12);
  MD5Update(&ctx, digest, 16);
  MD5Final(params->key, &ctx);

  params->key_length = 16;
}

int snmp_parse_hex(const char *string, int max_size, u8 *buffer)
{
  int i;
  for (i = 0; i != max_size && *string != 0; ++i, string += 2) {
    unsigned int val;
    if (sscanf(string, "%02x", &val) == 1)
      *buffer++ = val;
    else
      return 0;
  }

  if (i == max_size && *string != 0)
    return 0;
  else
    return i;
}
