#include "aes-ctr.h"
#include <string.h>

#define AES_BLOCKLEN 16

void aes_ctr_xcrypt_buffer(aes_context *ctx, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out)
{
	uint8_t bi, buffer[AES_BLOCKLEN], ivc[AES_BLOCKLEN];
	size_t i;

	memcpy(ivc,iv,AES_BLOCKLEN);

	for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
	{
		if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
		{
			memcpy(buffer, ivc, AES_BLOCKLEN);
			aes_cipher(ctx, buffer, buffer);

			/* Increment ivc and handle overflow */
			for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
			{
				/* inc will owerflow */
				if (ivc[bi] == 255)
				{
					ivc[bi] = 0;
					continue;
				}
				ivc[bi] += 1;
				break;
			}
			bi = 0;
		}
		out[i] = in[i] ^ buffer[bi];
	}
}

int aes_ctr_crypt(const uint8_t *key, const size_t key_len, const uint8_t *iv, const uint8_t *in, size_t length, uint8_t *out)
{
	int ret=0;
	aes_context ctx;

	aes_init_keygen_tables();

	if (!(ret=aes_setkey(&ctx, AES_ENCRYPT, key, key_len)))
		aes_ctr_xcrypt_buffer(&ctx, iv, in, length, out);

	return ret;
}
