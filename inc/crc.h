#ifndef CRC_H
#define CRC_H

#include "valinor.h"

static inline uint64_t __mm_crc32_u64(uint64_t crc, uint64_t val)
{
	asm("crc32q %1, %0" : "+r" (crc) : "rm" (val));
	return crc;
}

static inline uint32_t hash_crc32c_two(uint32_t seed, uint64_t a, uint64_t b)
{
	seed = __mm_crc32_u64(seed, a);
	return __mm_crc32_u64(seed, b);
}

static inline uint32_t hash_crc32c_one(uint32_t seed, uint64_t val)
{
	return __mm_crc32_u64(seed, val);
}

static inline uint32_t trans_hash_3tuple(uint8_t proto, struct netaddr laddr)
{
	return hash_crc32c_one(trans_seed,
		(uint64_t)laddr.ip | ((uint64_t)laddr.port << 32) |
		((uint64_t)proto << 48));
}

static inline uint32_t trans_hash_5tuple(uint8_t proto, struct netaddr laddr,
				         struct netaddr raddr)
{
	return hash_crc32c_two(trans_seed,
		(uint64_t)laddr.ip | ((uint64_t)laddr.port << 32),
		(uint64_t)raddr.ip | ((uint64_t)raddr.port << 32) |
		((uint64_t)proto << 48));
}

static inline uint32_t marker_packet_hash(char *buff, unsigned int len)
{
	uint64_t chunk;
	uint32_t seed = trans_seed;
	int i, n = len >> 3;
	n = n > 8 ? 8 : n;
	for(i = 0;i < n; i++)
	{
		chunk = (uint64_t) buff[8*i];
		seed = __mm_crc32_u64(seed, chunk);
	}
	log_debug("Packet hash=%u, n=%d", seed, n);
	return seed;
}

/**
 * rand_crc32c - generates a very fast pseudorandom value using crc32c
 * @seed: a seed-value for the hash
 *
 * WARNING: not a cryptographic hash.
 */
static inline uint64_t rand_crc32c(uint32_t seed)
{
	return hash_crc32c_one(seed, rdtsc());
}

#endif