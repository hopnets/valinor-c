/*
 * chksum.h - utilities for calculating checksums
 */

#pragma once

#include <stdint.h>

/**
 * chksum_internet - performs an internet checksum on a buffer
 * @buf: the buffer
 * @len: the length in bytes
 *
 * An internet checksum is a 16-bit one's complement sum. Details
 * are described in RFC 1071.
 *
 * Returns a 16-bit checksum value.
 */
static inline uint16_t chksum_internet(const void *buf, int len)
{
        uint64_t sum;

        asm volatile("xorq %0, %0\n"

                     /* process 8 byte chunks */
                     "movl %2, %%edx\n"
                     "shrl $3, %%edx\n"
                     "cmp $0, %%edx\n"
                     "jz 2f\n"
                     "1: adcq (%1), %0\n"
                     "leaq 8(%1), %1\n"
                     "decl %%edx\n"
                     "jne 1b\n"
                     "adcq $0, %0\n"

                     /* process 4 byte (if left) */
                     "2: test $4, %2\n"
                     "je 3f\n"
                     "movl (%1), %%edx\n"
                     "addq %%rdx, %0\n"
                     "adcq $0, %0\n"
                     "leaq 4(%1), %1\n"

                     /* process 2 byte (if left) */
                     "3: test $2, %2\n"
                     "je 4f\n"
                     "movzxw (%1), %%rdx\n"
                     "addq %%rdx, %0\n"
                     "adcq $0, %0\n"
                     "leaq 2(%1), %1\n"

                     /* process 1 byte (if left) */
                     "4: test $1, %2\n"
                     "je 5f\n"
                     "movzxb (%1), %%rdx\n"
                     "addq %%rdx, %0\n"
                     "adcq $0, %0\n"

                     /* fold into 16-bit answer */
                     "5: movq %0, %1\n"
                     "shrq $32, %0\n"
                     "addl %k1, %k0\n"
                     "adcl $0, %k0\n"
                     "movq %0, %1\n"
                     "shrl $16, %k0\n"
                     "addw %w1, %w0\n"
                     "adcw $0, %w0\n"
                     "not %0\n"

                     : "=&r"(sum), "=r"(buf)
                     : "r"(len), "1"(buf)
                     : "%rdx", "cc", "memory");

        return (uint16_t)sum;
}

static uint16_t
ipv4_hdr_cksum(void *ip_h)
{
        uint16_t *v16_h;
        uint32_t ip_cksum;

        /*
                * Compute the sum of successive 16-bit words of the IPv4 header,
                * skipping the checksum field of the header.
                */
        v16_h = (uint16_t *)ip_h;
        ip_cksum = v16_h[0] + v16_h[1] + v16_h[2] + v16_h[3] +
                        v16_h[4] + v16_h[6] + v16_h[7] + v16_h[8] + v16_h[9];

        /* reduce 32 bit checksum to 16 bits and complement it */
        ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
        ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
        ip_cksum = (~ip_cksum) & 0x0000FFFF;
        return (ip_cksum == 0) ? 0xFFFF : (uint16_t)ip_cksum;
}

/**
 * @internal Calculate a sum of all words in the buffer.
 * Helper routine for the rte_raw_cksum().
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @param sum
 *   Initial value of the sum.
 * @return
 *   sum += Sum of all words in the buffer.
 */
static inline uint32_t
__raw_cksum(const void *buf, size_t len, uint32_t sum)
{
        /* workaround gcc strict-aliasing warning */
        uintptr_t ptr = (uintptr_t)buf;
        typedef uint16_t __attribute__((__may_alias__)) u16_p;
        const u16_p *u16 = (const u16_p *)ptr;

        while (len >= (sizeof(*u16) * 4))
        {
                sum += u16[0];
                sum += u16[1];
                sum += u16[2];
                sum += u16[3];
                len -= sizeof(*u16) * 4;
                u16 += 4;
        }
        while (len >= sizeof(*u16))
        {
                sum += *u16;
                len -= sizeof(*u16);
                u16 += 1;
        }

        /* if length is in odd bytes */
        if (len == 1)
                sum += *((const uint8_t *)u16);

        return sum;
}

/**
 * @internal Reduce a sum to the non-complemented checksum.
 * Helper routine for the rte_raw_cksum().
 *
 * @param sum
 *   Value of the sum.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
__raw_cksum_reduce(uint32_t sum)
{
        sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
        sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
        return (uint16_t)sum;
}

/**
 * Process the non-complemented checksum of a buffer.
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @return
 *   The non-complemented checksum.
 */
static inline uint16_t
raw_cksum(const void *buf, size_t len)
{
        uint32_t sum;

        sum = __raw_cksum(buf, len, 0);
        return __raw_cksum_reduce(sum);
}