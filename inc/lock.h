/*
 * lock.h - locking primitives
 */

#pragma once

#include <stddef.h>
#include <assert.h>


typedef struct {
	volatile int locked;
} spinlock_t;

typedef struct {
	volatile int cnt;
} atomic_t;

typedef struct {
	volatile long cnt;
} atomic64_t;

#define SPINLOCK_INITIALIZER {.locked = 0}
#define DEFINE_SPINLOCK(name) spinlock_t name = SPINLOCK_INITIALIZER
#define DECLARE_SPINLOCK(name) extern spinlock_t name

static inline void cpu_relax(void)
{
	asm volatile("pause");
}
