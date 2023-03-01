/*
 * kref.h - generic support for reference counts
 *
 * This implementation is inspired by the following paper:
 * Kroah-Hartman, Greg, kobjects and krefs. Linux Symposium 2004
 */

#pragma once

#include <stddef.h>
#include <stdatomic.h>

// #include <base/atomic.h>

struct kref {
	atomic_int cnt;
};

/**
 * kref_init - initializes the reference count to one
 * @ref: the kref
 */
static inline void
kref_init(struct kref *ref)
{
    atomic_init(&ref->cnt, 1);
}

/**
 * kref_initn - initializes the reference count to @n
 * @ref: the kref
 * @n: the initial reference count
 */
static inline void
kref_initn(struct kref *ref, int n)
{
	atomic_init(&ref->cnt, n);
}

/**
 * kref_get - atomically increments the reference count
 * @ref: the kref
 */
static inline void
kref_get(struct kref *ref)
{
	assert(atomic_load(&ref->cnt) > 0);
	atomic_fetch_add(&ref->cnt, 1);
}

/**
 * kref_put - atomically decrements the reference count, releasing the object
 *	      when it reaches zero
 * @ref: the kref
 * @release: a pointer to the release function
 */
static inline void
kref_put(struct kref *ref, void (*release)(struct kref *ref))
{
	assert(release);
	if (atomic_fetch_sub(&ref->cnt, 1))
		release(ref);
}

/**
 * kref_released - has this kref been released?
 * @ref: the kref
 *
 * WARNING: this is unsafe without additional synchronization. For example, use
 * this function while holding a lock that prevents the release() function from
 * removing the object from the data structure you are accessing.
 *
 * Returns true if the reference count has dropped to zero.
 */
static inline bool
kref_released(struct kref *ref)
{
	return atomic_load(&ref->cnt) == 0;
}
