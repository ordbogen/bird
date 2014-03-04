/*
 *  BIRD Library -- Object ID lists
 *
 *  (c) 2014 Peter Christensen <pch@ordbogen.com>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_OIDLIST_H_
#define _BIRD_OIDLIST_H_

typedef struct _oidlist oidlist;
typedef struct _oiditer oiditer;
typedef u32 oid;

oidlist *oidlist_new(pool *pool);
void *oidlist_get(const oidlist *list, const oid *oid, unsigned int oidlen);
void oidlist_set(oidlist *list, const oid *oid, unsigned int oidlen, void *value);
void oidlist_unset(oidlist *list, const oid *oid, unsigned int oidlen);

oiditer *oidlist_find(oidlist *list, const oid *oid, unsigned int oidlen);
void oidlist_free(oidlist *list);

const oid *oiditer_oid(const oiditer *iter, unsigned int *oidlen);
void *oiditer_value(const oiditer *iter);
int oiditer_next(oiditer *iter);
void oiditer_unset(oiditer *iter);
void oiditer_free(oiditer *iter);

#endif // _BIRD_OIDLIST_H_
