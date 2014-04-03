/*
 *  BIRD Library -- Object ID lists
 *
 *  (c) 2014 Peter Christensen <pch@ordbogen.com>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/oidlist.h"

typedef struct _oidentry oidentry;

struct _oidentry
{
  oidentry *next;
  void *value;
  unsigned int oidlen;
  u32 oid[0];
};

struct _oidlist
{
  oidentry *head;
  pool *pool;
};

struct _oiditer
{
  oidlist *list;
  oidentry *entry;
  oidentry *prev;
};

oidlist *oidlist_new(pool *pool)
{
  oidlist *list = (oidlist *)mb_alloc(pool, sizeof(*list));
  list->head = NULL;
  list->pool = pool;
  return list;
}

static int oidentry_cmp(const u32 *a_oid, unsigned int a_size, const u32 *b_oid, unsigned int b_size)
{
  while (a_size != 0 && b_size != 0)
  {
    if (*a_oid < *b_oid)
      return -1;
    else if (*a_oid > *b_oid)
      return 1;
  }
  if (a_size == 0 && b_size == 0)
	return 0;
  else if (a_size == 0)
	return -1;
  else /* if (b_size == 0) */
	return 1;
}

void *oidlist_get(const oidlist *list, const u32 *oid, unsigned int oidlen)
{
  const oidentry *entry;
  for (entry = list->head; entry != NULL; entry = entry->next)
  {
    int res = oidentry_cmp(oid, oidlen, entry->oid, entry->oidlen);
    if (res == 0)
      return entry->value;
    else if (res < 0)
      break;
  }
  return 0;
}

void oidlist_set(oidlist *list, const u32 *oid, unsigned int oidlen, void *value)
{
  oidentry *entry;
  oidentry *prev = NULL;
  for (entry = list->head; entry != NULL; prev = entry, entry = entry->next)
  {
    int res = oidentry_cmp(oid, oidlen, entry->oid, entry->oidlen);
    if (res == 0)
    {
      entry->value = value;
      return;
    }
    else if (res > 0)
      break;
  }

  entry = (oidentry *)mb_alloc(list->pool, sizeof(*entry) + oidlen * sizeof(*oid));
  entry->value = value;
  entry->oidlen = oidlen;
  memcpy(entry->oid, oid, oidlen * sizeof(*oid));

  if (prev == NULL)
  {
    entry->next = list->head;
    list->head = entry;
  }
  else
  {
    entry->next = prev->next;
    prev->next = entry;
  }
}

void oidlist_unset(oidlist *list, const u32 *oid, unsigned int oidlen)
{
  oidentry *entry;
  oidentry *prev = NULL;
  for (entry = list->head; entry != NULL; prev = entry, entry = entry->next)
  {
    int res = oidentry_cmp(oid, oidlen, entry->oid, entry->oidlen);
    if (res == 0)
    {
      if (prev)
	list->head = entry->next;
      else
	prev->next = entry->next;
      mb_free(entry);
      break;
    }
    else if (res > 0)
      break;
  }
}


oiditer *oidlist_find(oidlist *list, const u32 *oid, unsigned int oidlen)
{
  oidentry *entry;
  oidentry *prev = NULL;
  for (entry = list->head; entry != NULL; prev = entry, entry = entry->next)
  {
    int res = oidentry_cmp(oid, oidlen, entry->oid, entry->oidlen);
    if (res == 0)
    {
      oiditer *iter = (oiditer *)mb_alloc(list->pool, sizeof(*iter));
      iter->list = list;
      iter->entry = entry;
      iter->prev = prev;
      return iter;
    }
    else if (res > 0)
      return 0;
  }
  return 0;
}

void oidlist_free(oidlist *list)
{
  oidentry *entry;
  oidentry *next;
  for (entry = list->head; entry != NULL; entry = next)
  {
    next = entry->next;
    mb_free(next);
  }
  mb_free(list);
}

const u32 *oiditer_oid(const oiditer *iter, unsigned int *oidlen)
{
  if (iter == NULL || iter->entry == NULL)
  {
    if (oidlen)
      *oidlen = 0;
    return 0;
  }
  else
  {
    if (oidlen)
      *oidlen = iter->entry->oidlen;
    return iter->entry->oid;
  }
}

void *oiditer_value(const oiditer *iter)
{
  if (iter == NULL || iter->entry == NULL)
    return NULL;
  else
    return iter->entry->value;
}

int oiditer_next(oiditer *iter)
{
  if (iter == NULL || iter->entry == NULL)
    return 0;

  iter->prev = iter->entry;
  iter->entry = iter->entry->next;

  return iter->entry != NULL;
}

void oiditer_unset(oiditer *iter)
{
  if (iter != NULL && iter->entry != NULL)
  {
    oidentry *entry = iter->entry;

    if (iter->prev == NULL)
      iter->list->head = iter->entry->next;
    else
      iter->prev->next = iter->entry->next;
    iter->entry = iter->entry->next;

    mb_free(entry);
  }
}


void oiditer_free(oiditer *iter)
{
  if (iter != NULL)
    mb_free(iter);
}
