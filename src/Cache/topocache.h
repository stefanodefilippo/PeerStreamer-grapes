#ifndef TOPOCACHE
#define TOPOCACHE

#include <stdbool.h>

#define MAX_SESSION_IDS 10

struct peer_cache;
struct cache_entry;
struct id_entry;
typedef int (*ranking_function)(const void *target, const void *p1, const void *p2);    // FIXME!

struct peer_cache *cache_init(int n, int metadata_size, int max_timestamp);
struct peer_cache *cache_copy(const struct peer_cache *c);
void cache_free(struct peer_cache *c);
void cache_update(struct peer_cache *c);
void cache_delay(struct peer_cache *c, int dts);
struct nodeID *nodeid(const struct peer_cache *c, int i);
const void *get_metadata(const struct peer_cache *c, int *size);
int cache_metadata_update(struct peer_cache *c, const struct nodeID *p, const void *meta, int meta_size);
int cache_add_ranked(struct peer_cache *c, struct nodeID *neighbour, const void *meta, int meta_size, ranking_function f, const void *tmeta);
int cache_add(struct peer_cache *c, struct nodeID *neighbour, const void *meta, int meta_size);
int cache_del(struct peer_cache *c, const struct nodeID *neighbour);

int cache_entries(const struct peer_cache *c);
int cache_pos(const struct peer_cache *c, const struct nodeID *neighbour);
struct nodeID *rand_peer(const struct peer_cache *c, void **meta, int max);
struct nodeID *last_peer(const struct peer_cache *c);
struct peer_cache *rand_cache(struct peer_cache *c, int n);
struct peer_cache *rand_cache_except(struct peer_cache *c, int n, struct nodeID *except[], int len);
void cache_randomize(const struct peer_cache *c);

struct peer_cache *entries_undump(const uint8_t *buff, int size);
struct peer_cache *entries_undump_session_id(const uint8_t *buff, int size, int num_flows);
int update_random_session_id_set(struct peer_cache *c);
char * get_session_id(int index, const struct peer_cache *c);
char * get_session_id_request(int index, const struct peer_cache *c);
bool topo_update_session_id_set(struct peer_cache *dst, struct peer_cache *src);
void topo_add_session_id(struct peer_cache *c, struct id_entry session_id);
int cache_header_dump(uint8_t *b, const struct peer_cache *c, int include_me);
int entry_dump(uint8_t *b, const struct peer_cache *e, int i, size_t max_write_size);

struct peer_cache *merge_caches(const struct peer_cache *c1, const struct peer_cache *c2, int newsize, int *source);
struct peer_cache *cache_rank (const struct peer_cache *c, ranking_function rank, const struct nodeID *target, const void *target_meta);
struct peer_cache *cache_union(const struct peer_cache *c1, const struct peer_cache *c2, int *size);
int cache_resize (struct peer_cache *c, int size);

int cache_max_size(const struct peer_cache *c);
int cache_current_size(const struct peer_cache *c);

int cache_fill_rand(struct peer_cache *dst, const struct peer_cache *src, int target_size);
int cache_fill_ordered(struct peer_cache *dst, const struct peer_cache *src, int target_size);

void cache_check(const struct peer_cache *c);

void cache_log(const struct peer_cache *c, const char *name);

int cache_add_cache(struct peer_cache *dst, const struct peer_cache *src);

#endif  /* TOPOCACHE */
