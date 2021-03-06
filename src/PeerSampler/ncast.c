/*
 *  Copyright (c) 2010 Luca Abeni
 *
 *  This is free software; see lgpl-2.1.txt
 */

#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include "net_helper.h"
#include "peersampler_iface.h"
#include "../Cache/topocache.h"
#include "../Cache/ncast_proto.h"
#include "../Cache/proto.h"
#include "grapes_config.h"
#include "grapes_msg_types.h"

#define DEFAULT_CACHE_SIZE 10
#define DEFAULT_MAX_TIMESTAMP 5
#define DEFAULT_BOOTSTRAP_CYCLES 5
#define DEFAULT_BOOTSTRAP_PERIOD 2*1000*1000
#define DEFAULT_PERIOD 10*1000*1000
#define SESSION_ID_SIZE 32
#define SEND_IN_ALL_QUERY 1
#define SEND_AFTER_LOCAL_CHANGE 2
#define SEND_AFTER_QUERY_SUCCESS 3
#define SEND_AFTER_QUERY_FAILURE 4

struct peersampler_context{
  uint64_t currtime;
  int cache_size;
  int cache_size_threshold;
  struct peer_cache *local_cache;
  bool bootstrap;
  struct nodeID *bootstrap_node;
  int bootstrap_period;
  int bootstrap_cycles;
  int period;
  int counter;
  struct ncast_proto_context *tc;
  const struct nodeID **r;
  int query_tokens;
  int reply_tokens;
  int first_ts;
  int adaptive;
  int restart;
  int randomize;
  int slowstart;
  int SDP_policy;
};

static uint64_t gettime(void)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return tv.tv_usec + tv.tv_sec * 1000000ull;
}

static struct peersampler_context* ncast_context_init(void)
{
  struct peersampler_context* con;
  con = (struct peersampler_context*) calloc(1,sizeof(struct peersampler_context));

  //Initialize context with default values
  con->bootstrap = true;
  con->bootstrap_node = NULL;
  con->currtime = gettime();
  con->r = NULL;

  return con;
}

static int ncast_update_random_session_id_set(struct peersampler_context *context){
    return ncast_proto_update_random_session_id_set(context->tc);
}

static void ncast_add_session_id(struct peersampler_context *context, char * session_id)
{
    return ncast_proto_add_session_id(context->tc, session_id);
}

static void ncast_set_distributed(struct peersampler_context *context, char * session_id, bool value)
{
    return ncast_proto_set_distributed(context->tc, session_id, value);
}

static int time_to_send(struct peersampler_context *context)
{
  int p = context->bootstrap ? context->bootstrap_period : context->period;
  if (gettime() - context->currtime > p) {
    context->currtime += p;

    return 1;
  }

  return 0;
}

static void cache_size_threshold_init(struct peersampler_context* context)
{
  context->cache_size_threshold = (context->cache_size - 1 / 2);
}

/*
 * Exported Functions!
 */
static struct peersampler_context* init(struct nodeID *myID, const void *metadata, int metadata_size, const char *config, int plus_features)
{
  struct tag *cfg_tags;
  struct peersampler_context *context;
  int max_timestamp;

  context = ncast_context_init();
  if (!context) return NULL;

  cfg_tags = grapes_config_parse(config);
  grapes_config_value_int_default(cfg_tags, "cache_size", &context->cache_size, DEFAULT_CACHE_SIZE);
  grapes_config_value_int_default(cfg_tags, "max_timestamp", &max_timestamp, DEFAULT_MAX_TIMESTAMP);
  grapes_config_value_int_default(cfg_tags, "period", &context->period, DEFAULT_PERIOD);
  grapes_config_value_int_default(cfg_tags, "bootstrap_period", &context->bootstrap_period, DEFAULT_BOOTSTRAP_PERIOD);
  grapes_config_value_int_default(cfg_tags, "bootstrap_cycles", &context->bootstrap_cycles, DEFAULT_BOOTSTRAP_CYCLES);
  grapes_config_value_int_default(cfg_tags, "adaptive", &context->adaptive, plus_features);
  grapes_config_value_int_default(cfg_tags, "restart", &context->restart, plus_features);
  grapes_config_value_int_default(cfg_tags, "randomize", &context->randomize, plus_features);
  grapes_config_value_int_default(cfg_tags, "slowstart", &context->slowstart, plus_features);
  grapes_config_value_int_default(cfg_tags, "SDP_policy", &context->SDP_policy, SEND_IN_ALL_QUERY);
  free(cfg_tags);

  fprintf(stderr, "peersampler_context* init: LA SDP POLICY è: %d\n", context->SDP_policy);
  
  context->local_cache = cache_init(context->cache_size, metadata_size, max_timestamp);
  if (context->local_cache == NULL) {
    free(context);
    return NULL;
  }

  cache_size_threshold_init(context);

  context->tc = ncast_proto_init(myID, metadata, metadata_size);
  if (!context->tc){
    free(context->local_cache);
    free(context);
    return NULL;
  }
  
  context->query_tokens = 0;
  context->reply_tokens = 0;
  context->first_ts = (max_timestamp + 1) / 2;
  // increase timestamp for initial message, since that is out of the normal cycle of the bootstrap peer
  ncast_proto_myentry_update(context->tc, NULL, context->first_ts, NULL, 0);

  return context;
}

static int ncast_change_metadata(struct peersampler_context *context, const void *metadata, int metadata_size)
{
  if (ncast_proto_metadata_update(context->tc, metadata, metadata_size) <= 0) {
    return -1;
  }

  return 1;
}

static struct peersampler_context* ncast_init(struct nodeID *myID, const void *metadata, int metadata_size, const char *config)
{
    return init(myID, metadata, metadata_size, config, 0);
}

static struct peersampler_context* ncastplus_init(struct nodeID *myID, const void *metadata, int metadata_size, const char *config)
{
    return init(myID, metadata, metadata_size, config, 1);
}

static int ncast_add_neighbour(struct peersampler_context *context, struct nodeID *neighbour, const void *metadata, int metadata_size)
{
  if (cache_add(context->local_cache, neighbour, metadata, metadata_size) < 0) {
    return -1;
  }
  if (!context->bootstrap_node) {	//save the first added nodeid as bootstrap nodeid
    context->bootstrap_node = nodeid_dup(neighbour);
  }
  return ncast_query_peer(context->tc, context->local_cache, neighbour);
}

static int ncast_parse_SDP(const uint8_t *buff)
{
    uint8_t num_sessions;
    int *dim_array;
    char **session_id_array;
    uint8_t **SDP_array;
    num_sessions = buff[1];
    session_id_array = (char **)malloc(num_sessions * sizeof(char*));
    dim_array = (int *)malloc(num_sessions * sizeof(int));
    memcpy(dim_array, buff + 2 + num_sessions * SESSION_ID_SIZE * sizeof(char), num_sessions * sizeof(int));
    for(int i = 0; i < num_sessions; i++){
        session_id_array[i] = (char*)malloc(SESSION_ID_SIZE * sizeof(char));
        memcpy(session_id_array[i], buff + 2 + i*SESSION_ID_SIZE*sizeof(char), SESSION_ID_SIZE);
    }
    session_id_array = buff + 2;
    fprintf(stderr, "ncast_parse_SDP: NUMERO FLUSSI RICEVUTI: %d\n", num_sessions);
    for(int i = 0; i < num_sessions; i++){
        fprintf(stderr, "ncast_parse_SDP: DIMENSIONE DEL SDP RICEVUTO: %d\n", dim_array[i]);
    }
    for(int i = 0; i < num_sessions; i++){
        fprintf(stderr, "ncast_parse_SDP: ID DEL SDP RICEVUTO: %s\n", &session_id_array[i]);
    }
    for(int i = 0; i < num_sessions; i++){
        char *str;
        if(i == 0){
            str = (char *)malloc(dim_array[i] * sizeof(char));
            memcpy(str, buff + 2 + num_sessions * SESSION_ID_SIZE * sizeof(char) + num_sessions * sizeof(int), dim_array[i] * sizeof(char));
            str[dim_array[i]] = '\0';
            fprintf(stderr, "ncast_parse_SDP: SDP RICEVUTO:\n%s\n", str);
        }else{
            str = (char *)malloc(dim_array[i] * sizeof(char));
            memcpy(str, buff + 2 + num_sessions * SESSION_ID_SIZE * sizeof(char) + num_sessions * sizeof(int) + dim_array[i - 1], dim_array[i] * sizeof(char));
            str[dim_array[i]] = '\0';
            fprintf(stderr, "ncast_parse_SDP: SDP RICEVUTO:\n%s\n", str);
        }
        char s[64];
        strcpy(s, "SDP");
        strcat(s + 3, &session_id_array[i]);
        FILE *file = fopen(s, "w");
        fputs(str, file);
    }
}

static int ncast_parse_data(struct peersampler_context *context, const uint8_t *buff, int len)
{
  int dummy;
  bool session_id_set_changed = false;

  if (len) {
    const struct topo_header *h = (const struct topo_header *)buff;
    
    if(h->protocol == MSG_TYPE_SDP){
        return ncast_parse_SDP(buff);
    }
    
    struct peer_cache *new, *remote_cache;

    if (h->protocol != MSG_TYPE_TOPOLOGY) {
      fprintf(stderr, "NCAST: Wrong protocol!\n");

      return -1;
    }

    context->counter++;
    if (context->counter == context->bootstrap_cycles) {
      context->bootstrap = false;
      ncast_proto_myentry_update(context->tc, NULL , - context->first_ts, NULL, 0);  // reset the timestamp of our own ID, we are in normal cycle, we will not disturb the algorithm
    }

    if(h->subtype == WITH_SESSION_IDS_OFFER){
        fprintf(stderr, "ncast_parse_data: RICEVUTO MESSAGGIO DI TOPOLOGIA CON SESSION_ID_SET OFFER\n");
        remote_cache = entries_undump_session_id(buff + sizeof(struct topo_header), len - sizeof(struct topo_header) - h->num_sessions*SESSION_ID_SIZE*sizeof(char) - h->num_sessions*sizeof(uint8_t), h->num_sessions);
    }else if(h->subtype == WITH_SESSION_IDS_REQUEST){
        fprintf(stderr, "ncast_parse_data: RICEVUTO MESSAGGIO DI TOPOLOGIA CON SESSION_ID_SET REQUEST\n");
        remote_cache = entries_undump_session_id(buff + sizeof(struct topo_header), len - sizeof(struct topo_header) - h->num_sessions*SESSION_ID_SIZE*sizeof(char) - h->num_sessions*sizeof(uint8_t), h->num_sessions);
        if(context->SDP_policy == SEND_AFTER_QUERY_SUCCESS)
            ncast_proto_set_time_to_send_session_id_set(context->tc, true);
        if(context->SDP_policy == SEND_AFTER_QUERY_FAILURE)
            ncast_proto_set_time_to_send_session_id_set(context->tc, false);
    }else if(h->subtype == SESSION_ID_NO_CHANGE){
        fprintf(stderr, "ncast_parse_data: RICEVUTO MESSAGGIO DI TOPOLOGIA CON SESSION_ID_SET_NO_CHANGE\n");
        if(context->SDP_policy == SEND_AFTER_QUERY_SUCCESS)
            ncast_proto_set_time_to_send_session_id_set(context->tc, false);
        if(context->SDP_policy == SEND_AFTER_QUERY_FAILURE)
            ncast_proto_set_time_to_send_session_id_set(context->tc, true);
        remote_cache = entries_undump(buff + sizeof(struct topo_header), len - sizeof(struct topo_header));
    }else{
        fprintf(stderr, "ncast_parse_data: RICEVUTO MESSAGGIO DI TOPOLOGIA SENZA SESSION_ID_SET\n");
        remote_cache = entries_undump(buff + sizeof(struct topo_header), len - sizeof(struct topo_header));
    }
    
    if(h->subtype == WITH_SESSION_IDS_OFFER){
        session_id_set_changed = ncast_proto_update_session_id_set(context->tc, remote_cache);
        fprintf(stderr, "ncast_parse_data: IL MIO SESSION_ID_SET è CAMBIATO? %d\n", session_id_set_changed);
        if(session_id_set_changed)
            ncast_proto_set_time_to_send_id_set_request(context->tc, true);
        else
            ncast_proto_set_time_to_send_id_set_no_change(context->tc, true);
    }
    if(h->subtype == WITH_SESSION_IDS_REQUEST){
        ncast_send_SDP(context->tc, remote_cache);
    }
    if(context->SDP_policy == SEND_IN_ALL_QUERY){
        ncast_proto_set_time_to_send_session_id_set(context->tc, true);
    }
    
    if (h->type == NCAST_QUERY) {
      context->reply_tokens--;	//sending a reply to someone who presumably receives it
      cache_randomize(context->local_cache);
      ncast_reply(context->tc, remote_cache, context->local_cache);
    } else {
     context->query_tokens--;	//a query was successful
    }
    cache_randomize(context->local_cache);
    cache_randomize(remote_cache);
    new = merge_caches(context->local_cache, remote_cache, context->cache_size, &dummy);
    cache_free(remote_cache);
    if (new != NULL) {
      cache_free(context->local_cache);
      context->local_cache = new;
    }
  }

  if (time_to_send(context)) {
    //fprintf(stderr,"[DEBUG] Time to send a TOPO message\n");
    int ret = INT_MIN;
    int i;
    int entries = cache_entries(context->local_cache);

    if (context->bootstrap_node &&
        (cache_entries(context->local_cache) <= context->cache_size_threshold) &&
        (cache_pos(context->local_cache, context->bootstrap_node) < 0)) {
      cache_add(context->local_cache, context->bootstrap_node, NULL, 0);
    }
    context->query_tokens++;
    if (context->reply_tokens++ > 0) {//on average one reply is sent, if not, do something
      context->query_tokens += context->reply_tokens;
      context->reply_tokens = 0;
    }
    if (context->query_tokens > entries) context->query_tokens = entries;	//don't be too aggressive

    cache_update(context->local_cache);
    for (i = 0; i < context->query_tokens; i++) {
      int r;

      r = ncast_query(context->tc, context->local_cache);
      r = r > ret ? r : ret;
    }
  }
  return 0;
}

static const struct nodeID *const*ncast_get_neighbourhood(struct peersampler_context *context, int *n)
{
  context->r = realloc(context->r, context->cache_size * sizeof(struct nodeID *));
  if (context->r == NULL) {
    return NULL;
  }

  for (*n = 0; nodeid(context->local_cache, *n) && (*n < context->cache_size); (*n)++) {
    context->r[*n] = nodeid(context->local_cache, *n);
    //fprintf(stderr, "Checking table[%d]\n", *n);
  }

  return context->r;
}

static const void *ncast_get_metadata(struct peersampler_context *context, int *metadata_size)
{
  return get_metadata(context->local_cache, metadata_size);
}

static int ncast_grow_neighbourhood(struct peersampler_context *context, int n)
{
  context->cache_size += n;
  cache_size_threshold_init(context);

  return context->cache_size;
}

static int ncast_shrink_neighbourhood(struct peersampler_context *context, int n)
{
  if (context->cache_size < n) {
    return -1;
  }
  context->cache_size -= n;
  cache_size_threshold_init(context);

  return context->cache_size;
}

static int ncast_remove_neighbour(struct peersampler_context *context, const struct nodeID *neighbour)
{
  return cache_del(context->local_cache, neighbour);
}

struct peersampler_iface ncast = {
  .init = ncast_init,
  .change_metadata = ncast_change_metadata,
  .add_neighbour = ncast_add_neighbour,
  .parse_data = ncast_parse_data,
  .get_neighbourhood = ncast_get_neighbourhood,
  .get_metadata = ncast_get_metadata,
  .grow_neighbourhood = ncast_grow_neighbourhood,
  .shrink_neighbourhood = ncast_shrink_neighbourhood,
  .remove_neighbour = ncast_remove_neighbour,
  .update_random_session_id_set = ncast_update_random_session_id_set,
  .add_session_id = ncast_add_session_id,
  .set_distributed = ncast_set_distributed,
};

struct peersampler_iface ncastplus = {
  .init = ncastplus_init,
  .change_metadata = ncast_change_metadata,
  .add_neighbour = ncast_add_neighbour,
  .parse_data = ncast_parse_data,
  .get_neighbourhood = ncast_get_neighbourhood,
  .get_metadata = ncast_get_metadata,
  .grow_neighbourhood = ncast_grow_neighbourhood,
  .shrink_neighbourhood = ncast_shrink_neighbourhood,
  .remove_neighbour = ncast_remove_neighbour,
  .update_random_session_id_set = ncast_update_random_session_id_set,
  .add_session_id = ncast_add_session_id,
  .set_distributed = ncast_set_distributed,
};
