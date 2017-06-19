/*
 *  Copyright (c) 2010 Luca Abeni
 *
 *  This is free software; see lgpl-2.1.txt
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "net_helper.h"
#include "topocache.h"
#include "proto.h"
#include "topo_proto.h"
#include "ncast_proto.h"
#include "grapes_msg_types.h"

struct ncast_proto_context {
  struct topo_context *context;
};

struct ncast_proto_context* ncast_proto_init(struct nodeID *s, const void *meta, int meta_size)
{
  struct ncast_proto_context *con;
  con = malloc(sizeof(struct ncast_proto_context));

  if (!con) return NULL;

  con->context = topo_proto_init(s, meta, meta_size);
  if (!con->context){
    free(con);
    return NULL;
  }

  return con;
}

int ncast_reply(struct ncast_proto_context *context, const struct peer_cache *c, const struct peer_cache *local_cache)
{
  int ret;
  struct peer_cache *send_cache;

  send_cache = cache_copy(local_cache);
  cache_update(send_cache);
  ret = topo_reply(context->context, c, send_cache, MSG_TYPE_TOPOLOGY, NCAST_REPLY, 0, 1);
  cache_free(send_cache);

  return ret;
}

int ncast_query_peer(struct ncast_proto_context *context, const struct peer_cache *local_cache, struct nodeID *dst)
{
  return topo_query_peer(context->context, local_cache, dst, MSG_TYPE_TOPOLOGY, NCAST_QUERY, 0);
}

int ncast_query(struct ncast_proto_context *context, const struct peer_cache *local_cache)
{
  struct nodeID *dst;

  dst = rand_peer(local_cache, NULL, 0);
  if (dst == NULL) {
    //fprintf(stderr,"[DEBUG] Megaerror, no peer selected for TOPO\n");
    return 0;
  }
  return topo_query_peer(context->context, local_cache, dst, MSG_TYPE_TOPOLOGY, NCAST_QUERY, 0);
}

void ncast_send_SDP(struct ncast_proto_context *context, const struct peer_cache *remote_cache)
{
    return topo_proto_send_SDP(context->context, remote_cache);
}

int ncast_proto_metadata_update(struct ncast_proto_context *context, const void *meta, int meta_size){
  return topo_proto_metadata_update(context->context, meta, meta_size);
}

int ncast_proto_myentry_update(struct ncast_proto_context *context, struct nodeID *s, int dts, const void *meta, int meta_size) {
  return topo_proto_myentry_update(context->context, s, dts, meta, meta_size);
}

int ncast_proto_update_random_session_id_set(struct ncast_proto_context *context){
    return topo_update_random_session_id_set(context->context);
}

bool ncast_proto_update_session_id_set(struct ncast_proto_context *context, struct peer_cache *remote_cache){
    return topo_proto_update_session_id_set(context->context, remote_cache);
}

int ncast_proto_set_time_to_send_session_id_set(struct ncast_proto_context *context, bool value){
    return topo_proto_set_time_to_send_session_id_set(context->context, value);
}

int ncast_proto_set_time_to_send_id_set_no_change(struct ncast_proto_context *context, bool value){
    return topo_proto_set_time_to_send_id_set_no_change(context->context, value);
}

void ncast_proto_add_session_id(struct ncast_proto_context *context, char * session_id){
    return topo_proto_add_session_id(context->context, session_id);
}

void ncast_proto_set_distributed(struct ncast_proto_context *context, char * session_id, bool value){
    return topo_proto_set_distributed(context->context, session_id, value);
}

void ncast_proto_set_time_to_send_id_set_request(struct ncast_proto_context *context, bool value){
    return topo_proto_set_time_to_send_id_set_request(context->context, value);
}

void ncast_proto_set_SDP_policy(struct ncast_proto_context *context, int * SDP_policy){
    return topo_proto_set_SDP_policy(context->context, SDP_policy);
}