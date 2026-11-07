// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
// Offline-only exporter. The official engine decodes RDB; this module never does.
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "vendor/valkeymodule.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char *output_path;
static char snapshot[65];
static size_t page_limit, item_limit;
static uint64_t total_limit, deadline_ms;
static int database_count, attempted;

typedef struct {
    ValkeyModuleCtx *ctx;
    int fd, db, failed;
    unsigned char *page;
    size_t used, items;
    uint64_t bytes, rows, pages, keys, stop_ms;
    const char *key;
    size_t key_len;
    long long expiry;
} Export;

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return UINT64_MAX;
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static void wipe(void *data, size_t size) {
    volatile unsigned char *p = data;
    while (size--) *p++ = 0;
}
static void little(unsigned char *out, uint64_t n, size_t width) {
    for (size_t i = 0; i < width; ++i) { out[i] = (unsigned char)n; n >>= 8; }
}
static int write_bytes(Export *e, const void *data, size_t size) {
    if (e->failed || monotonic_ms() >= e->stop_ms || size > total_limit - e->bytes) {
        e->failed = 1;
        return 0;
    }
    const unsigned char *p = data;
    while (size) {
        ssize_t n = write(e->fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { e->failed = 1; return 0; }
        p += n; size -= (size_t)n; e->bytes += (uint64_t)n;
    }
    return 1;
}
static int flush_page(Export *e) {
    if (!e->items) return !e->failed;
    unsigned char header[24];
    memcpy(header, "BBVPAGE1", 8);
    little(header + 8, e->used, 8);
    little(header + 16, e->items, 8);
    if (!write_bytes(e, header, sizeof(header)) || !write_bytes(e, e->page, e->used)) return 0;
    wipe(e->page, e->used);
    e->used = e->items = 0;
    ++e->pages;
    return 1;
}
// Cell: database:u32, kind:u8, absolute-expiry:i64, then three u64 lengths
// followed by exact key, position and value bytes. No quantity decoding here.
static void cell(Export *e, unsigned char kind, const void *position, size_t plen,
                 const void *value, size_t vlen) {
    if (e->failed) return;
    if (monotonic_ms() >= e->stop_ms || e->key_len > page_limit || plen > page_limit || vlen > page_limit) {
        e->failed = 1; return;
    }
    uint64_t size = 37ULL + e->key_len + plen + vlen;
    if (size > page_limit) { e->failed = 1; return; }
    if (e->items == item_limit || size > page_limit - e->used) {
        if (!flush_page(e)) return;
    }
    unsigned char *p = e->page + e->used;
    little(p, (uint32_t)e->db, 4); p[4] = kind;
    little(p + 5, (uint64_t)e->expiry, 8);
    little(p + 13, e->key_len, 8); little(p + 21, plen, 8); little(p + 29, vlen, 8);
    p += 37;
    memcpy(p, e->key, e->key_len); p += e->key_len;
    if (plen) memcpy(p, position, plen);
    p += plen;
    if (vlen) memcpy(p, value, vlen);
    e->used += (size_t)size; ++e->items; ++e->rows;
}
static void collection(ValkeyModuleKey *key, ValkeyModuleString *field,
                       ValkeyModuleString *value, void *data) {
    Export *e = data;
    if (e->failed) return;
    size_t flen = 0, vlen = 0;
    const char *f = ValkeyModule_StringPtrLen(field, &flen);
    const char *v = value ? ValkeyModule_StringPtrLen(value, &vlen) : NULL;
    int native = ValkeyModule_KeyType(key);
    unsigned char kind = native == VALKEYMODULE_KEYTYPE_HASH ? 2 :
                         native == VALKEYMODULE_KEYTYPE_SET ? 3 : 4;
    cell(e, kind, f, flen, v, vlen);
}
static void scan_key(ValkeyModuleCtx *ctx, ValkeyModuleString *name,
                     ValkeyModuleKey *key, void *data) {
    Export *e = data;
    if (e->failed) return;
    e->key = ValkeyModule_StringPtrLen(name, &e->key_len);
    e->expiry = ValkeyModule_GetAbsExpire(key);
    if (e->expiry < -1) { e->failed = 1; return; }
    int kind = ValkeyModule_KeyType(key);
    const char *type = kind == VALKEYMODULE_KEYTYPE_STRING ? "string" :
                       kind == VALKEYMODULE_KEYTYPE_HASH ? "hash" :
                       kind == VALKEYMODULE_KEYTYPE_SET ? "set" :
                       kind == VALKEYMODULE_KEYTYPE_ZSET ? "zset" :
                       kind == VALKEYMODULE_KEYTYPE_LIST ? "list" : NULL;
    if (!type) { e->failed = 1; return; }
    ++e->keys;
    cell(e, 0, NULL, 0, type, strlen(type));
    if (kind == VALKEYMODULE_KEYTYPE_STRING) {
        size_t length;
        const char *value = ValkeyModule_StringDMA(key, &length, VALKEYMODULE_READ);
        if (!value) { e->failed = 1; return; }
        cell(e, 1, NULL, 0, value, length);
    } else if (kind == VALKEYMODULE_KEYTYPE_LIST) {
        size_t length = ValkeyModule_ValueLength(key);
        if (length > LONG_MAX) { e->failed = 1; return; }
        for (size_t i = 0; i < length && !e->failed; ++i) {
            ValkeyModuleString *value = ValkeyModule_ListGet(key, (long)i);
            if (!value) { e->failed = 1; break; }
            char index[32];
            int n = snprintf(index, sizeof(index), "%zu", i);
            size_t vlen;
            const char *v = ValkeyModule_StringPtrLen(value, &vlen);
            cell(e, 5, index, (size_t)n, v, vlen);
            ValkeyModule_FreeString(ctx, value);
        }
    } else {
        ValkeyModuleScanCursor *cursor = ValkeyModule_ScanCursorCreate();
        if (!cursor) { e->failed = 1; return; }
        do {
            errno = 0;
            int more = ValkeyModule_ScanKey(key, cursor, collection, e);
            if (!more) { if (errno) e->failed = 1; break; }
        } while (!e->failed);
        ValkeyModule_ScanCursorDestroy(cursor);
    }
}
static int field_equals(ValkeyModuleServerInfoData *info, const char *field, const char *expected) {
    const char *value = ValkeyModule_ServerInfoGetFieldC(info, field);
    return value && strcmp(value, expected) == 0;
}
static int source_guard(ValkeyModuleCtx *ctx, uint64_t *counts) {
    if (ValkeyModule_GetServerVersion() != 0x00090103) return 0;
    int flags = ValkeyModule_GetContextFlags(ctx);
    if (!(flags & VALKEYMODULE_CTX_FLAGS_REPLICA) || !(flags & VALKEYMODULE_CTX_FLAGS_READONLY) ||
        !(flags & VALKEYMODULE_CTX_FLAGS_REPLICA_IS_STALE) ||
        (flags & (VALKEYMODULE_CTX_FLAGS_PRIMARY | VALKEYMODULE_CTX_FLAGS_CLUSTER |
                  VALKEYMODULE_CTX_FLAGS_AOF | VALKEYMODULE_CTX_FLAGS_RDB |
                  VALKEYMODULE_CTX_FLAGS_MAXMEMORY | VALKEYMODULE_CTX_FLAGS_EVICT |
                  VALKEYMODULE_CTX_FLAGS_LOADING))) return 0;
    ValkeyModuleServerInfoData *repl = ValkeyModule_GetServerInfo(ctx, "replication");
    if (!repl) return 0;
    int good = field_equals(repl, "master_host", "127.0.0.1") &&
               field_equals(repl, "master_port", "0") &&
               field_equals(repl, "master_link_status", "down") &&
               field_equals(repl, "slave_read_only", "1");
    ValkeyModule_FreeServerInfo(ctx, repl);
    if (!good || ValkeyModule_SelectDb(ctx, database_count) != VALKEYMODULE_ERR) return 0;
    ValkeyModuleServerInfoData *info = ValkeyModule_GetServerInfo(ctx, "keyspace");
    if (!info) return 0;
    for (int db = 0; db < database_count; ++db) {
        if (ValkeyModule_SelectDb(ctx, db) != VALKEYMODULE_OK) { good = 0; break; }
        counts[db] = ValkeyModule_DbSize(ctx);
        char field[32]; snprintf(field, sizeof(field), "db%d", db);
        const char *value = ValkeyModule_ServerInfoGetFieldC(info, field);
        if (!counts[db] && !value) continue; // INFO omits empty databases.
        unsigned long long keys, expires, volatile_items;
        long long avg;
        int end = 0;
        if (!value || sscanf(value, "keys=%llu,expires=%llu,avg_ttl=%lld,keys_with_volatile_items=%llu%n",
                             &keys, &expires, &avg, &volatile_items, &end) != 4 ||
            value[end] != '\0' || keys != counts[db] || expires > keys || volatile_items != 0) {
            good = 0; break;
        }
    }
    ValkeyModule_FreeServerInfo(ctx, info);
    return good;
}
static int run(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    (void)argv;
    if (argc != 1 || attempted++) return ValkeyModule_ReplyWithError(ctx, "ERR exporter is single use");
    uint64_t counts[1024] = {0};
    // Guard happens before creating any output. Missing counters, HFE, wrong
    // engine/role/config all fail as unsupported sources, never lossy exports.
    if (!source_guard(ctx, counts))
        return ValkeyModule_ReplyWithError(ctx, "ERR UnsupportedFrozenSource: native guards or hash field expiry");
    Export e = {.ctx = ctx, .fd = -1, .stop_ms = monotonic_ms() + deadline_ms};
    e.page = malloc(page_limit);
    if (!e.page) return ValkeyModule_ReplyWithError(ctx, "ERR export allocation failed");
    e.fd = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (e.fd < 0) { free(e.page); return ValkeyModule_ReplyWithError(ctx, "ERR export output unavailable"); }
    unsigned char header[80];
    memcpy(header, "BBVEXP01", 8); memcpy(header + 8, snapshot, 64);
    little(header + 72, 0x00090103, 4); little(header + 76, database_count, 4);
    write_bytes(&e, header, sizeof(header));
    for (int db = 0; db < database_count && !e.failed; ++db) {
        unsigned char count[8]; little(count, counts[db], 8); write_bytes(&e, count, 8);
    }
    for (int db = 0; db < database_count && !e.failed; ++db) {
        e.db = db;
        if (ValkeyModule_SelectDb(ctx, db) != VALKEYMODULE_OK) { e.failed = 1; break; }
        uint64_t start_keys = e.keys;
        ValkeyModuleScanCursor *cursor = ValkeyModule_ScanCursorCreate();
        if (!cursor) { e.failed = 1; break; }
        do {
            errno = 0;
            int more = ValkeyModule_Scan(ctx, cursor, scan_key, &e);
            if (!more) { if (errno) e.failed = 1; break; }
        } while (!e.failed);
        ValkeyModule_ScanCursorDestroy(cursor);
        // No rehashing/writes between scans: duplicate or missing key coverage
        // is refused, never accepted as a complete extraction.
        if (e.keys - start_keys != counts[db]) e.failed = 1;
    }
    uint64_t after[1024] = {0};
    if (!e.failed && (!source_guard(ctx, after) || memcmp(counts, after, sizeof(counts)))) e.failed = 1;
    if (!e.failed) flush_page(&e);
    if (!e.failed) {
        unsigned char footer[88]; memcpy(footer, "BBVEND01", 8);
        little(footer + 8, e.rows, 8); little(footer + 16, e.pages, 8);
        memcpy(footer + 24, snapshot, 64);
        write_bytes(&e, footer, sizeof(footer));
    }
    if (!e.failed && fsync(e.fd)) e.failed = 1;
    if (close(e.fd)) e.failed = 1;
    wipe(e.page, page_limit); free(e.page);
    if (e.failed) { unlink(output_path); return ValkeyModule_ReplyWithError(ctx, "ERR incomplete or unsupported frozen export"); }
    return ValkeyModule_ReplyWithSimpleString(ctx, "OK");
}
int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (ValkeyModule_Init(ctx, "busbar_offline_export", 1, VALKEYMODULE_APIVER_1) == VALKEYMODULE_ERR) return VALKEYMODULE_ERR;
    if (argc != 7 || !ValkeyModule_GetServerVersion || !ValkeyModule_GetContextFlags ||
        !ValkeyModule_Scan || !ValkeyModule_ScanKey || !ValkeyModule_GetAbsExpire ||
        !ValkeyModule_GetServerInfo || !ValkeyModule_ServerInfoGetFieldC || !ValkeyModule_FreeServerInfo ||
        !ValkeyModule_SelectDb || !ValkeyModule_DbSize || !ValkeyModule_ScanCursorCreate ||
        !ValkeyModule_ScanCursorDestroy || !ValkeyModule_KeyType || !ValkeyModule_StringPtrLen ||
        !ValkeyModule_StringDMA || !ValkeyModule_ListGet || !ValkeyModule_ValueLength ||
        !ValkeyModule_FreeString || !ValkeyModule_StringToLongLong || !ValkeyModule_CreateCommand ||
        !ValkeyModule_ReplyWithError || !ValkeyModule_ReplyWithSimpleString) return VALKEYMODULE_ERR;
    if (ValkeyModule_GetServerVersion() != 0x00090103) return VALKEYMODULE_ERR;
    size_t n;
    const char *path = ValkeyModule_StringPtrLen(argv[0], &n);
    if (memchr(path, 0, n)) return VALKEYMODULE_ERR;
    output_path = malloc(n + 1); if (!output_path) return VALKEYMODULE_ERR;
    memcpy(output_path, path, n); output_path[n] = 0;
    const char *digest = ValkeyModule_StringPtrLen(argv[1], &n);
    if (n != 64) return VALKEYMODULE_ERR;
    for (size_t i = 0; i < 64; ++i)
        if (!((digest[i] >= '0' && digest[i] <= '9') || (digest[i] >= 'a' && digest[i] <= 'f'))) return VALKEYMODULE_ERR;
    memcpy(snapshot, digest, 64);
    long long args[5];
    for (int i = 0; i < 5; ++i)
        if (ValkeyModule_StringToLongLong(argv[i + 2], &args[i]) != VALKEYMODULE_OK || args[i] <= 0) return VALKEYMODULE_ERR;
    if (args[0] < 64 || args[0] > 64 * 1024 * 1024 || args[1] > 1000000 || args[3] > 1024 || args[4] > 86400000) return VALKEYMODULE_ERR;
    page_limit = (size_t)args[0]; item_limit = (size_t)args[1]; total_limit = (uint64_t)args[2];
    database_count = (int)args[3]; deadline_ms = (uint64_t)args[4];
    return ValkeyModule_CreateCommand(ctx, "bbexport.run", run, "readonly allow-stale", 0, 0, 0);
}
