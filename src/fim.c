/*
 * fim - a small file integrity monitor
 *
 * Walks a directory, computes a SHA-256 for every regular file, and
 * compares the result against a stored baseline. On subsequent runs it
 * reports files that were ADDED, MODIFIED, or REMOVED.
 *
 * This is a learning project modelled on tools like Tripwire / AIDE.
 *
 * Build:  make
 * Usage:  ./fim baseline <dir> <baseline-file>   # record a baseline
 *         ./fim check    <dir> <baseline-file>   # compare against it
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#define PATH_MAX_LEN 4096
#define HEX_LEN      (EVP_MAX_MD_SIZE * 2 + 1)

/* Compute the SHA-256 of a file, writing a hex string into out[HEX_LEN]. */
static int sha256_file(const char *path, char out[HEX_LEN])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(f);
        return -1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(f);
            return -1;
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &dlen) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    fclose(f);

    for (unsigned int i = 0; i < dlen; i++)
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    out[dlen * 2] = '\0';
    return 0;
}

/* Recursively hash every regular file under `dir`, printing "hash  path". */
static void walk(const char *dir, FILE *sink)
{
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "warning: cannot open %s\n", dir);
        return;
    }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;

        char path[PATH_MAX_LEN];
        int len = snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (len < 0 || len >= (int)sizeof path) {
            fprintf(stderr, "warning: path too long under %s\n", dir);
            continue;
        }

        struct stat st;
        if (lstat(path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            walk(path, sink);
        } else if (S_ISREG(st.st_mode)) {
            char hex[HEX_LEN];
            if (sha256_file(path, hex) == 0)
                fprintf(sink, "%s  %s\n", hex, path);
            else
                fprintf(stderr, "warning: cannot hash %s\n", path);
        }
        /* symlinks, devices, etc. are intentionally skipped */
    }
    closedir(d);
}

/* A minimal open-addressing hash map from path -> sha256 hex. */
struct entry {
    char *path;
    char  hex[HEX_LEN];
    int   seen;      /* marked when matched during a check */
    int   used;
};

struct map {
    struct entry *slots;
    size_t        cap;
    size_t        count;
};

static unsigned long djb2(const char *s)
{
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*s++))
        h = ((h << 5) + h) + c;
    return h;
}

static void map_init(struct map *m, size_t cap)
{
    m->slots = calloc(cap, sizeof *m->slots);
    if (!m->slots) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    m->cap = cap;
    m->count = 0;
}

static void map_put(struct map *m, const char *path, const char *hex)
{
    size_t i = djb2(path) % m->cap;
    for (size_t probe = 0; probe < m->cap; probe++) {
        size_t idx = (i + probe) % m->cap;
        if (!m->slots[idx].used) {
            m->slots[idx].path = strdup(path);
            if (!m->slots[idx].path) {
                fprintf(stderr, "out of memory\n");
                exit(1);
            }
            snprintf(m->slots[idx].hex, HEX_LEN, "%.*s", HEX_LEN - 1, hex);
            m->slots[idx].used = 1;
            m->count++;
            return;
        }
        if (strcmp(m->slots[idx].path, path) == 0) {
            snprintf(m->slots[idx].hex, HEX_LEN, "%.*s", HEX_LEN - 1, hex);
            return;
        }
    }
    fprintf(stderr, "baseline too large for map\n");
    exit(1);
}

static struct entry *map_get(struct map *m, const char *path)
{
    size_t i = djb2(path) % m->cap;
    for (size_t probe = 0; probe < m->cap; probe++) {
        size_t idx = (i + probe) % m->cap;
        if (!m->slots[idx].used)
            return NULL;
        if (strcmp(m->slots[idx].path, path) == 0)
            return &m->slots[idx];
    }
    return NULL;
}

static void map_free(struct map *m)
{
    for (size_t i = 0; i < m->cap; i++)
        if (m->slots[i].used)
            free(m->slots[i].path);
    free(m->slots);
}

static int do_baseline(const char *dir, const char *out_path)
{
    FILE *out = fopen(out_path, "w");
    if (!out) {
        perror("fopen baseline");
        return 1;
    }
    walk(dir, out);
    fclose(out);
    printf("baseline written to %s\n", out_path);
    return 0;
}

static int do_check(const char *dir, const char *baseline_path)
{
    FILE *bf = fopen(baseline_path, "r");
    if (!bf) {
        perror("fopen baseline");
        return 1;
    }

    struct map m;
    map_init(&m, 4096);

    char line[PATH_MAX_LEN + HEX_LEN + 8];
    while (fgets(line, sizeof line, bf)) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        /* format: "<hex>  <path>" */
        char *sep = strstr(line, "  ");
        if (!sep)
            continue;
        *sep = '\0';
        const char *hex = line;
        const char *path = sep + 2;
        map_put(&m, path, hex);
    }
    fclose(bf);

    /* Hash the current tree into a temp file, then diff. */
    char tmpl[] = "/tmp/fim_cur_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        perror("mkstemp");
        map_free(&m);
        return 1;
    }
    FILE *cur = fdopen(fd, "w+");
    walk(dir, cur);
    rewind(cur);

    int changes = 0;
    while (fgets(line, sizeof line, cur)) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        char *sep = strstr(line, "  ");
        if (!sep)
            continue;
        *sep = '\0';
        const char *hex = line;
        const char *path = sep + 2;

        struct entry *e = map_get(&m, path);
        if (!e) {
            printf("ADDED     %s\n", path);
            changes++;
        } else {
            e->seen = 1;
            if (strcmp(e->hex, hex) != 0) {
                printf("MODIFIED  %s\n", path);
                changes++;
            }
        }
    }

    for (size_t i = 0; i < m.cap; i++) {
        if (m.slots[i].used && !m.slots[i].seen) {
            printf("REMOVED   %s\n", m.slots[i].path);
            changes++;
        }
    }

    fclose(cur);
    unlink(tmpl);
    map_free(&m);

    if (changes == 0)
        printf("OK: no changes against baseline\n");
    else
        printf("\n%d change(s) detected\n", changes);
    return changes == 0 ? 0 : 2;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage:\n"
        "  %s baseline <dir> <baseline-file>   record a baseline\n"
        "  %s check    <dir> <baseline-file>   compare against baseline\n",
        prog, prog);
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        usage(argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "baseline") == 0)
        return do_baseline(argv[2], argv[3]);
    if (strcmp(argv[1], "check") == 0)
        return do_check(argv[2], argv[3]);

    usage(argv[0]);
    return 1;
}
