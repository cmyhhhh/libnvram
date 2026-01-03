#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <mntent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alias.h"
#include "nvram.h"
#include "config.h"

/* 加载可能在固件中存在的默认NVRAM配置文件 */
#define NATIVE(a, b)
#define PATH(a)
#define TABLE(a) \
    extern const char *a[] __attribute__((weak));

    NVRAM_DEFAULTS_PATH
#undef TABLE
#undef PATH
#undef NATIVE

// https://lkml.org/lkml/2007/3/9/10
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + sizeof(typeof(int[1 - 2 * !!__builtin_types_compatible_p(typeof(arr), typeof(&arr[0]))])) * 0)

#define PRINT_MSG(fmt, ...) do { if (DEBUG) { fprintf(stderr, "%s: "fmt, __FUNCTION__, ##__VA_ARGS__); } } while (0)

/* Weak symbol definitions for library functions that may not be present */
// 防止固件的lib库中没有ftok函数，IPC可能会被裁剪掉
__typeof__(ftok) __attribute__((weak)) ftok;

/* Global variables */
static int init = 0;
static char temp[BUFFER_SIZE];
// 全局标志，用于控制是否记录默认键
static int recording_defaults = 0;
static FILE *defaults_list_fp = NULL;

static int sem_get() {
    int key, semid = 0;
    unsigned int timeout = 0;
    struct semid_ds seminfo;
    union semun {
        int val;
        struct semid_ds *buf;
        unsigned short *array;
        struct seminfo *__buf;
    } semun;
    struct sembuf sembuf = {
        .sem_num = 0,
        .sem_op = 1,
        .sem_flg = 0,
    };

    // Generate key for semaphore based on the mount point
    // 如果固件没有ftok函数，信号量机制失效，加锁和解锁操作都会失败并返回
    // 但 NVRAM 操作仍能执行，只是失去了并发保护
    if (!ftok || (key = ftok(MOUNT_POINT, IPC_KEY)) == -1) {
        PRINT_MSG("%s\n", "Unable to get semaphore key!");
        return -1;
    }

    PRINT_MSG("Key: %x\n", key);

    // Get the semaphore using the key
    if ((semid = semget(key, 1, IPC_CREAT | IPC_EXCL | 0666)) >= 0) {
        semun.val = 1;
        // Unlock the semaphore and set the sem_otime field
        if (semop(semid, &sembuf, 1) == -1) {
            PRINT_MSG("%s\n", "Unable to initialize semaphore!");
            // Clean up semaphore
            semctl(semid, 0, IPC_RMID);
            semid = -1;
        }
    } else if (errno == EEXIST) {
        // Get the semaphore in non-exclusive mode
        if ((semid = semget(key, 1, 0)) < 0) {
            PRINT_MSG("%s\n", "Unable to get semaphore non-exclusively!");
            return semid;
        }

        semun.buf = &seminfo;
        // Wait for the semaphore to be initialized
        while (timeout++ < IPC_TIMEOUT) {
            semctl(semid, 0, IPC_STAT, semun);

            if (semun.buf && semun.buf->sem_otime != 0) {
                break;
            }

            if (!(timeout % 100)) {
                PRINT_MSG("Waiting for semaphore initialization (Key: %x, Semaphore: %x)...\n", key, semid);
            }
        }
    }

    return (timeout < IPC_TIMEOUT) ? semid : -1;
}

static void sem_lock() {
    int semid;
    struct sembuf sembuf = {
        .sem_num = 0,
        .sem_op = -1,
        .sem_flg = SEM_UNDO,
    };
    struct mntent entry, *ent;
    FILE *mnt = NULL;

    // If not initialized, check for existing mount before triggering NVRAM init
    if (!init) {
        if ((mnt = setmntent("/proc/mounts", "r"))) {
            while ((ent = getmntent_r(mnt, &entry, temp, BUFFER_SIZE))) {
                if (!strncmp(ent->mnt_dir, MOUNT_POINT, sizeof(MOUNT_POINT) - 2)) {
                    init = 1;
                    PRINT_MSG("%s\n", "Already initialized!");
                    endmntent(mnt);
                    goto cont;
                }
            }
            endmntent(mnt);
        }

        PRINT_MSG("%s\n", "Triggering NVRAM initialization!");
        nvram_init();
    }

cont:
    // Must get sempahore after NVRAM initialization, mounting will change ID
    if ((semid = sem_get()) == -1) {
        PRINT_MSG("%s\n", "Unable to get semaphore!");
        return;
    }

//    PRINT_MSG("%s\n", "Locking semaphore...");

    if (semop(semid, &sembuf, 1) == -1) {
        PRINT_MSG("%s\n", "Unable to lock semaphore!");
    }

    return;
}

static void sem_unlock() {
    int semid;
    struct sembuf sembuf = {
        .sem_num = 0,
        .sem_op = 1,
        .sem_flg = SEM_UNDO,
    };

    if ((semid = sem_get(NULL)) == -1) {
        PRINT_MSG("%s\n", "Unable to get semaphore!");
        return;
    }

//    PRINT_MSG("%s\n", "Unlocking semaphore...");

    if (semop(semid, &sembuf, 1) == -1) {
        PRINT_MSG("%s\n", "Unable to unlock semaphore!");
    }

    return;
}

int nvram_init(void) {
    FILE *f;

    PRINT_MSG("%s\n", "Initializing NVRAM...");

    if (init) {
        PRINT_MSG("%s\n", "Early termination!");
        return E_SUCCESS;
    }
    init = 1;

    return nvram_set_default();
}

int nvram_reset(void) {
    PRINT_MSG("%s\n", "Reseting NVRAM...");

    if (nvram_clear() != E_SUCCESS) {
        PRINT_MSG("%s\n", "Unable to clear NVRAM!");
        return E_FAILURE;
    }

    return nvram_set_default();
}

int nvram_clear(void) {
    PRINT_MSG("%s\n", "Clearing NVRAM...");
    int ret = nvram_clear_defaults();
    return ret;
}

int nvram_close(void) {
    PRINT_MSG("%s\n", "Closing NVRAM...");
    return E_SUCCESS;
}

int nvram_list_add(const char *key, const char *val) {
    char *pos;

    PRINT_MSG("%s = %s + %s\n", val, temp, key);

    if (nvram_get_buf(key, temp, BUFFER_SIZE, "nvram_list_add") != E_SUCCESS) {
        return nvram_set(key, val);
    }

    if (!key || !val) {
        return E_FAILURE;
    }

    if (strlen(temp) + 1 + strlen(val) + 1 > BUFFER_SIZE) {
        return E_FAILURE;
    }

    // This will overwrite the temp buffer, but it is OK
    if (nvram_list_exist(key, val, LIST_MAGIC) != NULL) {
        return E_SUCCESS;
    }

    // Replace terminating NULL of list with LIST_SEP
    pos = temp + strlen(temp);
    if (pos != temp) {
        *pos++ = LIST_SEP[0];
    }

    if (strcpy(pos, val) != pos) {
        return E_FAILURE;
    }

    return nvram_set(key, temp);
}

char *nvram_list_exist(const char *key, const char *val, int magic) {
    char *pos = NULL;

    if (nvram_get_buf(key, temp, BUFFER_SIZE, "") != E_SUCCESS) {
        return E_FAILURE;
    }

    PRINT_MSG("%s ?in %s (%s)\n", val, key, temp);

    if (!val) {
        return (magic == LIST_MAGIC) ? NULL : (char *) E_FAILURE;
    }

    while ((pos = strtok(!pos ? temp : NULL, LIST_SEP))) {
        if (!strcmp(pos + 1, val)) {
            return (magic == LIST_MAGIC) ? pos + 1 : (char *) E_SUCCESS;
        }
    }

    return (magic == LIST_MAGIC) ? NULL : (char *) E_FAILURE;
}

int nvram_list_del(const char *key, const char *val) {
    char *pos;

    if (nvram_get_buf(key, temp, BUFFER_SIZE, "nvram_list_del") != E_SUCCESS) {
        return E_SUCCESS;
    }

    PRINT_MSG("%s = %s - %s\n", key, temp, val);

    if (!val) {
        return E_FAILURE;
    }

    // This will overwrite the temp buffer, but it is OK.
    if ((pos = nvram_list_exist(key, val, LIST_MAGIC))) {
        while (*pos && *pos != LIST_SEP[0]) {
            *pos++ = LIST_SEP[0];
        }
    }

    return nvram_set(key, temp);
}

char *replace_char(char *key, char oldchar, char newchar)
{
  char *ptr;

  for ( ptr = strchr(key, oldchar); ptr; ptr = strchr(ptr, oldchar) )
    *ptr = newchar;
  return key;
}

char * read_key(const char *key, const char *func_name, int enable_llm)
{
    if (!key){
        PRINT_MSG("NULL get key, func: %s!\n", func_name);
        return "";
    }

    if(!func_name){
        func_name = "nvram_get";
    }

    PRINT_MSG("get key: %s, func: %s\n", key, func_name);

    FILE *fp;
    size_t bufsize;
    char KEY_PATH[512];
    char KEY_NAME[256];
    char value[2049];

    memset(KEY_NAME, 0, sizeof(KEY_NAME));
    memset(KEY_PATH, 0, sizeof(KEY_PATH));
    snprintf(KEY_NAME, 255, "%s", key);
    replace_char(KEY_NAME, '/', '_');
    snprintf(KEY_PATH, 512, "%s/%s", "/fa_nvram", KEY_NAME);
    if (access(KEY_PATH, F_OK) != 0 && enable_llm){
        fprintf(stderr, "%s is unknown! try to use LLM for recovery!\n", key);
        
        const char *COMMUNICATION_FILE = "/msg_nvram.txt";
        const char *LOCK_FILE = "/msg_nvram.lock";
        const int MAX_WAIT_COUNT = 60;
        int WAIT_COUNT = 0;
        FILE *fp;
        
        while (access(LOCK_FILE, F_OK) == 0) {
            if (WAIT_COUNT >= MAX_WAIT_COUNT) {
                fflush(stderr);
                return -1;
            }
            WAIT_COUNT++;
            sleep(1);
        }
        
        fp = fopen(LOCK_FILE, "w");
        if (fp != NULL) {
            fprintf(fp, "%d", getpid());
            fclose(fp);
        }
        
        remove(COMMUNICATION_FILE);
        
        char MESSAGE[256];
        snprintf(MESSAGE, sizeof(MESSAGE), "--nvram_function_name %s --key %s", func_name, key);
        
        fp = fopen(COMMUNICATION_FILE, "w");
        if (fp != NULL) {
            fprintf(fp, "%s", MESSAGE);
            fclose(fp);
        }
        
        remove(LOCK_FILE);
        fflush(stderr);
    }

    int max_attempts = 10;
    int wait_seconds = 1;
    int attempts = 0;
    if (!enable_llm){
        max_attempts = 0;
    }
    while (attempts < max_attempts)
    {
        if (access(KEY_PATH, F_OK) == 0)
        {
            PRINT_MSG("find key %s file\n", KEY_NAME);
            break;
        }
        else
        {
            PRINT_MSG("wait key %s file (attempts: %d/%d)...\n",
                      KEY_PATH, attempts + 1, max_attempts);
            sleep(wait_seconds); // 等待一段时间再检查
        }
        attempts++;
    }

    fp = fopen(KEY_PATH, "r");
    if (fp)
    {
        PRINT_MSG("open %s success!\n", key);
        bufsize = fread(value, 1, 2048, fp);
        fclose(fp);
        if ( bufsize )
            return strdup(value);
        else
            return "";
    }
    else
    {
        PRINT_MSG("open %s fail!\n", key);
        return "";
    }
}

char *nvram_get(const char *key, const char *func_name, int enable_llm) {
// Some routers pass the key as the second argument, instead of the first.
// We attempt to fix this directly in assembly for MIPS if the key is NULL.
#if defined(mips)
    if (!key) {
        asm ("move %0, $a1" :"=r"(key));
    }
#endif

    if (access("/fa_nvram", F_OK))
        return 0;
    else
        return read_key(key, func_name, enable_llm);
}

char *nvram_safe_get(const char *key, const char *func_name) {
    char* ret = nvram_get(key, func_name, 1);
    return ret ? ret : strdup("");
}

char *nvram_default_get(const char *key, const char *val) {
    char *ret = nvram_get(key, "nvram_default_get", 0);

    if (ret) {
        return ret;
    }

    if (val && nvram_set(key, val)) {
        return val;
    }

    return NULL;
}

int nvram_get_buf(const char *key, char *buf, size_t sz, const char *func_name) {
    char *val;
    if (!buf || !sz) {
        return E_FAILURE;
    }
    val = nvram_get(key, func_name, 1);
    *buf = 0;
    memcpy(buf, val, sz);
    return E_SUCCESS;
}

int nvram_get_int(const char *key, const char *func_name) {
    if (!key) {
        return E_FAILURE;
    }

    const char *ret = nvram_get(key, func_name, 1);
    int value = atoi(ret);    
    return value;
}

int nvram_getall(char *buf, size_t len) {
    char path[PATH_MAX] = MOUNT_POINT;
    struct stat path_stat;
    struct dirent *entry;
    size_t pos = 0, ret;
    DIR *dir;
    FILE *f;

    if (!buf || !len) {
        PRINT_MSG("%s\n", "NULL buffer or zero length!");
        return E_FAILURE;
    }

    sem_lock();

    if (!(dir = opendir(MOUNT_POINT))) {
        sem_unlock();
        PRINT_MSG("Unable to open directory %s!\n", MOUNT_POINT);
        return E_FAILURE;
    }

    while ((entry = readdir(dir))) {
        if (!strncmp(entry->d_name, ".", 1) || !strcmp(entry->d_name, "..")) {
            continue;
        }

        strncpy(path + strlen(MOUNT_POINT), entry->d_name, ARRAY_SIZE(path) - ARRAY_SIZE(MOUNT_POINT) - 1);
        path[PATH_MAX - 1] = '\0';

        stat(path, &path_stat);
        if (!S_ISREG(path_stat.st_mode)) {
            continue;
        }

        if ((ret = snprintf(buf + pos, len - pos, "%s=", entry->d_name)) != strlen(entry->d_name) + 1) {
            closedir(dir);
            sem_unlock();
            PRINT_MSG("Unable to append key %s!\n", buf + pos);
            return E_FAILURE;
        }

        pos += ret;

        if ((f = fopen(path, "rb")) == NULL) {
            closedir(dir);
            sem_unlock();
            PRINT_MSG("Unable to open key: %s!\n", path);
            return E_FAILURE;
        }

        ret = fread(temp, sizeof(*temp), BUFFER_SIZE, f);
        if (ferror(f)) {
            fclose(f);
            closedir(dir);
            sem_unlock();
            PRINT_MSG("Unable to read key: %s!\n", path);
            return E_FAILURE;
        }

        memcpy(buf + pos, temp, ret);
        buf[pos + ret] = '\0';
        pos += ret + 1;

        fclose(f);
    }

    closedir(dir);
    sem_unlock();
    return E_SUCCESS;
}

int write_key(const char *key, const char *buf)
{
    if ( !key || !*key )
        return E_FAILURE;

    PRINT_MSG("set key: %s\n", key);
    PRINT_MSG("set buffer: %s\n", buf);

    FILE *fp;
    size_t bufsize;
    char KEY_PATH[512];
    char KEY_NAME[256];
    memset(KEY_NAME, 0, sizeof(KEY_NAME));
    memset(KEY_PATH, 0, sizeof(KEY_PATH));
    snprintf(KEY_NAME, 255, "%s", key);
    replace_char(KEY_NAME, '/', '_');
    snprintf(KEY_PATH, 512, "%s/%s", "/fa_nvram", KEY_NAME);
    sem_lock();
    fp = fopen(KEY_PATH, "w");
    if (!fp) {
        sem_unlock();
        return E_FAILURE;
    }
    fputs(buf, fp);
    // 如果正在记录默认键，将键写入列表文件
    if (recording_defaults && defaults_list_fp) {
        fprintf(defaults_list_fp, "%s\n", key);
    }
    fclose(fp);
    sem_unlock();
    return E_SUCCESS;
}

int nvram_set(const char *key, const char *val) {
    if ( access("/fa_nvram", 0) )
        return E_FAILURE;
    else
        return write_key(key, val);
}

int nvram_set_int(const char *key, const int val) {
    char charval[512]; // [sp+18h] [+18h] BYREF
    snprintf(charval, 512, "%d", val);
    return nvram_set(key, charval);
}

int nvram_set_default(void) {
    // 在qemu-user环境中，子进程间隔离，使用文件标记避免重复初始化
    const char *init_marker = "/fa_nvram/.defaults_loaded";
    const char *defaults_list = "/fa_nvram/.defaults_list";
    
    // 检查初始化标记文件是否存在
    if (!access(init_marker, F_OK)) {
        PRINT_MSG("Default values already loaded, skipping...\n");
        return 1;
    }
    
    // 打开默认值列表文件，用于记录所有设置的键
    defaults_list_fp = fopen(defaults_list, "w");
    if (!defaults_list_fp) {
        PRINT_MSG("Warning: Failed to create defaults list file %s!\n", defaults_list);
    }
    
    // 开启记录默认键
    recording_defaults = 1;
    
    int ret = nvram_set_default_builtin();
    PRINT_MSG("Loading built-in default values = %d!\n", ret);

#define NATIVE(a, b) \
    if (!system(a)) { \
        PRINT_MSG("Executing native call to built-in function: %s (%p) = %d!\n", #b, b, b); \
    }

#define TABLE(a) \
    PRINT_MSG("Checking for symbol \"%s\"...\n", #a); \
    if (a) { \
        PRINT_MSG("Loading from native built-in table: %s (%p) = %d!\n", #a, a, nvram_set_default_table(a)); \
    }

#define PATH(a) \
    if (!access(a, R_OK)) { \
        PRINT_MSG("Loading from default configuration file: %s = %d!\n", a, foreach_nvram_from(a, (void (*)(const char *, const char *, void *)) nvram_set, NULL)); \
    }

    NVRAM_DEFAULTS_PATH
#undef PATH
#undef NATIVE
#undef TABLE
    
    // 关闭记录默认键
    recording_defaults = 0;
    
    // 关闭默认值列表文件
    if (defaults_list_fp) {
        fclose(defaults_list_fp);
        defaults_list_fp = NULL;
        PRINT_MSG("Created defaults list file: %s\n", defaults_list);
    }
    
    // 创建初始化标记文件
    FILE *marker_fp = fopen(init_marker, "w");
    if (marker_fp) {
        fclose(marker_fp);
        PRINT_MSG("Created initialization marker: %s\n", init_marker);
    } else {
        PRINT_MSG("Failed to create initialization marker: %s\n", init_marker);
    }

    return 1;
}

static int nvram_set_default_builtin(void) {
    int ret = E_SUCCESS;
    char nvramKeyBuffer[100]="";
    int index=0;

    PRINT_MSG("%s\n", "Setting built-in default values!");

#define ENTRY(a, b, c) \
    if (b(a, c) != E_SUCCESS) { \
        PRINT_MSG("Unable to initialize built-in NVRAM value %s!\n", a); \
        ret = E_FAILURE; \
    }

#define FOR_ENTRY(a, b, c, d, e) \
    index = d; \
    while (index != e) { \
        snprintf(nvramKeyBuffer, 0x1E, a, index++); \
        ENTRY(nvramKeyBuffer, b, c) \
    } \

    NVRAM_DEFAULTS
#undef ENTRY
#undef FOR_ENTRY

    return ret;
}

static int nvram_set_default_table(const char *tbl[]) {
    size_t i = 0;

    while (tbl[i]) {
        nvram_set(tbl[i], tbl[i + 1]);
        i += (tbl[i + 2] != 0 && tbl[i + 2] != (char *) 1) ? 2 : 3;
    }

    return E_SUCCESS;
}

int nvram_unset(const char *key) {
    char path[PATH_MAX] = MOUNT_POINT;

    if (!key) {
        PRINT_MSG("%s\n", "NULL key!");
        return E_FAILURE;
    }

    PRINT_MSG("%s\n", key);

    strncat(path, key, ARRAY_SIZE(path) - ARRAY_SIZE(MOUNT_POINT) - 1);

    sem_lock();
    if (unlink(path) == -1 && errno != ENOENT) {
        sem_unlock();
        PRINT_MSG("Unable to unlink %s!\n", path);
        return E_FAILURE;
    }
    sem_unlock();
    return E_SUCCESS;
}

int nvram_match(const char *key, const char *val, const char *func_name) {
    if (!key) {
        PRINT_MSG("%s\n", "NULL key!");
        return E_FAILURE;
    }

    if (nvram_get_buf(key, temp, BUFFER_SIZE, func_name) != E_SUCCESS) {
        return !val ? E_SUCCESS : E_FAILURE;
    }

    PRINT_MSG("%s (%s) ?= \"%s\"\n", key, temp, val);

    if (strncmp(temp, val, BUFFER_SIZE)) {
        PRINT_MSG("%s\n", "false");
        return E_FAILURE;
    }

    PRINT_MSG("%s\n", "true");
    return E_SUCCESS;
}

int nvram_invmatch(const char *key, const char *val, const char *func_name) {
    if (!key) {
        PRINT_MSG("%s\n", "NULL key!");
        return E_FAILURE;
    }

    PRINT_MSG("%s ~?= \"%s\"\n", key, val);
    return !nvram_match(key, val, func_name);
}

int nvram_commit(void) {
    sem_lock();
    sync();
    sem_unlock();

    return E_SUCCESS;
}

// 仅删除nvram_set_default中设置的值
int nvram_clear_defaults(void) {
    const char *defaults_list = "/fa_nvram/.defaults_list";
    char key[512];
    FILE *fp;
    
    PRINT_MSG("Clearing only default NVRAM values...\n");
    
    // 检查默认值列表文件是否存在
    if (access(defaults_list, R_OK)) {
        PRINT_MSG("Defaults list file %s not found, nothing to clear!\n", defaults_list);
        return E_SUCCESS;
    }
    
    sem_lock();
    
    fp = fopen(defaults_list, "r");
    if (!fp) {
        sem_unlock();
        PRINT_MSG("Failed to open defaults list file %s!\n", defaults_list);
        return E_FAILURE;
    }
    
    // 遍历列表文件，删除每个键
    while (fgets(key, sizeof(key), fp)) {
        // 去除换行符
        char *newline = strchr(key, '\n');
        if (newline) {
            *newline = '\0';
        }
        
        // 删除键
        if (strlen(key) > 0) {
            PRINT_MSG("Removing default key: %s\n", key);
            nvram_unset(key);
        }
    }
    
    fclose(fp);
    
    // 删除列表文件和初始化标记
    unlink(defaults_list);
    unlink("/fa_nvram/.defaults_loaded");
    
    sem_unlock();
    
    PRINT_MSG("Default values cleared successfully!\n");
    return E_SUCCESS;
}

// Hack to use static variables in shared library
#include "alias.c"
