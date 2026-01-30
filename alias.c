#ifndef INCLUDE_ALIAS_C
#define INCLUDE_ALIAS_C

/* Aliased base functions */

int true() {
    return E_SUCCESS;
}

int false() {
    return E_FAILURE;
}

int nvram_load(void) __attribute__ ((alias ("nvram_init")));
int nvram_loaddefault(void) __attribute__ ((alias ("nvram_set_default")));
char *_nvram_get(const char *key){
    return nvram_get(key, "_nvram_get", 1);
}
int nvram_get_state(const char *key) {
    return nvram_get_int(key, "nvram_get_state");
}
int nvram_set_state(const char *key, const int val) __attribute__ ((alias ("nvram_set_int")));
int nvram_restore_default(void) __attribute__ ((alias ("nvram_reset")));
int nvram_upgrade(void* ptr) __attribute__ ((alias ("nvram_commit")));

/* Atheros/Broadcom NVRAM */

int nvram_get_nvramspace(void) {
    return NVRAM_SIZE;
}

// 从NVRAM配置文件中读取所有键值对，按=分隔key和val，调用nvram_set处理每个键值对
int foreach_nvram_from(const char *file, void (*fp)(const char *, const char *, void *), void *data) {
    char *key, *val, *tmp;
    FILE *f;

    if (!fp) {
        PRINT_MSG("%s\n", "NULL function pointer!");
        return E_FAILURE;
    }

    if ((f = fopen(file, "r")) == NULL) {
        PRINT_MSG("Unable to open file: %s!\n", file);
        return E_FAILURE;
    }

    while (fgets(temp, BUFFER_SIZE, f) == temp) {
        if (!(val = strchr(temp, '='))) {
            continue;
        }

        key = temp;
        while (*key == ' ' || *key == '\t') key++;

        *val = '\0';
        val += 1;

        tmp = val - 1;
        while (tmp > key && (*(tmp - 1) == ' ' || *(tmp - 1) == '\t')) {
            *(tmp - 1) = '\0';
            tmp--;
        }

        while (*val == ' ' || *val == '\t') val++;

        if ((tmp = strchr(val, '\n')) != NULL) {
            while (tmp > val && (*(tmp - 1) == ' ' || *(tmp - 1) == '\t')) {
                tmp--;
            }
            *tmp = '\0';
        }

        if (data) {
            fp(key, val, data);
        }
        else {
            ((void (*)(const char *, const char *)) fp)(key, val);
        }
    }

    fclose(f);
    return E_SUCCESS;
}

char *nvram_nget(const char *fmt, ...) {
    va_list va;

    va_start(va, fmt);
    vsnprintf(temp, BUFFER_SIZE, fmt, va);
    va_end(va);

    return nvram_get(temp, "nvram_nget", 1);
}

int nvram_nset(const char *val, const char *fmt, ...) {
    va_list va;

    va_start(va, fmt);
    vsnprintf(temp, BUFFER_SIZE, fmt, va);
    va_end(va);

    return nvram_set(temp, val);
}

int nvram_nset_int(const int val, const char *fmt, ...) {
    va_list va;

    va_start(va, fmt);
    vsnprintf(temp, BUFFER_SIZE, fmt, va);
    va_end(va);

    return nvram_set_int(temp, val);
}

int nvram_nmatch(const char *val, const char *fmt, ...) {
    va_list va;

    va_start(va, fmt);
    vsnprintf(temp, BUFFER_SIZE, fmt, va);
    va_end(va);

    return nvram_match(temp, val, "nvram_nmatch");
}

int get_default_mac() __attribute__ ((alias ("true")));

/* D-Link */

char *artblock_get(const char *key){
    return nvram_get(key, "artblock_get", 1);
}
char *artblock_fast_get(const char *key){
    return nvram_safe_get(key, "artblock_fast_get");
}
char *artblock_safe_get(const char *key){
    return nvram_safe_get(key, "artblock_safe_get");
}
int artblock_set(const char *key, const char *val) __attribute__ ((alias ("nvram_set")));
int nvram_flag_set(int unk) __attribute__ ((alias ("true")));
int nvram_flag_reset(int unk) __attribute__ ((alias ("true")));

/* D-Link ARM */
int nvram_master_init() __attribute__ ((alias ("false")));
int nvram_slave_init() __attribute__ ((alias ("false")));

/* Realtek */
// These functions expect integer keys, so we convert to string first.
// Unfortunately, this implementation is not entirely correct because some
// values are integers and others are string, but we treat all as integers.
// DIR_600L_REVA_FIRMWARE_1.14情况增强
int pWizMib;
int apmib_init(){
    int *WizMib = malloc(2048);
    memset(WizMib, 0, 2048);
    WizMib[0] = 1;
    pWizMib = (int)&WizMib;
    return E_SUCCESS;
}
int apmib_reinit() __attribute__ ((alias ("true")));
int apmib_read_boot_version(int)  __attribute__ ((alias ("true")));
int apmib_updateFlash(int, int, int, int, int, int)  __attribute__ ((alias ("true")));
// int apmib_hwconf() __attribute__ ((alias ("true")));
// int apmib_dsconf() __attribute__ ((alias ("true")));
// int apmib_load_hwconf() __attribute__ ((alias ("true")));
// int apmib_load_dsconf() __attribute__ ((alias ("true")));
// int apmib_load_csconf() __attribute__ ((alias ("true")));
int apmib_update(const int key) __attribute__((alias ("true")));

// TODO:更新apmib系列函数
enum nvram_value_type {
    NVRAM_TYPE_BOOL = 0,
    NVRAM_TYPE_CHAR = 1,
    NVRAM_TYPE_SHORT = 2,
    NVRAM_TYPE_INT = 3,
    NVRAM_TYPE_LONG_LONG = 4
};
// 存储的是字符串，返回值中前几位是存储值的类型，占1字节
int apmib_get(const int key, void *buf) {
    const char *res;
    int type;          // 第1字节为类型标记
    int ival;
    short sval;
    long long llval;
    char *endptr;

    snprintf(temp, BUFFER_SIZE, "%d", key);
    res = nvram_get(temp, "apmib_get", 1);

    if (!res) return 0;
    if (*res == '\0'){
        strcpy((char *)buf, "");
        return 1;
    }

    type = res[0] - '0';      // 取首字节判断存储类型
    switch (type) {
    case NVRAM_TYPE_BOOL:
        ival = (res[1] != '\0');   // 非'0'即真
        memcpy(buf, &ival, sizeof(char));
        break;

    case NVRAM_TYPE_INT:
        ival = (int)strtol(res + 1, &endptr, 10);
        memcpy(buf, &ival, sizeof(int));
        break;

    case NVRAM_TYPE_SHORT:
        sval = (short)strtol(res + 1, &endptr, 10);
        memcpy(buf, &sval, sizeof(short));
        break;

    case NVRAM_TYPE_LONG_LONG:
        llval = strtoll(res + 1, &endptr, 10);
        memcpy(buf, &llval, sizeof(long long));
        break;

    case NVRAM_TYPE_CHAR:
    default:
        strcpy((char *)buf, res + 1);
        break;
    }
    return 1;
}
int apmib_getDef(const int key, void *buf){
    const char *res;
    int type;          // 第1字节为类型标记
    int ival;
    short sval;
    long long llval;
    char *endptr;

    snprintf(temp, BUFFER_SIZE, "%d", key);
    res = nvram_get(temp, "apmib_getDef", 1);

    if (!res) return 0;

    type = res[0] - '0';      // 取首字节判断存储类型
    switch (type) {
    case NVRAM_TYPE_BOOL:
        ival = (res[1] != '\0');   // 非'0'即真
        memcpy(buf, &ival, sizeof(char));
        break;

    case NVRAM_TYPE_SHORT:
        sval = (short)strtol(res + 1, &endptr, 10);
        memcpy(buf, &sval, sizeof(short));
        break;

    case NVRAM_TYPE_INT:
        ival = (int)strtol(res + 1, &endptr, 10);
        memcpy(buf, &ival, sizeof(int));
        break;

    case NVRAM_TYPE_LONG_LONG:
        llval = strtoll(res + 1, &endptr, 10);
        memcpy(buf, &llval, sizeof(long long));
        break;

    case NVRAM_TYPE_CHAR:
    default:
        strcpy((char *)buf, res + 1);
        break;
    }
    return 1;
}

int apmib_set(const int key, void *buf) {
    memset(temp, 0, sizeof(temp));
    snprintf(temp, BUFFER_SIZE, "%d", key);
    // 调用脚本，根据返回值决定 buf 的真实类型
    char cmd[1024];
    char type_buf[8] = {0};
    FILE *pp;

    // 检查连续LLM超时计数，如果达到5次则跳过LLM逻辑
    if (llm_timeout_count >= MAX_LLM_TIMEOUT_COUNT) {
        fprintf(stderr, "LLM has timed out %d times consecutively, skipping LLM for this call!\n", llm_timeout_count);
        strcpy(type_buf, "1");
        goto cleanup;
    }

    const char *COMMUNICATION_FILE = "/msg_nvram.txt";
    const char *LOCK_FILE = "/msg_nvram.lock";
    const char *REPLY_FILE = "/msg_nvram_reply.txt";
    const int MAX_WAIT_COUNT = 20;
    const int MAX_WAIT_REPLY = 20;
    int WAIT_COUNT = 0;
    int WAIT_REPLY_COUNT = 0;
    FILE *fp;
    
    while (access(LOCK_FILE, F_OK) == 0) {
        if (WAIT_COUNT >= MAX_WAIT_COUNT) {
            strcpy(type_buf, "1");
            llm_timeout_count++;
            fprintf(stderr, "LLM lock file wait timeout! Consecutive timeout count: %d\n", llm_timeout_count);
            goto cleanup;
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
    remove(REPLY_FILE);
    
    char MESSAGE[256];
    snprintf(MESSAGE, sizeof(MESSAGE), "--nvram_function_name %s --key %s", "apmib_set", temp);
    
    fp = fopen(COMMUNICATION_FILE, "w");
    if (fp != NULL) {
        fprintf(fp, "%s", MESSAGE);
        fclose(fp);
    }
    
    remove(LOCK_FILE);
    
    while (access(REPLY_FILE, F_OK) != 0) {
        if (WAIT_REPLY_COUNT >= MAX_WAIT_REPLY) {
            fprintf(stderr, "error: timeout waiting for reply\n");
            strcpy(type_buf, "1");
            llm_timeout_count++;
            fprintf(stderr, "LLM reply file wait timeout! Consecutive timeout count: %d\n", llm_timeout_count);
            goto cleanup;
        }
        WAIT_REPLY_COUNT++;
        sleep(1);
    }
    
    fp = fopen(REPLY_FILE, "r");
    if (fp != NULL) {
        if (fgets(type_buf, sizeof(type_buf), fp)) {
            type_buf[strcspn(type_buf, "\r\n")] = 0;
            // LLM成功返回结果，重置超时计数
            llm_timeout_count = 0;
        } else {
            strcpy(type_buf, "1");
        }
        fclose(fp);
    } else {
        strcpy(type_buf, "1");
    }
    
    remove(REPLY_FILE);
    
cleanup:

    /* 构造带类型前缀的 value 字符串 */
    if (strcmp(type_buf, "0") == 0) {
        char bval = *(char *)buf;
        snprintf(temp, BUFFER_SIZE, "0%c", bval);
    }  else if (strcmp(type_buf, "2") == 0) {
        short sval = *(short *)buf;
        snprintf(temp, BUFFER_SIZE, "2%hd", sval);
    } else if (strcmp(type_buf, "3") == 0) {
        int ival = *(int *)buf;
        snprintf(temp, BUFFER_SIZE, "3%d", ival);
    } else if (strcmp(type_buf, "4") == 0) {
        long long llval = *(long long *)buf;
        snprintf(temp, BUFFER_SIZE, "4%lld", llval);
    } else {
        snprintf(temp, BUFFER_SIZE, "1%s", (char *)buf);
    }
    return nvram_set(temp, (const char *)buf);
}

/* Netgear ACOS */

int WAN_ith_CONFIG_GET(char *buf, const char *fmt, ...) {
    va_list va;

    va_start(va, fmt);
    vsnprintf(temp, BUFFER_SIZE, fmt, va);
    va_end(va);

    return nvram_get_buf(temp, buf, USER_BUFFER_SIZE, "WAN_ith_CONFIG_GET");
}

int WAN_ith_CONFIG_SET_AS_STR(const char *val, const char *fmt, ...) __attribute__ ((alias ("nvram_nset")));

int WAN_ith_CONFIG_SET_AS_INT(const int val, const char *fmt, ...) __attribute__ ((alias ("nvram_nset_int")));

int acos_nvram_init(void) __attribute__ ((alias ("nvram_init")));
char *acos_nvram_get(const char *key){
    return nvram_get(key, "acos_nvram_get", 1);
}
int acos_nvram_read (const char *key, char *buf, size_t sz){
    return nvram_get_buf(key, buf, sz, "acos_nvram_read");
}
int acos_nvram_set(const char *key, const char *val) __attribute__ ((alias ("nvram_set")));
int acos_nvram_loaddefault(void) __attribute__ ((alias ("nvram_set_default")));
int acos_nvram_unset(const char *key) __attribute__ ((alias ("nvram_unset")));
int acos_nvram_commit(void) __attribute__ ((alias ("nvram_commit")));

int acosNvramConfig_init(char *mount) __attribute__ ((alias ("nvram_init")));
char *acosNvramConfig_exist(const char *key){
    return nvram_get(key, "acosNvramConfig_exist", 1);
}
char *acosNvramConfig_get(const char *key){
    return nvram_get(key, "acosNvramConfig_get", 1);
}
int acosNvramConfig_read(const char *key, char *buf, size_t sz){
    return nvram_get_buf(key, buf, sz, "acosNvramConfig_read");
}
int acosNvramConfig_set(const char *key, const char *val) __attribute__ ((alias ("nvram_set")));
int acosNvramConfig_write(const char *key, const char *val) __attribute__ ((alias ("nvram_set")));
int acosNvramConfig_unset(const char *key) __attribute__ ((alias ("nvram_unset")));
int acosNvramConfig_match(const char *key, const char *val){
    return nvram_match(key, val, "acosNvramConfig_match");
}
int acosNvramConfig_invmatch(const char *key, const char *val){
    return nvram_invmatch(key, val, "acosNvramConfig_invmatch");
}
int acosNvramConfig_save(void) __attribute__ ((alias ("nvram_commit")));
int acosNvramConfig_save_config(void) __attribute__ ((alias ("nvram_commit")));
int acosNvramConfig_loadFactoryDefault(const char* key);
int acosNvramConfig_readAsInt(char *key, int *val){
    int v = nvram_get_int(key, "acosNvramConfig_readAsInt");
    *val = v;
    return E_SUCCESS;
}
int acosNvramConfig_writeAsInt(char *k, int *r){
    return nvram_set_int(k, *r);
}

/* ZyXel / Edimax */
// many functions expect the opposite return values: (0) success, failure (1/-1)

int nvram_getall_adv(int unk, char *buf, size_t len) {
    return nvram_getall(buf, len) == E_SUCCESS ? E_FAILURE : E_SUCCESS;
}

char *nvram_get_adv(int unk, const char *key) {
    return nvram_get(key, "nvram_get_adv", 1);
}

int nvram_set_adv(int unk, const char *key, const char *val) {
    return nvram_set(key, val);
}

int nvram_commit_adv(int) __attribute__ ((alias ("nvram_commit")));
int nvram_unlock_adv(int) __attribute__ ((alias ("true")));
int nvram_lock_adv(int) __attribute__ ((alias ("true")));
int nvram_check(void) __attribute__ ((alias ("true")));

int nvram_state(int unk1, void *unk2, void *unk3) {
    return E_FAILURE;
}

int envram_commit(void) {
    return !nvram_commit();
}

int envram_default(void) {
    return !nvram_set_default();
}

int envram_load(void)  {
    return !nvram_init();
}

int envram_safe_load(void)  {
    return !nvram_init();
}

int envram_match(const char *key, const char *val)  {
    return !nvram_match(key, val, "envram_match");
}

int envram_get(const char* key, char *buf) {
    // may be incorrect
    return !nvram_get_buf(key, buf, USER_BUFFER_SIZE, "envram_get");
}
int envram_get_func(const char* key, char *buf){
    return !nvram_get_buf(key, buf, USER_BUFFER_SIZE, "envram_get_func");
} 
int envram_getf(const char* key, const char *fmt, ...) {
    va_list va;
    char *val = nvram_get(key, "envram_getf", 1);

    if (!val) {
        return E_FAILURE;
    }

    va_start(va, fmt);
    int ret = vsscanf(val, fmt, va);
    va_end(va);

    free(val);
    return ret == 0 ? E_FAILURE : E_SUCCESS;
}
int nvram_getf(const char* key, const char *fmt, ...){
    va_list va;
    char *val = nvram_get(key, "nvram_getf", 1);

    if (!val) {
        return E_FAILURE;
    }

    va_start(va, fmt);
    int ret = vsscanf(val, fmt, va);
    va_end(va);

    free(val);
    return ret == 0 ? E_FAILURE : E_SUCCESS;
}

int envram_set(const char *key, const char *val) {
    return !nvram_set(key, val);
}
int envram_set_func(const char *key, const char *val) __attribute__ ((alias ("envram_set")));

int envram_setf(const char* key, const char* fmt, ...) {
    va_list va;

    va_start(va, fmt);
    vsnprintf(temp, BUFFER_SIZE, fmt, va);
    va_end(va);

    return !nvram_set(key, temp);
}
int nvram_setf(const char* key, const char* fmt, ...) __attribute__ ((alias ("envram_setf")));

int envram_unset(const char *key) {
    return !nvram_unset(key);
}
int envram_unset_func(void) __attribute__ ((alias ("envram_unset")));

/* Ralink */

char *nvram_bufget(int idx, const char *key) {
    return nvram_safe_get(key, "nvram_bufget");
}

int nvram_bufset(int idx, const char *key, const char *val) {
    return nvram_set(key, val);
}

int isspace(int c)
{
  return c == 32 || c == 10 || c == 9;
}

char *rstrip(char *s)
{
  char *p; // [sp+18h] [+18h]

  for ( p = &s[strlen(s)]; s < p; *p = 0 )
  {
    if ( !isspace((unsigned char)*--p) )
      break;
  }
  return s;
}

char *lskip(const char *s)
{
  while ( *s && isspace(*(unsigned char *)s) )
    ++s;
  return (char *)s;
}

char *find_char_or_comment(const char *s, char c)
{
  int was_whitespace;

  for ( was_whitespace = 0;
        *s && c != *s && (!was_whitespace || *s != 59);
        was_whitespace = isspace(*(unsigned char *)s++) )
  {
    ;
  }
  return (char *)s;
}

char *strncpy0(char *dest, const char *src, size_t size)
{
  strncpy(dest, src, size);
  dest[size - 1] = 0;
  return dest;
}

int ini_parse_file(FILE *file, int (*handler)(void *, const char *, const char *, const char *), void *user)
{
  char *v4;
  char *start;
  char *starta;
  char *end;
  char *enda;
  char *endb;
  int lineno;
  int error;
  char *line;
  const char *name;
  char *value;
  char section[50];
  char prev_name[50]; 

  memset(section, 0, sizeof(section));
  memset(prev_name, 0, sizeof(prev_name));
  lineno = 0;
  error = 0;
  line = (char *)malloc(2000);
  if ( !line )
    return -2;
  while ( fgets(line, 2000, file) )
  {
    ++lineno;
    start = line;
    if ( lineno == 1 && *line == -17 && line[1] == -69 && line[2] == -65 )
      start = line + 3;
    v4 = rstrip(start);
    starta = lskip(v4);
    if ( *starta != 59 && *starta != 35 )
    {
      if ( prev_name[0] && *starta && line < starta )
      {
        if ( !handler(user, section, prev_name, starta) && !error )
          error = lineno;
      }
      else if ( *starta == 91 )
      {
        end = find_char_or_comment(starta + 1, 93);
        if ( *end == 93 )
        {
          *end = 0;
          strncpy0(section, starta + 1, 0x32u);
          prev_name[0] = 0;
        }
        else if ( !error )
        {
          error = lineno;
        }
      }
      else if ( *starta && *starta != 59 )
      {
        enda = find_char_or_comment(starta, 61);
        if ( *enda != 61 )
          enda = find_char_or_comment(starta, 58);
        if ( *enda == 61 || *enda == 58 )
        {
          *enda = 0;
          name = rstrip(starta);
          value = lskip(enda + 1);
          endb = find_char_or_comment(value, 0);
          if ( *endb == 59 )
            *endb = 0;
          rstrip(value);
          strncpy0(prev_name, name, 0x32u);
          if ( !handler(user, section, name, value) && !error )
            error = lineno;
        }
        else if ( !error )
        {
          error = lineno;
        }
      }
    }
  }
  free(line);
  return error;
}

int ini_parse(const char *filename, int (*handler)(void *, const char *, const char *, const char *), void *user){
  FILE *file; // [sp+18h] [+18h]
  int error; // [sp+1Ch] [+1Ch]

  file = fopen(filename, "r");
  if ( !file )
    return -1;
  error = ini_parse_file(file, handler, user);
  fclose(file);
  return error;
}

#endif
