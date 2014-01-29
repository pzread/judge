#define FOG_CONT_UID 2147483647
#define FOG_CONT_GID 2147483647

struct cont_stat{
    unsigned long utime;
    unsigned long stime;
    unsigned long memory;
};

int fog_init(void);
int fog_cont_alloc(const char *snap,unsigned long memlimit);
int fog_cont_free(int id);
int fog_cont_attach(int id);
int fog_cont_stat(int id,struct cont_stat *stat);
