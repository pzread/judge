typedef int (*check_init_fn)(char *abspath,void **data);
typedef int (*check_post_fn)(void *data);
typedef int (*check_clean_fn)(void *data);

struct line_setting_info{
    unsigned long timelimit;
    unsigned long memlimit;
    int count;
    int score[JUDGX_LINE_RESULTMAX];
};

static void line_ini_handler(void *data,char *section,char *key,char *value);

DLL_PUBLIC int run(struct judgx_line_info *line_info);
