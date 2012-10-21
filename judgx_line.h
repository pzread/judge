#define JUDGX_LINE_RESULTMAX 64

struct judgx_line_result{
    int status;
    int score;
    int maxscore;
    unsigned long runtime;
    unsigned long peakmem;
};
struct judgx_line_info{
    char pro_path[PATH_MAX + 1];
    char cpp_path[PATH_MAX + 1];
    char exe_path[PATH_MAX + 1];
    FILE *set_file;
    void *line_dll;
    void *check_dll;

    int result_count;
    struct judgx_line_result result[JUDGX_LINE_RESULTMAX];
};
