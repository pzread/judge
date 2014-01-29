#ifndef _IO_H
#define _IO_H

#define IO_POST(x) ((x)->post_handler((x)))
#define IO_EXEC(x) ((x)->exec_handler((x)))
#define IO_FREE(x) {int (*free_handler)(struct io_header *iohdr);   \
                    free_handler = (x)->free_handler; \
                    free_handler((x));}
#define IO_END(x,s) ((x)->end_handler((x)->end_data,(s)))

struct io_header{
    int (*post_handler)(struct io_header *iohdr);
    int (*exec_handler)(struct io_header *iohdr);
    int (*free_handler)(struct io_header *iohdr);

    void (*end_handler)(void *end_data,int status);
    void *end_data;
};

struct io_header* io_stdfile_alloc(const char *in_path,const char *ans_path);

#endif
