typedef struct _memory_merge       memory_merge;
typedef struct _memory_merge_list  memory_merge_list;
typedef struct _xd3_state        xd3_state;
typedef struct _main_input_memory main_input_memory;
typedef struct _main_output_memory main_output_memory;

struct _memory_merge_list
{
    memory_merge_list  *next;
    memory_merge_list  *prev;
};

struct _xd3_state
{
    /* recode_stream_global is used by both recode/merge for reading vcdiff inputs */
    xd3_stream *recode_stream;

    uint8_t*        main_bdata;
    usize_t         main_bsize;

    /* merge_stream is used by merge commands for storing the source encoding */
    xd3_stream *merge_stream;

    int         option_use_checksum;
    usize_t     option_iopt_size;
    usize_t     option_winsize;
    usize_t     option_sprevsz;
    int         flags;
};

struct _main_input_memory
{
    size_t offset;
    size_t size;
    const char *data;
};

struct _main_output_memory
{
    size_t size;
    size_t total_size;
    char *data;
};

struct _memory_merge
{
    main_input_memory input;
    memory_merge_list  link;
};

XD3_MAKELIST(memory_merge_list,memory_merge,link);

