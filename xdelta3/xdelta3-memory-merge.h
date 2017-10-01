static int handle_memory_input1 (main_input_memory *input, main_output_memory  *output, xd3_state* state);

static int handle_memory_input2 ( main_input_memory* input_memory, xd3_state* state);

static void state_reset (xd3_state* state);
static void state_cleanup (xd3_state* state);

static usize_t memory_get_winsize (size_t data_size, size_t option_winsize);


static int
memory_read_primary_input (main_input_memory* merge,
        uint8_t     *buf,
        size_t       size,
        size_t      *nread);
static int state_init_recode_stream (xd3_state* state);
static int memory_merge_arguments (memory_merge_list* merges, xd3_state* state);
static int memory_merge_output (xd3_stream *stream, main_output_memory *output, xd3_state* state);


static int memory_write_output (xd3_stream* stream, main_output_memory *output);
int memory_file_write (main_output_memory *output, uint8_t *buf, usize_t size, const char *msg);
