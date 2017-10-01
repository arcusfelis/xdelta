/* opaque */
struct _xd3_merger;
typedef struct _xd3_merger xd3_merger;
/* 0 - success */
typedef unsigned int xd3_errcode;

/* returns NULL if error */
xd3_merger* xd3_merger_init();
xd3_errcode xd3_merger_add_input(xd3_merger* merger, char* data, size_t size);
xd3_errcode xd3_merger_run(xd3_merger* merger);
size_t xd3_merger_get_output_size(xd3_merger* merger);
char* xd3_merger_get_output_data(xd3_merger* merger);
xd3_errcode xd3_merger_clean(xd3_merger* merger);

