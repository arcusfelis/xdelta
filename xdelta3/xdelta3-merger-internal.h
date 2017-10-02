
struct _xd3_merger
{
    size_t  last_input_size;
    char*   last_input_data;
    memory_merge_list merge_order;
    main_output_memory output;
    int     flags;
};


xd3_merger* xd3_merger_init(int flags)
{
    xd3_merger* merger = (xd3_merger*) main_malloc (sizeof (xd3_merger));
    merger->last_input_size = 0;
    merger->last_input_data = NULL;
    merger->output.size = 0;
    merger->output.data = NULL;
    merger->flags = flags;
    memory_merge_list_init (& merger->merge_order);
    return merger;
}

xd3_errcode xd3_merger_add_input(xd3_merger* merger, char* data, size_t size)
{
    /* put earlier added input into a merger list */
    if (merger->last_input_data != NULL)
    {
       memory_merge* merge = (memory_merge*) main_malloc (sizeof (memory_merge));
       merge->input.data = merger->last_input_data;
       merge->input.size = merger->last_input_size;
       merge->input.offset = 0;
       memory_merge_list_push_back (& merger->merge_order, merge);
    }

    merger->last_input_data = data;
    merger->last_input_size = size;

    return 0;
}

xd3_errcode xd3_merger_run(xd3_merger* merger)
{
    xd3_errcode err = 0;
    xd3_state state_struct;
    main_input_memory last_input;
    xd3_state* state;

    state = &state_struct;

    state->recode_stream = NULL;
    state->main_bdata = NULL;
    state->main_bsize = 0;
    state->merge_stream = NULL;
    state->flags = 0;
    state_reset(state);
    state->flags = merger->flags;

    merger->output.size = 0;
    merger->output.total_size = 1000000;
    merger->output.data = malloc(merger->output.total_size);

    last_input.offset = 0;
    last_input.size = merger->last_input_size;
    last_input.data = merger->last_input_data;

    err = memory_merge_arguments (& merger->merge_order, state);

    if (!err)
        err = handle_memory_input1 (& last_input, & merger->output, state);

    state_cleanup (state);
    return err;
}

size_t xd3_merger_get_output_size(xd3_merger* merger)
{
    return merger->output.size;
}

char* xd3_merger_get_output_data(xd3_merger* merger)
{
    return merger->output.data;
}

xd3_errcode xd3_merger_clean(xd3_merger* merger)
{
    memory_merge* merge;
    while (! memory_merge_list_empty (& merger->merge_order))
    {
        merge = memory_merge_list_pop_front (& merger->merge_order);
        main_free (merge);
    }
    if (merger->output.data)
       free(merger->output.data);
    main_free(merger);
    return 0;
}
