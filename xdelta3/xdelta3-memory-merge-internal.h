    static int
handle_memory_input1 (
        main_input_memory   *input,
        main_output_memory  *output,
        xd3_state*   state)
{
    int        ret;
    xd3_stream stream;
    size_t     nread = 0;
    usize_t    winsize;
    int        stream_flags = 0;
    xd3_config config;
    xd3_source source;
    int (*input_func) (xd3_stream*);

    memset (& stream, 0, sizeof (stream));
    memset (& source, 0, sizeof (source));
    memset (& config, 0, sizeof (config));

    config.alloc = main_alloc;
    config.freef = main_free1;

    config.iopt_size = state->option_iopt_size;
    config.sprevsz = state->option_sprevsz;

    do_src_fifo = 0;

    if (state->option_use_checksum) { stream_flags |= XD3_ADLER32; }

    /* No source will be read */
    stream_flags |= XD3_ADLER32_NOVER | XD3_SKIP_EMIT;
    input_func = xd3_decode_input;

    if ((ret = state_init_recode_stream (state)))
    {
        return EXIT_FAILURE;
    }

    state->main_bsize = winsize = memory_get_winsize (input->size, state->option_winsize);


    if ((state->main_bdata = (uint8_t*) main_bufalloc (winsize)) == NULL)
    {
        return EXIT_FAILURE;
    }

    config.winsize = winsize;
    config.getblk = NULL;
    config.flags = stream_flags;

    if ((ret = xd3_config_stream (& stream, & config)))
    {
        XPR(NT XD3_LIB_ERRMSG (& stream, ret));
        return EXIT_FAILURE;
    }

    if ((ret = xd3_whole_state_init (& stream)))
    {
        XPR(NT XD3_LIB_ERRMSG (& stream, ret));
        return EXIT_FAILURE;
    }

    /* Main input loop. */
    do
    {
        xoff_t input_offset;
        xoff_t input_remain;
        usize_t try_read;

        input_offset = input->offset;

        input_remain = XOFF_T_MAX - input_offset;

        try_read = (usize_t) xd3_min ((xoff_t) config.winsize, input_remain);

        if ((ret = memory_read_primary_input (input, state->main_bdata,
                        try_read, & nread)))

        {
            return EXIT_FAILURE;
        }

        /* If we've reached EOF tell the stream to flush. */
        if (nread < try_read)
        {
            stream.flags |= XD3_FLUSH;
        }

        xd3_avail_input (& stream, state->main_bdata, nread);

        /* If we read zero bytes after encoding at least one window... */
        if (nread == 0 && stream.current_window > 0) {
            break;
        }

again:

        ret = input_func (& stream);

        switch (ret)
        {
            case XD3_INPUT:
                continue;

            case XD3_GOTHEADER:
                {
                    XD3_ASSERT (stream.current_window == 0);
                }
                /* FALLTHROUGH */
            case XD3_WINSTART:
                {
                    /* e.g., set or unset XD3_SKIP_WINDOW. */
                    goto again;
                }

            case XD3_OUTPUT:
                {
                    if ((ret = xd3_whole_append_window (& stream)) &&
                            (ret != PRINTHDR_SPECIAL))
                    {
                        return EXIT_FAILURE;
                    }

                    if (ret == PRINTHDR_SPECIAL)
                    {
                        xd3_abort_stream (& stream);
                        ret = EXIT_SUCCESS;
                        goto done;
                    }

                    ret = 0;

                    xd3_consume_output (& stream);
                    goto again;
                }

            case XD3_WINFINISH:
                {
                    goto again;
                }

            default:
                /* input_func() error */
                XPR(NT XD3_LIB_ERRMSG (& stream, ret));
                return EXIT_FAILURE;
        }
    }
    while (nread == config.winsize);
done:

    if ((ret = memory_merge_output (& stream, output, state)))
    {
        return EXIT_FAILURE;
    }

    if ((ret = xd3_close_stream (& stream)))
    {
        XPR(NT XD3_LIB_ERRMSG (& stream, ret));
        return EXIT_FAILURE;
    }

    xd3_free_stream (& stream);

    return EXIT_SUCCESS;
}


    static int
handle_memory_input2 ( main_input_memory* input_memory, xd3_state* state)
{
    int        ret;
    xd3_stream stream;
    size_t     nread = 0;
    usize_t    winsize;
    int        stream_flags = 0;
    xd3_config config;
    xd3_source source;
    int (*input_func) (xd3_stream*);

    memset (& stream, 0, sizeof (stream));
    memset (& source, 0, sizeof (source));
    memset (& config, 0, sizeof (config));

    config.alloc = main_alloc;
    config.freef = main_free1;

    config.iopt_size = state->option_iopt_size;
    config.sprevsz = state->option_sprevsz;

    do_src_fifo = 0;

    if (option_use_checksum) { stream_flags |= XD3_ADLER32; }

    /* No source will be read */
    stream_flags |= XD3_ADLER32_NOVER | XD3_SKIP_EMIT;
    input_func = xd3_decode_input;

    if ((ret = state_init_recode_stream (state)))
    {
        return EXIT_FAILURE;
    }

    state->main_bsize = winsize = memory_get_winsize (input_memory->size, state->option_winsize);

    if ((state->main_bdata = (uint8_t*) main_bufalloc (winsize)) == NULL)
    {
        return EXIT_FAILURE;
    }

    config.winsize = winsize;
    config.getblk = NULL;
    config.flags = stream_flags;

    if ((ret = xd3_config_stream (& stream, & config)))
    {
        XPR(NT XD3_LIB_ERRMSG (& stream, ret));
        return EXIT_FAILURE;
    }

    if ((ret = xd3_whole_state_init (& stream)))
    {
        XPR(NT XD3_LIB_ERRMSG (& stream, ret));
        return EXIT_FAILURE;
    }

    /* Main input loop. */
    do
    {
        xoff_t input_offset;
        xoff_t input_remain;
        usize_t try_read;

        input_offset = input_memory->offset;

        input_remain = XOFF_T_MAX - input_offset;

        try_read = (usize_t) xd3_min ((xoff_t) config.winsize, input_remain);

        if ((ret = memory_read_primary_input (input_memory, state->main_bdata,
                        try_read, & nread)))
        {
            return EXIT_FAILURE;
        }

        /* If we've reached EOF tell the stream to flush. */
        if (nread < try_read)
        {
            stream.flags |= XD3_FLUSH;
        }

        xd3_avail_input (& stream, state->main_bdata, nread);

        /* If we read zero bytes after encoding at least one window... */
        if (nread == 0 && stream.current_window > 0) {
            break;
        }

again:
        ret = input_func (& stream);

        switch (ret)
        {
            case XD3_INPUT:
                continue;

            case XD3_GOTHEADER:
                {
                    XD3_ASSERT (stream.current_window == 0);
                }
                /* FALLTHROUGH */
            case XD3_WINSTART:
                {
                    /* e.g., set or unset XD3_SKIP_WINDOW. */
                    goto again;
                }

            case XD3_OUTPUT:
                {


                    if ((ret = xd3_whole_append_window (& stream)) &&
                            (ret != PRINTHDR_SPECIAL))
                    {
                        return EXIT_FAILURE;
                    }

                    if (ret == PRINTHDR_SPECIAL)
                    {
                        xd3_abort_stream (& stream);
                        ret = EXIT_SUCCESS;
                        goto done;
                    }

                    ret = 0;

                    xd3_consume_output (& stream);
                    goto again;
                }

            case XD3_WINFINISH:
                {
                    goto again;
                }

            default:
                /* input_func() error */
                XPR(NT XD3_LIB_ERRMSG (& stream, ret));
                return EXIT_FAILURE;
        }
    }
    while (nread == config.winsize);
done:

        xd3_swap_whole_state (& stream.whole_target,
                & state->recode_stream->whole_target);


    if ((ret = xd3_close_stream (& stream)))
    {
        XPR(NT XD3_LIB_ERRMSG (& stream, ret));
        return EXIT_FAILURE;
    }

    xd3_free_stream (& stream);

    return EXIT_SUCCESS;
}

/* free memory before exit, reset single-use variables. */
    static void
state_cleanup (xd3_state* state)
{
    main_buffree (state->main_bdata);
    state->main_bdata = NULL;
    state->main_bsize = 0;

    main_lru_cleanup();

    if (state->recode_stream != NULL)
    {
        xd3_free_stream (state->recode_stream);
        main_free (state->recode_stream);
        state->recode_stream = NULL;
    }

    if (state->merge_stream != NULL)
    {
        xd3_free_stream (state->merge_stream);
        main_free (state->merge_stream);
        state->merge_stream = NULL;
    }
}

static usize_t
memory_get_winsize (size_t data_size, size_t winsize) {
    usize_t size = winsize;

    size = (usize_t) xd3_min (data_size, (xoff_t) size);
    size = xd3_max (size, XD3_ALLOCSIZE);

    return size;
}

static int
memory_read_primary_input (main_input_memory* merge,
        uint8_t     *buf,
        size_t       size,
        size_t      *nread)
{
    size_t available = merge->size - merge->offset;
    size_t length;

    if (available < size)
        length = available;
    else
        length = size;

    memcpy(buf, merge->data + merge->offset, length);

    merge->offset += length;
    (*nread) = length;

    return 0;
}









/* Modifies static state. */
    static int
state_init_recode_stream (xd3_state* state)
{
    int ret;
    int stream_flags = XD3_ADLER32_NOVER | XD3_SKIP_EMIT;
    int recode_flags;
    xd3_config recode_config;

    XD3_ASSERT (state->recode_stream == NULL);

    if ((state->recode_stream = (xd3_stream*) main_malloc(sizeof(xd3_stream))) == NULL)
    {
        return ENOMEM;
    }

    recode_flags = (stream_flags & state->flags);
//  recode_flags = (stream_flags & XD3_SEC_TYPE);

    recode_config.alloc = main_alloc;
    recode_config.freef = main_free1;

    xd3_init_config(&recode_config, recode_flags);

    if ((ret = xd3_config_stream (state->recode_stream, &recode_config)) ||
            (ret = xd3_encode_init_partial (state->recode_stream)) ||
            (ret = xd3_whole_state_init (state->recode_stream)))
    {
        XPR(NT XD3_LIB_ERRMSG (state->recode_stream, ret));
        xd3_free_stream (state->recode_stream);
        state->recode_stream = NULL;
        return ret;
    }

    return 0;
}



/* This processes the sequence of -m arguments.  The final input
 * is processed as part of the ordinary main_input() loop. */
    static int
memory_merge_arguments (memory_merge_list* merges, xd3_state* state)
{
    int ret = 0;
    int count = 0;
    memory_merge *merge = NULL;
    xd3_stream merge_input;

    if (memory_merge_list_empty (merges))
    {
        return 0;
    }

    if ((ret = xd3_config_stream (& merge_input, NULL)) ||
            (ret = xd3_whole_state_init (& merge_input)))
    {
        XPR(NT XD3_LIB_ERRMSG (& merge_input, ret));
        return ret;
    }

    // run for each delta
    // version1-version2.delta
    // version2-version3.delta
    // version3-version4.delta
    // But don't run for the last one!
    // version4-version5.delta (not inside memory_merge_list)
    merge = memory_merge_list_front (merges);
    while (!memory_merge_list_end (merges, merge))

    {
        // copy delta into stream
        ret = handle_memory_input2 (& merge->input, state);

        if (ret == 0)
        {
            if (count++ == 0)
            {
                /* The first merge source is the next merge input. */
                xd3_swap_whole_state (& state->recode_stream->whole_target,
                        & merge_input.whole_target);
            }
            else
            {
                /* Merge the recode_stream with merge_input. */
                ret = xd3_merge_input_output (state->recode_stream,
                        & merge_input.whole_target);

                /* Save the next merge source in merge_input. */
                xd3_swap_whole_state (& state->recode_stream->whole_target,
                        & merge_input.whole_target);
            }
        }

        if (state->recode_stream != NULL)
        {
            xd3_free_stream (state->recode_stream);
            main_free (state->recode_stream);
            state->recode_stream = NULL;
        }

        if (state->main_bdata != NULL)
        {
            main_buffree (state->main_bdata);
            state->main_bdata = NULL;
            state->main_bsize = 0;
        }

        if (ret != 0)
        {
            goto error;
        }

        merge = memory_merge_list_next (merge);
    }

    XD3_ASSERT (state->merge_stream == NULL);

    if ((state->merge_stream = (xd3_stream*) main_malloc (sizeof(xd3_stream))) == NULL)
    {
        ret = ENOMEM;
        goto error;
    }

    if ((ret = xd3_config_stream (state->merge_stream, NULL)) ||
            (ret = xd3_whole_state_init (state->merge_stream)))
    {
        XPR(NT XD3_LIB_ERRMSG (& merge_input, ret));
        goto error;
    }

    xd3_swap_whole_state (& state->merge_stream->whole_target,
            & merge_input.whole_target);
    ret = 0;
error:
    xd3_free_stream (& merge_input);

    return ret;
}


/* This is called after all windows have been read, as a final step in
 * main_input().  This is only called for the final merge step. */
    static int
memory_merge_output (xd3_stream *stream, main_output_memory *output, xd3_state* state)
{
    int ret;
    usize_t inst_pos = 0;
    xoff_t output_pos = 0;
    xd3_source recode_source;
    usize_t window_num = 0;
    int at_least_once = 0;

    /* merge_stream is set if there were arguments.  this stream's input
     * needs to be applied to the merge_stream source. */
    if ((state->merge_stream != NULL) &&
            (ret = xd3_merge_input_output (stream,
                                           & state->merge_stream->whole_target)))
    {
        XPR(NT XD3_LIB_ERRMSG (stream, ret));
        return ret;
    }

    /* Enter the ENC_INPUT state and bypass the next_in == NULL test
     * and (leftover) input buffering logic. */
    XD3_ASSERT(state->recode_stream->enc_state == ENC_INIT);
    state->recode_stream->enc_state = ENC_INPUT;
    state->recode_stream->next_in = state->main_bdata;
    state->recode_stream->flags |= XD3_FLUSH;

    /* This encodes the entire target. */
    while (inst_pos < stream->whole_target.instlen || !at_least_once)
    {
        xoff_t window_start = output_pos;
        int window_srcset = 0;
        xoff_t window_srcmin = 0;
        xoff_t window_srcmax = 0;
        usize_t window_pos = 0;
        usize_t window_size;

        /* at_least_once ensures that we encode at least one window,
         * which handles the 0-byte case. */
        at_least_once = 1;

        XD3_ASSERT (state->recode_stream->enc_state == ENC_INPUT);

        if ((ret = xd3_encode_input (state->recode_stream)) != XD3_WINSTART)
        {
            XPR(NT "invalid merge state: %s\n", xd3_mainerror (ret));
            return XD3_INVALID;
        }

        /* Window sizes must match from the input to the output, so that
         * target copies are in-range (and so that checksums carry
         * over). */
        XD3_ASSERT (window_num < stream->whole_target.wininfolen);
        window_size = stream->whole_target.wininfo[window_num].length;

        /* Output position should also match. */
        if (output_pos != stream->whole_target.wininfo[window_num].offset)
        {
            XPR(NT "internal merge error: offset mismatch\n");
            return XD3_INVALID;
        }

        if (option_use_checksum &&
                (stream->dec_win_ind & VCD_ADLER32) != 0)
        {
            state->recode_stream->flags |= XD3_ADLER32_RECODE;
            state->recode_stream->recode_adler32 =
                stream->whole_target.wininfo[window_num].adler32;
        }

        window_num++;

        if (state->main_bsize < window_size)
        {
            main_buffree (state->main_bdata);
            state->main_bdata = NULL;
            state->main_bsize = 0;
            if ((state->main_bdata = (uint8_t*)
                        main_bufalloc (window_size)) == NULL)
            {
                return ENOMEM;
            }
            state->main_bsize = window_size;
        }

        /* This encodes a single target window. */
        while (window_pos < window_size &&
                inst_pos < stream->whole_target.instlen)
        {
            xd3_winst *inst = &stream->whole_target.inst[inst_pos];
            usize_t take = xd3_min(inst->size, window_size - window_pos);
            xoff_t addr;

            switch (inst->type)
            {
                case XD3_RUN:
                    if ((ret = xd3_emit_run (state->recode_stream, window_pos, take,
                                    &stream->whole_target.adds[inst->addr])))
                    {
                        return ret;
                    }
                    break;

                case XD3_ADD:
                    /* Adds are implicit, put them into the input buffer. */
                    memcpy (state->main_bdata + window_pos,
                            stream->whole_target.adds + inst->addr, take);
                    break;

                default: /* XD3_COPY + copy mode */
                    if (inst->mode != 0)
                    {
                        if (window_srcset) {
                            window_srcmin = xd3_min (window_srcmin, inst->addr);
                            window_srcmax = xd3_max (window_srcmax, inst->addr + take);
                        } else {
                            window_srcset = 1;
                            window_srcmin = inst->addr;
                            window_srcmax = inst->addr + take;
                        }
                        addr = inst->addr;
                    }
                    else
                    {
                        XD3_ASSERT (inst->addr >= window_start);
                        addr = inst->addr - window_start;
                    }
                    IF_DEBUG2 ({
                            XPR(NTR "[merge copy] winpos %"W"u take %"W"u "
                                    "addr %"Q"u mode %u\n",
                                    window_pos, take, addr, inst->mode);
                            });

                    if ((ret = xd3_found_match (state->recode_stream, window_pos, take,
                                    addr, inst->mode != 0)))
                    {
                        return ret;
                    }
                    break;
            }

            window_pos += take;
            output_pos += take;

            if (take == inst->size)
            {
                inst_pos += 1;
            }
            else
            {
                /* Modify the instruction for the next pass. */
                if (inst->type != XD3_RUN)
                {
                    inst->addr += take;
                }
                inst->size -= take;
            }
        }

        xd3_avail_input (state->recode_stream, state->main_bdata, window_pos);

        state->recode_stream->enc_state = ENC_INSTR;

        if (window_srcset) {
            state->recode_stream->srcwin_decided = 1;
            state->recode_stream->src = &recode_source;
            recode_source.srclen = (usize_t)(window_srcmax - window_srcmin);
            recode_source.srcbase = window_srcmin;
            state->recode_stream->taroff = recode_source.srclen;

            XD3_ASSERT (recode_source.srclen != 0);
        } else {
            state->recode_stream->srcwin_decided = 0;
            state->recode_stream->src = NULL;
            state->recode_stream->taroff = 0;
        }

        for (;;)
        {
            switch ((ret = xd3_encode_input (state->recode_stream)))
            {
                case XD3_INPUT: {
                                    goto done_window;
                                }
                case XD3_OUTPUT: {
                                     /* main_file_write below */
                                     break;
                                 }
                case XD3_GOTHEADER:
                case XD3_WINSTART:
                case XD3_WINFINISH: {
                                        /* ignore */
                                        continue;
                                    }
                case XD3_GETSRCBLK:
                case 0: {
                            return XD3_INTERNAL;
                        }
                default:
                        return ret;
            }

            if ((ret = memory_write_output(state->recode_stream, output)))
            {
                return ret;
            }

            xd3_consume_output (state->recode_stream);
        }
done_window:
        (void) 0;
    }

    return 0;
}



    static int
memory_write_output (xd3_stream* stream, main_output_memory *output)
{
    int ret;

    if (stream->avail_out > 0 &&
            (ret = memory_file_write (output, stream->next_out,
                                    stream->avail_out, "write failed")))
    {
        return ret;
    }

    return 0;
}

    int
memory_file_write (main_output_memory *output, uint8_t *buf, usize_t size, const char *msg)
{
    size_t available = output->total_size - output->size;

    if (size <= available)
    {
        memcpy(output->data + output->size, buf, size);
        output->size += size;
        return 0;
    }
    else
    {
        char* new_data;
        size_t new_size = output->total_size + ((size > 1000000) ? size : 1000000);
        if (!(new_data = realloc(output->data, new_size)))
        {
            // failed to realloc
            return 1;
        }
        output->data = new_data;
        output->total_size = new_size;
        return memory_file_write(output, buf, size, msg);
    }
}

static void
state_reset(xd3_state* state)
{
    state->main_bdata = NULL;
    state->main_bsize = 0;

    state->option_use_checksum = 1;
    state->option_iopt_size = XD3_DEFAULT_IOPT_SIZE;
    state->option_winsize = XD3_DEFAULT_WINSIZE;
    state->option_sprevsz = XD3_DEFAULT_SPREVSZ;
}
