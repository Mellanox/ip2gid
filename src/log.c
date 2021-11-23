/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/time.h>

#include "log.h"

static char log_file[128] = IP2GID_LOG_FILE;
static int log_level = IP2GID_LOG_ERR;
static FILE *flog;

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static char *log_level_str(int level)
{
	if (level == IP2GID_LOG_INFO)
		return "INFO";
	if (level == IP2GID_LOG_WARN)
		return "WARN";
	if (level == IP2GID_LOG_ERR)
		return "ERR";

	return "UNKNOWN";
}

void ip2gid_write(int level, const char *format, ...)
{
        va_list args;
        struct timeval tv;
        struct tm tmtime;
        char buffer[20];

        if (level < log_level)
                return;

        gettimeofday(&tv, NULL);
        localtime_r(&tv.tv_sec, &tmtime);
        strftime(buffer, 20, "%Y-%m-%dT%H:%M:%S", &tmtime);
        va_start(args, format);
        pthread_mutex_lock(&log_lock);
        fprintf(flog, "%s.%03u:%s: ",
		buffer,
		(unsigned) (tv.tv_usec / 1000),
		log_level_str(level));
        vfprintf(flog, format, args);
        fflush(flog);
        pthread_mutex_unlock(&log_lock);
        va_end(args);
}

int ip2gid_open_log(int level)
{
        if (!strcasecmp(log_file, "stdout")) {
                flog = stdout;
	} else if (!strcasecmp(log_file, "stderr")) {
                flog = stderr;
	} else {
		flog = fopen(log_file, "w");
		if (!flog) {
			printf("Failed to open logfile %s: %d\n",
			       log_file, errno);
			return errno;
		}
	}

	log_level = level;
        return 0;
}
