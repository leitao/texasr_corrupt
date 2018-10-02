/*
 * Test case that sets TEXASR TM SPR and sleeps, waiting kernel load_tm
 * to be zero. Then causes a segfault to generate core dump that will be
 * analyzed, in order to make sure the coredump was set properly.
 *
 * TEXASR value in the coredump could be read as:
 *  $ eu-readelf --notes core | grep texasr | awk '{print $4}'
 *
 * Author: Breno Leitao <leitao@debian.org>
 */
#define _GNU_SOURCE
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <string.h>

#include <sched.h>

#define SPRN_TEXASR	0x82
#define PATH_MAX	1024
#define CORE_FILE_LIMIT	(5 * 1024 * 1024)       /* 5 MB should be enough */

#define err_at_line(status, errnum, format, ...) \
        error_at_line(status, errnum,  __FILE__, __LINE__, format ##__VA_ARGS__)

#define pr_err(code, format, ...) err_at_line(1, code, format, ##__VA_ARGS__)

static const char core_pattern_file[] = "/proc/sys/kernel/core_pattern";
pthread_attr_t attr;

void set_texasr(unsigned int val) {
	asm volatile("mtspr %1,%0" : : "r" (val), "i" (SPRN_TEXASR));
}

/* Set the process limits to be able to create a core dump */
void increase_core_file_limit(void)
{
	struct rlimit rlim;
	int ret;

	ret = getrlimit(RLIMIT_CORE, &rlim);
	if (ret != 0)
		pr_err(ret, "getrlimit core failed\n");

	if (rlim.rlim_cur != RLIM_INFINITY && rlim.rlim_cur < CORE_FILE_LIMIT) {
		rlim.rlim_cur = CORE_FILE_LIMIT;

		if (rlim.rlim_max != RLIM_INFINITY &&
		    rlim.rlim_max < CORE_FILE_LIMIT)
			rlim.rlim_max = CORE_FILE_LIMIT;

		ret = setrlimit(RLIMIT_CORE, &rlim);
		if (ret != 0)
			pr_err(ret, "setrlimit CORE failed\n");
	}

	ret = getrlimit(RLIMIT_FSIZE, &rlim);
	if (ret != 0)
		pr_err(ret, "getrlimit FSIZE failed\n");

	if (rlim.rlim_cur != RLIM_INFINITY && rlim.rlim_cur < CORE_FILE_LIMIT) {
		rlim.rlim_cur = CORE_FILE_LIMIT;

		if (rlim.rlim_max != RLIM_INFINITY &&
		    rlim.rlim_max < CORE_FILE_LIMIT)
			rlim.rlim_max = CORE_FILE_LIMIT;

		ret = setrlimit(RLIMIT_FSIZE, &rlim);
		if (ret != 0)
			pr_err(ret, "setrlimit FSIZE failed\n");
	}
}

static int write_core_pattern(const char *core_pattern, char *old)
{
	size_t len = strlen(core_pattern), ret;
	FILE *f;

	f = fopen(core_pattern_file, "r+");
	if (!f) {
		perror("Error writing to core_pattern file");
		return -1;
	}

	/* Skip saving old value */
	if (old != NULL) {
		ret = fread(old, 1, PATH_MAX, f);
		if (!ret) {
			perror("Error reading core_pattern file");
			return -1;
		}
		printf("OLD = %s\n", old);

		rewind(f);
	}

	printf("wrote %s\n", core_pattern);
	ret = fwrite(core_pattern, 1, len, f);
	fclose(f);
	if (ret != len) {
		perror("Error writing to core_pattern file");
		return -1;
	}

	return 0;
}


/* Thread to force context switch */
void *tm_una_pong(void *not_used)
{
	/* 
	 * Pong has TEXASR=5. Probably the value that will be caught on
	 * error
	 */
	set_texasr(5);
	while (1)
		sched_yield();
}


/* Sleep in userspace waiting for load_tm to reach zero */
void wait_lazy(unsigned long counter) {
	asm volatile (
		"mtctr  %[counter]      \n"
		"1:     bdnz 1b         \n"
		:
		: [counter] "r" (counter)
		:
	);
}

void *sleep_and_dump(void *time)
{
	pid_t child;
	int status;
	unsigned long t = *(unsigned long *)time;


	/* Fork, and the child process will sleep and die */
	child = fork();
	if (child < 0) {
		pr_err(child, "fork failure");
	} else if (child == 0) {

		/* Set TEXASR=7. Coredump should have this value */
		set_texasr(7);
		wait_lazy(t);
		/*
		 * Cause a segfault and coredeump. Can not call any syscalls,
		 * which will reload load_tm due to 'tabort' being inserted
		 * by glibc
		 */
		asm(".long 0x0");
	}

	/* Only parent will continue here */
	waitpid(child, &status, 0);
	if (!WCOREDUMP(status)){
		pr_err(status, "Core dump not generated.");
	}
}


/* Speed up load_tm overflow with this thread */
void start_pong_thread() {
	int rc;
	pthread_t t1;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);

	/* Init pthread attribute. */
	rc = pthread_attr_init(&attr);
	if (rc)
		pr_err(rc, "pthread_attr_init()");

	rc = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
	if (rc)
		pr_err(rc, "pthread_attr_setaffinity_np()");

	rc = pthread_create(&t1, &attr /* Bind to CPU 0 */, tm_una_pong, NULL);
	if (rc)
		pr_err(rc, "pthread_create()");
}


/* Main test thread */
void start_main_thread(unsigned long t)
{
	pthread_t t0;
	void *ret_value;
	int rc, ret;
	char old_core_pattern[PATH_MAX];

	increase_core_file_limit();
	/* Change the name of the core dump file */
	ret = write_core_pattern("core-tm-spr.%p", old_core_pattern);
	if (ret) {
		pr_err(ret, "Not able to generate core pattern");
		exit(-1);
	}

	rc = pthread_create(&t0, &attr, sleep_and_dump, &t);
	if (rc)
		pr_err(rc, "pthread_create()");

	rc = pthread_join(t0, &ret_value);
	if (rc)
		pr_err(rc, "pthread_join");

	/* Restore old core pattern to the original value */
	ret = write_core_pattern(old_core_pattern, NULL);
	if (ret != 0)
		pr_err(ret, "/proc/sys/kernel/core_pattern not restored properly");
}

int main(int argc, char *argv[]){
	/* Default time that causes the crash on P8/pseries */
	unsigned long time = 0x00d0000000;
	char *endptr;

	/* Argv[1] is the amount of cycles to sleep */
	if (argv[1] != NULL)
		time = strtol(argv[1], &endptr, 10);
			
	printf("Sleeping for %lu cycles\n", time);
	start_pong_thread();
	start_main_thread(time);

	return 0;
}
