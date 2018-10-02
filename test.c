/*
 * Test case that sets TEXASR TM SPR and sleeps, waiting kernel load_tm
 * to be zero. Then causes a segfault to generate core dump that will be
 * analyzed, in order to make sure the coredump was set properly.
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
#include <elf.h>
#include <assert.h>
#include <linux/kernel.h>

#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#define SPRN_TEXASR		0x82
#define SPRN_TFIAR      	0x81
#define SPRN_TFHAR      	0x80

#define PATH_MAX		1024
#define CORE_FILE_LIMIT		(5 * 1024 * 1024)
#define COREDUMPFILE 		"core-tm-spr"
#define COREDUMP(APPEND)	COREDUMPFILE#APPEND
#define CORE_PATTERN_FILE 	"/proc/sys/kernel/core_pattern"

#define __stringify(x)		#x
#define mtspr(rn, v)		asm volatile("mtspr "__stringify(rn) ",%0" : \
                                     : "r" ((unsigned long)(v)) \
                                     : "memory")

#define err_at_line(status, errnum, format, ...) \
        error_at_line(status, errnum,  __FILE__, __LINE__, format ##__VA_ARGS__)
#define pr_err(code, format, ...) err_at_line(1, code, format, ##__VA_ARGS__)

/* Child pid */
pid_t child;

/* Pthread attribute for both ping and pong threads */
pthread_attr_t attr;

/* SPR values to be written (and verified) against SPRs */
const unsigned long texasr = 0xf1;
const unsigned long tfiar = 0xf20000;
const unsigned long tfhar = 0xf300;

struct tm_sprs {
	unsigned long texasr;
	unsigned long tfhar;
	unsigned long tfiar;
};

struct coremem {
	void *p;
	off_t len;
};

/* Set the process limits to be able to create a core dump */
int increase_core_file_limit(void)
{
	struct rlimit rlim;
	int ret;

	ret = getrlimit(RLIMIT_CORE, &rlim);
	if (ret != 0) {
		pr_err(ret, "getrlimit core failed\n");
		return -1;
	}

	if (rlim.rlim_cur != RLIM_INFINITY && rlim.rlim_cur < CORE_FILE_LIMIT) {
		rlim.rlim_cur = CORE_FILE_LIMIT;

		if (rlim.rlim_max != RLIM_INFINITY &&
		    rlim.rlim_max < CORE_FILE_LIMIT)
			rlim.rlim_max = CORE_FILE_LIMIT;

		ret = setrlimit(RLIMIT_CORE, &rlim);
		if (ret != 0) {
			pr_err(ret, "setrlimit CORE failed\n");
			return -1;
		}
	}

	ret = getrlimit(RLIMIT_FSIZE, &rlim);
	if (ret != 0) {
		pr_err(ret, "getrlimit FSIZE failed\n");
		return -1;
	}

	if (rlim.rlim_cur != RLIM_INFINITY && rlim.rlim_cur < CORE_FILE_LIMIT) {
		rlim.rlim_cur = CORE_FILE_LIMIT;

		if (rlim.rlim_max != RLIM_INFINITY &&
		    rlim.rlim_max < CORE_FILE_LIMIT)
			rlim.rlim_max = CORE_FILE_LIMIT;

		ret = setrlimit(RLIMIT_FSIZE, &rlim);
		if (ret != 0) {
			pr_err(ret, "setrlimit FSIZE failed\n");
			return -1;
		}
	}

	return 0;
}

/*
 * Set pattern for coredump file name. It returns current pattern being
 * used as 'old', if old != NULL
 */
static int write_core_pattern(const char *core_pattern, char *old)
{
	FILE *f;
	size_t len = strlen(core_pattern), ret;

	f = fopen(CORE_PATTERN_FILE, "r+");
	if (!f) {
		perror("Error writing to core_pattern file");
		return -1;
	}

	/* Skip saving old value */
	if (old != NULL) {
		ret = fread(old, 1, PATH_MAX, f);
		if (!ret) {
			perror("Error reading core_pattern file");
			fclose(f);
			return -1;
		}
		rewind(f);
	}

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

/*
 * Main test function. This function will fork, and the child will set the
 * SPRs and sleep expecting load_tm to be zero. After a while, it will
 * segfault and generate a core dump. The parent process just wait the
 * child to die before continuing.
 */
void *sleep_and_dump(void *time)
{
	int status;
	unsigned long t = *(unsigned long *)time;

	/* Fork, and the child process will sleep and die */
	child = fork();
	if (child < 0) {
		pr_err(child, "fork failure");
	} else if (child == 0) {
		/* Set TM SPRS to be checked later */
		mtspr(SPRN_TFIAR, tfiar);
		mtspr(SPRN_TFHAR, tfhar);
		mtspr(SPRN_TEXASR,texasr);
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
		return (void *) -1;
	}

	return  NULL;
}


/* Speed up load_tm overflow with this thread */
int start_pong_thread() {
	int rc;
	pthread_t t1;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);

	/* Init pthread attribute. */
	rc = pthread_attr_init(&attr);
	if (rc) {
		pr_err(rc, "pthread_attr_init()");
		return rc;
	}

	rc = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);
	if (rc) {
		pr_err(rc, "pthread_attr_setaffinity_np()");
		return rc;
	}

	rc = pthread_create(&t1, &attr /* Bind to CPU 0 */, tm_una_pong, NULL);
	if (rc) {
		pr_err(rc, "pthread_create()");
		return rc;
	}
}


/* Main test thread */
int start_main_thread(unsigned long t)
{
	pthread_t t0;
	void *ret_value;
	int rc, ret;
	char old_core_pattern[PATH_MAX];

	ret = increase_core_file_limit();
	if (ret)
		return ret;

	/* Change the name of the core dump file */
	ret = write_core_pattern(COREDUMP(.%p), old_core_pattern);
	if (ret) {
		pr_err(ret, "Not able to generate core pattern");
		return -1;
	}

	rc = pthread_create(&t0, &attr, sleep_and_dump, &t);
	if (rc)
		pr_err(rc, "pthread_create()");

	rc = pthread_join(t0, &ret_value);
	if (rc || ret_value != NULL) {
		pr_err(rc, "pthread_join");
		return -1;
	}

	/* Restore old core pattern to the original value */
	ret = write_core_pattern(old_core_pattern, NULL);
	if (ret != 0)
		pr_err(ret, "/proc/sys/kernel/core_pattern not restored properly");

	return 0;
}

/* Open coredump file and return it mapped into memory */
void open_coredump(struct coremem *c)
{
        struct stat buf;
	int fd; int ret;
	void *core;
	off_t core_size;

	char coredump[PATH_MAX];

	/* default return value */
	c->p = NULL;

	sprintf(coredump, COREDUMP(.%d), child);

	fd = open(coredump, O_RDONLY);
	if (fd == -1) {
		perror("Error opening core file");
	}

	ret = stat(coredump, &buf);
	if (ret == -1) {
		printf("Coredump %s does not exists\n");
		return;
	}
	core_size = buf.st_size;

	core = mmap(NULL, core_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (core == (void *) -1) {
		perror("Error mmaping core file");
		return;
	}
	c->p = core;
	c->len = core_size;
}

static Elf64_Nhdr *next_note(Elf64_Nhdr *nhdr)
{
	return (void *) nhdr + sizeof(*nhdr) +
		__ALIGN_KERNEL(nhdr->n_namesz, 4) +
		__ALIGN_KERNEL(nhdr->n_descsz, 4);
}

/* Parse elf in memory and return TM SPRS values */
void parse_elf(Elf64_Ehdr *ehdr, struct tm_sprs *ret){
	void *p = ehdr;
	Elf64_Phdr *phdr;
	Elf64_Nhdr *nhdr;
	size_t phdr_size;
	unsigned long *regs, *note;

	assert(memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0);

	assert(ehdr->e_type == ET_CORE);
	assert(ehdr->e_machine == EM_PPC64);
	assert(ehdr->e_phoff != 0 || ehdr->e_phnum != 0);

	wphdr_size = sizeof(*phdr) * ehdr->e_phnum;
	for (phdr = p + ehdr->e_phoff;
	     (void *) phdr < p + ehdr->e_phoff + phdr_size;
	      phdr += ehdr->e_phentsize)
		/* Stop at NOTES section type */
		if (phdr->p_type == PT_NOTE)
			break;

	for (nhdr = p + phdr->p_offset;
	     (void *) nhdr < p + phdr->p_offset + phdr->p_filesz;
	     nhdr = next_note(nhdr))
		/* Stop at TM SPR segment */
		if (nhdr->n_type == NT_PPC_TM_SPR)
			break;

	assert(nhdr->n_descsz != 0);

	p = nhdr;
	note = p + sizeof(*nhdr) + __ALIGN_KERNEL(nhdr->n_namesz, 4);
	regs = (unsigned long *) note;

	ret->texasr = regs[1];
	ret->tfhar = regs[0];
	ret->tfiar = regs[2];
}

int check_return_value(struct tm_sprs *s)
{
	if ((s->texasr = texasr) &&
	    (s->tfiar == tfiar) &&
	    (s->tfhar == tfhar)) {
		return 0;
	} else {
		printf("Corrupted SPR values detected\n");
		printf("Tfiar : %016lx vs %016lx\n", s->texasr, texasr);
		printf("Texasr: %016lx vs %016lx\n", s->tfiar, tfiar);
		printf("Tfhar : %016lx vs %016lx\n", s->tfhar, tfhar);
		return -1;
	}
}

int clear_coredump()
{
	char file[PATH_MAX];
	int ret;

	sprintf(file, COREDUMP(.%d), child);
	ret = remove(file);
	if (ret != 0) {
		perror("Not able to remove core dump file");
	}

	return ret;
}

int main(int argc, char *argv[]){
	/* Default time that causes the crash on P8/pseries */
	unsigned long time = 0x00d0000000;
	int ret;
	char *endptr;
	struct tm_sprs sprs;
	struct coremem mem;

	printf("Sleeping for %lu cycles\n", time);
	ret = start_pong_thread();
	if (ret != 0)
		return ret;

	ret = start_main_thread(time);
	if (ret != 0)
		return ret;

	open_coredump(&mem);
	if (mem.p == NULL) {
		/* if open_coredump failed, mem.p returns NULL */
		pr_err(1, "Open core dump failed");
		return -1;
	}

	parse_elf(mem.p, &sprs);

	ret = clear_coredump();
	if (ret != 0)
		goto out;

	ret = check_return_value(&sprs);
	if (ret == 0)
		printf("Success!\n");
	else
		printf("Failure!\n");

out:
	/* unmap memory allocated in open_coredump() */
	munmap(mem.p, mem.len);
	return ret;
}
