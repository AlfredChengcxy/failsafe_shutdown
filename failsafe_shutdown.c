#define _XOPEN_SOURCE 500
#define _BSD_SOURCE
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <linux/reboot.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <string.h>

#define SHUTDOWN_TIMEOUT 30

#define ACT_CODE_POWEROFF ((unsigned)'P')
#define ACT_CODE_HALT     ((unsigned)'H')
#define ACT_CODE_REBOOT   ((unsigned)'B')
#define ACT_CODE_KEXEC    ((unsigned)'K')

#define log(msg, ...) printf("INIT: " msg "\n", ##__VA_ARGS__ )

static const char* default_argv[]= { "/etc/init/rc.shutdown", (const char*) NULL };

static int sysrq_fd= -1;

static void remount_proc();
static int open_sysrq();
static int sysrq_trigger(char c);

static void act_reboot() {
	log("Rebooting");
	sleep(1);
	reboot(LINUX_REBOOT_CMD_RESTART);
	log("Failed to reboot! : %m");
	sysrq_trigger('b');
}

static void act_poweroff() {
	log("Powering Off");
	sleep(1);
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	log("Failed to power-off! : %m");
	sysrq_trigger('o');
}

static void act_halt() {
	log("Halting");
	sleep(1);
	reboot(LINUX_REBOOT_CMD_HALT);
	log("Failed to halt! : %m");
}

static void act_kexec() {
	log("kexec...");
	sleep(1);
	reboot(LINUX_REBOOT_CMD_KEXEC);
	log("Failed to kexec! : %m");
}

static int do_action(int code) {
	switch (code) {
	case ACT_CODE_REBOOT:   act_reboot();   break;
	case ACT_CODE_POWEROFF: act_poweroff(); break;
	case ACT_CODE_KEXEC:    act_kexec();    break;
	case ACT_CODE_HALT:     act_halt();     break;
	default: return 0;
	}
	// this means the reboot failed for some reason
	return -1;
}

int main(int argc, const char **argv, char **environ) {
	int finalize_pid;
	pid_t me, reaped;
	time_t deadline;
	int wstat, n;
	int action= 0, default_action= 0;
	int timeout= SHUTDOWN_TIMEOUT;
	char *endptr, *e;
	const char **child_argv;

	if (getpid() != 1)
		log("warning: failsafe_shutdown should be run as process 1");

	// Process options
	if ((e= getenv("TIMEOUT"))) {
		n= strtol(e, &endptr, 10);
		if (*endptr == '\0') {
			timeout= n;
		} else {
			log("invalid shutdown TIMEOUT: \"%s\".  Ignored.", e);
		}
	}
	if ((e= getenv("DEFAULT_ACTION"))) {
		default_action= (unsigned) e[0];
	}
	
	// determine what to execute for the shutdown
	child_argv= (!argv[1] || !argv[1][0])? default_argv : argv+1;
	
	// run from root dir
	if (chdir("/") < 0)
		log("chdir('/'): %m");

	log("shutting down");

	// spawn a child process to perform shutdown actions
	// Its return code tells us how to call reboot.
	if ((finalize_pid= fork()) == 0) {
		execve(child_argv[0], (char * const *) child_argv, environ);
		log("unable to execute \"%s\": %m", child_argv[0]);
		exit(2);
	}
	// We give it 30 seconds to do so... after which we forcibly reboot the system.
	// Also, we continue to reap pids every 1/10 sec.
	if (finalize_pid > 0) {
		deadline= time(NULL) + timeout;
		while (1) {
			reaped= waitpid(-1, &wstat, WNOHANG);
			if (reaped == -1) {
				usleep(100000);
			} else if (reaped == finalize_pid) {
				if (WIFEXITED(wstat))
					action= WEXITSTATUS(wstat);
				break;
			} else if (deadline - time(NULL) <= 0) {
				log("%s failed to complete in a timely manner", child_argv[0]);
				kill(finalize_pid, SIGTERM);
				sleep(1);
				break;
			}
		}
	}
	else {
		log("unable to fork! : %m");
	}
	
	log("Restoring default behavior of ctrl-alt-del");
	reboot(LINUX_REBOOT_CMD_CAD_ON);

	if (!do_action(action)) {
		if (finalize_pid > 0) {
			log("invalid action code %d ('%c') received from %s",
				action, action, child_argv[0]);
		}
		// Execute default shutdown sequence
		log("executing basic term/kill/sync/remount/sync");
		kill(-1, SIGTERM);
		sleep(4);
		kill(-1, SIGKILL);
		sleep(2);
		sysrq_trigger('s');
		sleep(1);
		sysrq_trigger('u');
		sleep(1);
		sync();
		
		if (!do_action(default_action)) {
			log("defaulting to PANIC in 10 seconds");
			log("(hope your panic action is set the way you like)");
		}
	}
	// If do_action didn't reboot us, or if the user picked invalid
	// action codes, then we panic the kernel after giving them 10
	// seconds to read the console messages
	sleep(10);
	return -1;
}

static void remount_proc() {
	// Lazy-unmount, should work even if in use.
	if (umount2("/proc", MNT_DETACH) < 0)
		log("umount(/proc): %m");
	// on the off-chance it is missing and / is writeable
	mkdir("/proc", 0770);
	// Mount it again
	if (mount("none", "/proc", "proc", 0, "") < 0)
		log("mount(/proc): %m");
}

static int open_sysrq() {
	if (sysrq_fd < 0) {
		// Make sure it is enabled
		int fd= open("/proc/sys/kernel/sysrq", O_WRONLY);
		if (fd < 0) {
			remount_proc();
			fd= open("/proc/sys/kernel/sysrq", O_WRONLY);
		}
		if (fd < 0 || (write(fd, "1", 1) != 1))
			log("can't enable sysrq-trigger: %m");
		close(fd);

		// open the trigger file
		sysrq_fd= open("/proc/sysrq-trigger", O_WRONLY);
		if (sysrq_fd < 0) {
			remount_proc();
			sysrq_fd= open("/proc/sysrq-trigger", O_WRONLY);
		}
		if (sysrq_fd < 0)	
			log("can't open /proc/sysrq-trigger: %m");
	}
	return sysrq_fd >= 0;
}

static int sysrq_trigger(char c) {
	if (open_sysrq() && write(sysrq_fd, &c, 1) == 1)
		return 1;
	return 0;
}
