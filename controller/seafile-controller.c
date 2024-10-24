/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <fcntl.h>

#include <glib.h>

#include "utils.h"
#include "log.h"
#include "seafile-controller.h"

#define CHECK_PROCESS_INTERVAL 10        /* every 10 seconds */

#if defined(__sun)
#define PROC_SELF_PATH "/proc/self/path/a.out"
#else
#define PROC_SELF_PATH "/proc/self/exe"
#endif

SeafileController *ctl;

static char *controller_pidfile = NULL;

char *bin_dir = NULL;
char *installpath = NULL;
char *topdir = NULL;
gboolean enabled_go_fileserver = FALSE;

char *seafile_ld_library_path = NULL;

static const char *short_opts = "hvftc:d:l:g:G:P:F:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "foreground", no_argument, NULL, 'f', },
    { "test", no_argument, NULL, 't', },
    { "config-dir", required_argument, NULL, 'c', },
    { "seafile-dir", required_argument, NULL, 'd', },
    { "central-config-dir", required_argument, NULL, 'F' },
    { "logdir", required_argument, NULL, 'l', },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "seafile-debug-level", required_argument, NULL, 'G' },
    { "pidfile", required_argument, NULL, 'P' },
    { NULL, 0, NULL, 0, },
};

static void controller_exit (int code) __attribute__((noreturn));

static int read_seafdav_config();

static void
controller_exit (int code)
{
    if (code != 0) {
        seaf_warning ("seaf-controller exited with code %d\n", code);
    }
    exit(code);
}

//
// Utility functions Start
//

/* returns the pid of the newly created process */
static int
spawn_process (char *argv[], bool is_python_process)
{
    char **ptr = argv;
    GString *buf = g_string_new(argv[0]);
    while (*(++ptr)) {
        g_string_append_printf (buf, " %s", *ptr);
    }
    seaf_message ("spawn_process: %s\n", buf->str);
    g_string_free (buf, TRUE);

    int pipefd[2] = {0, 0};
    if (is_python_process) {
        if (pipe(pipefd) < 0) {
            seaf_warning("Failed to create pipe.\n");
        }
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    }

    pid_t pid = fork();

    if (pid == 0) {
        if (is_python_process) {
            if (pipefd[0] > 0 && pipefd[1] > 0) {
                close(pipefd[0]);
                dup2(pipefd[1], 2);
            }
        }
        /* child process */
        execvp (argv[0], argv);
        seaf_warning ("failed to execvp %s\n", argv[0]);
        
        if (pipefd[1] > 0) {
            close(pipefd[1]);
        }

        exit(-1);
    } else {
        /* controller */
        if (pid == -1)
            seaf_warning ("error when fork %s: %s\n", argv[0], strerror(errno));
        else
            seaf_message ("spawned %s, pid %d\n", argv[0], pid);

        if (is_python_process) {
            char child_stderr[1024] = {0};
            if (pipefd[0] > 0 && pipefd[1] > 0){
                close(pipefd[1]);
                sleep(1);
                while (read(pipefd[0], child_stderr, sizeof(child_stderr)) > 0)
                    seaf_warning("%s", child_stderr);
                close(pipefd[0]);
            }
        }
        return (int)pid;
    }
}

#define PID_ERROR_ENOENT 0
#define PID_ERROR_OTHER  -1

/**
 * @return
 * - pid if successfully opened and read the file
 * - PID_ERROR_ENOENT if file not exists,
 * - PID_ERROR_OTHER if other errors
 */
static int
read_pid_from_pidfile (const char *pidfile)
{
    FILE *pf = g_fopen (pidfile, "r");
    if (!pf) {
        if (errno == ENOENT) {
            return PID_ERROR_ENOENT;
        } else {
            return PID_ERROR_OTHER;
        }
    }

    int pid = PID_ERROR_OTHER;
    if (fscanf (pf, "%d", &pid) < 0) {
        seaf_warning ("bad pidfile format: %s\n", pidfile);
        fclose(pf);
        return PID_ERROR_OTHER;
    }

    fclose(pf);

    return pid;
}

static void
kill_by_force (int which)
{
    if (which < 0 || which >= N_PID)
        return;

    char *pidfile = ctl->pidfile[which];
    int pid = read_pid_from_pidfile(pidfile);
    if (pid > 0) {
        // if SIGKILL send success, then remove related pid file
        if (kill ((pid_t)pid, SIGKILL) == 0) {
            g_unlink (pidfile);
        }
    }
}

//
// Utility functions End
//

static int
start_seaf_server ()
{
    if (!ctl->config_dir || !ctl->seafile_dir)
        return -1;

    seaf_message ("starting seaf-server ...\n");
    static char *logfile = NULL;
    if (logfile == NULL) {
        logfile = g_build_filename (ctl->logdir, "seafile.log", NULL);
    }

    char *argv[] = {
        "seaf-server",
        "-F", ctl->central_config_dir,
        "-c", ctl->config_dir,
        "-d", ctl->seafile_dir,
        "-l", logfile,
        "-P", ctl->pidfile[PID_SERVER],
        "-p", ctl->rpc_pipe_path,
        NULL};
    int pid = spawn_process (argv, false);
    if (pid <= 0) {
        seaf_warning ("Failed to spawn seaf-server\n");
        return -1;
    }

    return 0;
}

static int
start_go_fileserver()
{
    if (!ctl->central_config_dir || !ctl->seafile_dir)
        return -1;

    static char *logfile = NULL;
    if (logfile == NULL) {
        logfile = g_build_filename (ctl->logdir, "fileserver.log", NULL);
    }

    char *argv[] = {
        "fileserver",
        "-F", ctl->central_config_dir,
        "-d", ctl->seafile_dir,
        "-l", logfile,
        "-p", ctl->rpc_pipe_path,
        "-P", ctl->pidfile[PID_FILESERVER],
        NULL};

    seaf_message ("starting go-fileserver ...");
    int pid = spawn_process(argv, false);

    if (pid <= 0) {
        seaf_warning("Failed to spawn fileserver\n");
        return -1;
    }
    return 0;
}

static const char *
get_python_executable() {
    static const char *python = NULL;
    if (python != NULL) {
        return python;
    }

    static const char *try_list[] = {
        "python3"
    };

    int i;
    for (i = 0; i < G_N_ELEMENTS(try_list); i++) {
        char *binary = g_find_program_in_path (try_list[i]);
        if (binary != NULL) {
            python = binary;
            break;
        }
    }

    if (python == NULL) {
        python = g_getenv ("PYTHON");
        if (python == NULL) {
            python = "python";
        }
    }

    return python;
}

static void
init_seafile_path ()
{
    GError *error = NULL;
    char *binary = g_file_read_link (PROC_SELF_PATH, &error);
    char *tmp = NULL;
    if (error != NULL) {
        seaf_warning ("failed to readlink: %s\n", error->message);
        return;
    }

    bin_dir = g_path_get_dirname (binary);

    tmp = g_path_get_dirname (bin_dir);
    installpath = g_path_get_dirname (tmp);

    topdir = g_path_get_dirname (installpath);

    g_free (binary);
    g_free (tmp);
}

static void
setup_python_path()
{
    static GList *path_list = NULL;
    if (path_list != NULL) {
        /* Only setup once */
        return;
    }

    /* Allow seafdav to access seahub_settings.py */
    path_list = g_list_prepend (path_list, g_build_filename (topdir, "conf", NULL));

    path_list = g_list_prepend (path_list,
        g_build_filename (installpath, "seahub", NULL));

    path_list = g_list_prepend (path_list,
        g_build_filename (installpath, "seahub/thirdpart", NULL));

    path_list = g_list_prepend (path_list,
        g_build_filename (installpath, "seahub/seahub-extra", NULL));

    path_list = g_list_prepend (path_list,
        g_build_filename (installpath, "seahub/seahub-extra/thirdparts", NULL));

    path_list = g_list_prepend (path_list,
        g_build_filename (installpath, "seafile/lib/python3/site-packages", NULL));

    path_list = g_list_prepend (path_list,
        g_build_filename (installpath, "seafile/lib64/python3/site-packages", NULL));

    path_list = g_list_reverse (path_list);

    GList *ptr;
    GString *new_pypath = g_string_new (g_getenv("PYTHONPATH"));

    for (ptr = path_list; ptr != NULL; ptr = ptr->next) {
        const char *path = (char *)ptr->data;

        g_string_append_c (new_pypath, ':');
        g_string_append (new_pypath, path);
    }

    g_setenv ("PYTHONPATH", g_string_free (new_pypath, FALSE), TRUE);

    /* seaf_message ("PYTHONPATH is:\n\n%s\n", g_getenv ("PYTHONPATH")); */
}

static void
setup_env ()
{
    g_setenv ("CCNET_CONF_DIR", ctl->config_dir, TRUE);
    g_setenv ("SEAFILE_CONF_DIR", ctl->seafile_dir, TRUE);
    g_setenv ("SEAFILE_CENTRAL_CONF_DIR", ctl->central_config_dir, TRUE);
    g_setenv ("SEAFILE_RPC_PIPE_PATH", ctl->rpc_pipe_path, TRUE);

    char *seahub_dir = g_build_filename (installpath, "seahub", NULL);
    char *seafdav_conf = g_build_filename (ctl->central_config_dir, "seafdav.conf", NULL);
    g_setenv ("SEAHUB_DIR", seahub_dir, TRUE);
    g_setenv ("SEAFDAV_CONF", seafdav_conf, TRUE);

    setup_python_path();
}

static int
start_seafdav() {
    static char *seafdav_log_file = NULL;
    if (seafdav_log_file == NULL)
        seafdav_log_file = g_build_filename (ctl->logdir,
                                             "seafdav.log",
                                             NULL);

    SeafDavConfig conf = ctl->seafdav_config;
    char port[16];
    snprintf (port, sizeof(port), "%d", conf.port);

    int pid;
    if (conf.debug_mode) {
        char *argv[] = {
            (char *)get_python_executable(),
            "-m", "wsgidav.server.server_cli",
            "--server", "gunicorn",
            "--root", "/",
            "--log-file", seafdav_log_file, 
            "--pid", ctl->pidfile[PID_SEAFDAV],
            "--port", port,
            "--host", conf.host,
            "-v",
            NULL
        };
        pid = spawn_process (argv, true);
    } else {
        char *argv[] = {
            (char *)get_python_executable(),
            "-m", "wsgidav.server.server_cli",
            "--server", "gunicorn",
            "--root", "/",
            "--log-file", seafdav_log_file, 
            "--pid", ctl->pidfile[PID_SEAFDAV],
            "--port", port,
            "--host", conf.host,
            NULL
        };
        pid = spawn_process (argv, true);
    }

    if (pid <= 0) {
        seaf_warning ("Failed to spawn seafdav\n");
        return -1;
    }

    return 0;
}

static void
run_controller_loop ()
{
    GMainLoop *mainloop = g_main_loop_new (NULL, FALSE);

    g_main_loop_run (mainloop);
}

static gboolean
need_restart (int which)
{
    if (which < 0 || which >= N_PID)
        return FALSE;

    int pid = read_pid_from_pidfile (ctl->pidfile[which]);
    if (pid == PID_ERROR_ENOENT) {
        seaf_warning ("pid file %s does not exist\n", ctl->pidfile[which]);
        return TRUE;
    } else if (pid == PID_ERROR_OTHER) {
        seaf_warning ("failed to read pidfile %s: %s\n", ctl->pidfile[which], strerror(errno));
        return FALSE;
    } else {
        char buf[256];
        snprintf (buf, sizeof(buf), "/proc/%d", pid);
        if (g_file_test (buf, G_FILE_TEST_IS_DIR)) {
            return FALSE;
        } else {
            seaf_warning ("path /proc/%d doesn't exist, restart progress [%d]\n", pid, which);
            return TRUE;
        }
    }
}

static gboolean
should_start_go_fileserver()
{
    char *seafile_conf = g_build_filename (ctl->central_config_dir, "seafile.conf", NULL);
    GKeyFile *key_file = g_key_file_new ();
    gboolean ret = 0;

    if (!g_key_file_load_from_file (key_file, seafile_conf,
                                    G_KEY_FILE_KEEP_COMMENTS, NULL)) {
        seaf_warning("Failed to load seafile.conf.\n");
        ret = FALSE;
        goto out;
    }
    GError *err = NULL;
    gboolean enabled;
    enabled = g_key_file_get_boolean(key_file, "fileserver", "use_go_fileserver", &err);
    if (err) {
        seaf_warning("Config [fileserver, use_go_fileserver] not set, default is FALSE.\n");
        ret = FALSE;
        g_clear_error(&err);
    } else {
        if (enabled) {
            ret = TRUE;
        } else {
            ret = FALSE;
        }
    }

    if (ret) {
        char *type = NULL;
        type = g_key_file_get_string (key_file, "database", "type", NULL);
        if (!type || g_strcmp0 (type, "mysql") != 0) {
            seaf_message ("Use C fileserver because go fileserver does not support sqlite.");
            ret = FALSE;
        }
        g_free (type);
    }

out:
    g_key_file_free (key_file);
    g_free (seafile_conf);

    return ret;
}

static gboolean
check_process (void *data)
{
    if (need_restart(PID_SERVER)) {
        seaf_message ("seaf-server need restart...\n");
        start_seaf_server();
    }

    if (enabled_go_fileserver) {
        if (need_restart(PID_FILESERVER)) {
            seaf_message("fileserver need restart...\n");
            start_go_fileserver();
        }
    }

    if (ctl->seafdav_config.enabled) {
        if (need_restart(PID_SEAFDAV)) {
            seaf_message ("seafdav need restart...\n");
            start_seafdav ();
        }
    }

    return TRUE;
}

static void
start_process_monitor ()
{
    ctl->check_process_timer = g_timeout_add (
        CHECK_PROCESS_INTERVAL * 1000, check_process, NULL);
}

static int seaf_controller_start ();
/* This would also stop seaf-server & other components */
static void
stop_services ()
{
    seaf_message ("shutting down all services ...\n");

    kill_by_force(PID_SERVER);
    kill_by_force(PID_FILESERVER);
    kill_by_force(PID_SEAFDAV);
}

static void
init_pidfile_path (SeafileController *ctl)
{
    char *pid_dir = g_build_filename (topdir, "pids", NULL);
    if (!g_file_test(pid_dir, G_FILE_TEST_EXISTS)) {
        if (g_mkdir(pid_dir, 0777) < 0) {
            seaf_warning("failed to create pid dir %s: %s", pid_dir, strerror(errno));
            controller_exit(1);
        }
    }

    ctl->pidfile[PID_SERVER] = g_build_filename (pid_dir, "seaf-server.pid", NULL);
    ctl->pidfile[PID_SEAFDAV] = g_build_filename (pid_dir, "seafdav.pid", NULL);
    ctl->pidfile[PID_FILESERVER] = g_build_filename (pid_dir, "fileserver.pid", NULL);
}

static int
seaf_controller_init (SeafileController *ctl,
                      char *central_config_dir,
                      char *config_dir,
                      char *seafile_dir,
                      char *logdir)
{
    init_seafile_path ();
    if (!g_file_test (config_dir, G_FILE_TEST_IS_DIR)) {
        seaf_warning ("invalid config_dir: %s\n", config_dir);
        return -1;
    }

    if (!g_file_test (seafile_dir, G_FILE_TEST_IS_DIR)) {
        seaf_warning ("invalid seafile_dir: %s\n", seafile_dir);
        return -1;
    }

    if (logdir == NULL) {
        char *topdir = g_path_get_dirname(config_dir);
        logdir = g_build_filename (topdir, "logs", NULL);
        if (checkdir_with_mkdir(logdir) < 0) {
            seaf_error ("failed to create log folder \"%s\": %s\n",
                        logdir, strerror(errno));
            return -1;
        }
        g_free (topdir);
    }

    ctl->central_config_dir = central_config_dir;
    ctl->config_dir = config_dir;
    ctl->seafile_dir = seafile_dir;
    ctl->rpc_pipe_path = g_build_filename (installpath, "runtime", NULL);
    ctl->logdir = logdir;

    if (read_seafdav_config() < 0) {
        return -1;
    }

    init_pidfile_path (ctl);
    setup_env ();

    return 0;
}

static int
seaf_controller_start ()
{
    if (start_seaf_server() < 0) {
        seaf_warning ("Failed to start seaf server\n");
        return -1;
    }

    if (enabled_go_fileserver) {
        if (start_go_fileserver() < 0) {
            seaf_warning ("Failed to start fileserver\n");
            return -1;
        }
    }

    start_process_monitor ();
    return 0;
}

static int
write_controller_pidfile ()
{
    if (!controller_pidfile)
        return -1;

    pid_t pid = getpid();

    FILE *pidfile = g_fopen(controller_pidfile, "w");
    if (!pidfile) {
        seaf_warning ("Failed to fopen() pidfile %s: %s\n",
                      controller_pidfile, strerror(errno));
        return -1;
    }

    char buf[32];
    snprintf (buf, sizeof(buf), "%d\n", pid);
    if (fputs(buf, pidfile) < 0) {
        seaf_warning ("Failed to write pidfile %s: %s\n",
                      controller_pidfile, strerror(errno));
        fclose (pidfile);
        return -1;
    }

    fflush (pidfile);
    fclose (pidfile);
    return 0;
}

static void
remove_controller_pidfile ()
{
    if (controller_pidfile) {
        g_unlink (controller_pidfile);
    }
}

static void
sigint_handler (int signo)
{
    stop_services ();

    remove_controller_pidfile();

    signal (signo, SIG_DFL);
    raise (signo);
}

static void
sigchld_handler (int signo)
{
    waitpid (-1, NULL, WNOHANG);
}

static void
sigusr1_handler (int signo)
{
    seafile_log_reopen();
}

static void
set_signal_handlers ()
{
    signal (SIGINT, sigint_handler);
    signal (SIGTERM, sigint_handler);
    signal (SIGCHLD, sigchld_handler);
    signal (SIGUSR1, sigusr1_handler);
    signal (SIGPIPE, SIG_IGN);
}

static void
usage ()
{
    fprintf (stderr, "Usage: seafile-controller OPTIONS\n"
                     "OPTIONS:\n"
                     "  -b, --bin-dir           insert a directory in front of the PATH env\n"
                     "  -c, --config-dir        ccnet config dir\n"
                     "  -d, --seafile-dir       seafile dir\n"
                     );
}

/* seafile-controller -t is used to test whether config file is valid */
static void
test_config (const char *central_config_dir,
             const char *ccnet_dir,
             const char *seafile_dir)
{
    char buf[1024];
    GError *error = NULL;
    int retcode = 0;
    char *child_stdout = NULL;
    char *child_stderr = NULL;

    snprintf (buf,
          sizeof(buf),
          "seaf-server -F \"%s\" -c \"%s\" -d \"%s\" -t -f",
          central_config_dir,
          ccnet_dir,
          seafile_dir);

    g_spawn_command_line_sync (buf,
                               &child_stdout,
                               &child_stderr,
                               &retcode,
                               &error);

    if (error != NULL) {
        seaf_error ("failed to run \"seaf-server -t\": %s\n",
                    error->message);
        exit (1);
    }

    if (child_stdout) {
        fputs (child_stdout, stdout);
    }

    if (child_stderr) {
        fputs (child_stderr, stdout);
    }

    if (retcode != 0) {
        seaf_error ("failed to run \"seaf-server -t\" [%d]\n", retcode);
        exit (1);
    }

    exit(0);
}

static int
read_seafdav_config()
{
    int ret = 0;
    char *seafdav_conf = NULL;
    GKeyFile *key_file = NULL;
    GError *error = NULL;

    seafdav_conf = g_build_filename(ctl->central_config_dir, "seafdav.conf", NULL);
    if (!g_file_test(seafdav_conf, G_FILE_TEST_EXISTS)) {
        goto out;
    }

    key_file = g_key_file_new ();
    if (!g_key_file_load_from_file (key_file, seafdav_conf,
                                    G_KEY_FILE_KEEP_COMMENTS, NULL)) {
        seaf_warning("Failed to load seafdav.conf\n");
        ret = -1;
        goto out;
    }

    /* enabled */
    ctl->seafdav_config.enabled = g_key_file_get_boolean(key_file, "WEBDAV", "enabled", &error);
    if (error != NULL) {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
            seaf_message ("Error when reading WEBDAV.enabled, use default value 'false'\n");
        }
        ctl->seafdav_config.enabled = FALSE;
        g_clear_error (&error);
        goto out;
    }

    if (!ctl->seafdav_config.enabled) {
        goto out;
    }

    /* host */
    char *host = seaf_key_file_get_string (key_file, "WEBDAV", "host", &error);
    if (error != NULL) {
        g_clear_error(&error);
        ctl->seafdav_config.host = g_strdup("0.0.0.0");
    } else {
        ctl->seafdav_config.host = host;
    }

    /* port */
    ctl->seafdav_config.port = g_key_file_get_integer(key_file, "WEBDAV", "port", &error);
    if (error != NULL) {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
            seaf_message ("Error when reading WEBDAV.port, use deafult value 8080\n");
        }
        ctl->seafdav_config.port = 8080;
        g_clear_error (&error);
    }

    ctl->seafdav_config.debug_mode = g_key_file_get_boolean (key_file, "WEBDAV", "debug", &error);
    if (error != NULL) {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
            seaf_message ("Error when reading WEBDAV.debug, use deafult value FALSE\n");
        }
        ctl->seafdav_config.debug_mode = FALSE;
        g_clear_error (&error);
    }

    if (ctl->seafdav_config.port <= 0 || ctl->seafdav_config.port > 65535) {
        seaf_warning("Failed to load seafdav config: invalid port %d\n", ctl->seafdav_config.port);
        ret = -1;
        goto out;
    }

out:
    if (key_file) {
        g_key_file_free (key_file);
    }
    g_free (seafdav_conf);

    return ret;
}

static int
init_syslog_config ()
{
    char *seafile_conf = g_build_filename (ctl->central_config_dir, "seafile.conf", NULL);
    GKeyFile *key_file = g_key_file_new ();
    int ret = 0;

    if (!g_key_file_load_from_file (key_file, seafile_conf,
                                    G_KEY_FILE_KEEP_COMMENTS, NULL)) {
        seaf_warning("Failed to load seafile.conf.\n");
        ret = -1;
        goto out;
    }

    set_syslog_config (key_file);

out:
    g_key_file_free (key_file);
    g_free (seafile_conf);

    return ret;
}


int main (int argc, char **argv)
{
    if (argc <= 1) {
        usage ();
        exit (1);
    }

    char *config_dir = DEFAULT_CONFIG_DIR;
    char *central_config_dir = NULL;
    char *seafile_dir = NULL;
    char *logdir = NULL;
    char *ccnet_debug_level_str = "info";
    char *seafile_debug_level_str = "debug";
    int daemon_mode = 1;
    gboolean test_conf = FALSE;

    int c;
    while ((c = getopt_long (argc, argv, short_opts,
                             long_opts, NULL)) != EOF)
    {
        switch (c) {
        case 'h':
            usage ();
            exit(1);
            break;
        case 'v':
            fprintf (stderr, "seafile-controller version 1.0\n");
            exit(1);
            break;
        case 't':
            test_conf = TRUE;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'F':
            central_config_dir = g_strdup(optarg);
            break;
        case 'd':
            seafile_dir = g_strdup(optarg);
            break;
        case 'f':
            daemon_mode = 0;
            break;
        case 'L':
            logdir = g_strdup(optarg);
            break;
        case 'g':
            ccnet_debug_level_str = optarg;
            break;
        case 'G':
            seafile_debug_level_str = optarg;
            break;
        case 'P':
            controller_pidfile = optarg;
            break;
        default:
            usage ();
            exit (1);
        }
    }

#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif
#if !GLIB_CHECK_VERSION(2,32,0)
    g_thread_init (NULL);
#endif

    if (!seafile_dir) {
        fprintf (stderr, "<seafile_dir> must be specified with --seafile-dir\n");
        exit(1);
    }

    if (!central_config_dir) {
        fprintf (stderr, "<central_config_dir> must be specified with --central-config-dir\n");
        exit(1);
    }

    central_config_dir = ccnet_expand_path (central_config_dir);
    config_dir = ccnet_expand_path (config_dir);
    seafile_dir = ccnet_expand_path (seafile_dir);

    if (test_conf) {
        test_config (central_config_dir, config_dir, seafile_dir);
    }

    ctl = g_new0 (SeafileController, 1);
    if (seaf_controller_init (ctl, central_config_dir, config_dir, seafile_dir, logdir) < 0) {
        controller_exit(1);
    }

    char *logfile = g_build_filename (ctl->logdir, "controller.log", NULL);
    if (seafile_log_init (logfile, ccnet_debug_level_str,
                          seafile_debug_level_str, "seafile-controller") < 0) {
        fprintf (stderr, "Failed to init log.\n");
        controller_exit (1);
    }

    if (init_syslog_config () < 0) {
        controller_exit (1);
    }

    set_signal_handlers ();

    enabled_go_fileserver = should_start_go_fileserver();

    if (seaf_controller_start () < 0)
        controller_exit (1);

    const char *log_to_stdout_env = g_getenv("SEAFILE_LOG_TO_STDOUT");
    if (g_strcmp0(log_to_stdout_env, "true") == 0) {
        daemon_mode = 0;
    }

#ifndef WIN32
    if (daemon_mode) {
#ifndef __APPLE__
        daemon (1, 0);
#else   /* __APPLE */
        /* daemon is deprecated under APPLE
         * use fork() instead
         * */
        switch (fork ()) {
          case -1:
              seaf_warning ("Failed to daemonize");
              exit (-1);
              break;
          case 0:
              /* all good*/
              break;
          default:
              /* kill origin process */
              exit (0);
        }
#endif  /* __APPLE */
    }
#endif /* !WIN32 */

    if (controller_pidfile == NULL) {
        controller_pidfile = g_strdup(g_getenv ("SEAFILE_PIDFILE"));
    }

    if (controller_pidfile != NULL) {
        if (write_controller_pidfile () < 0) {
            seaf_warning ("Failed to write pidfile %s\n", controller_pidfile);
            return -1;
        }
    }

    run_controller_loop ();

    return 0;
}

