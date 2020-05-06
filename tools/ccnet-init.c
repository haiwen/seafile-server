
#include <sys/stat.h>
#include <sys/param.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <getopt.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "../common/option.h"

#include <openssl/rsa.h>

enum {
    ERR_NAME_NULL = 1,
    ERR_PERMISSION,
    ERR_CONF_FILE,
};

/* Number of bits in the RSA/DSA key.  This value can be set on the command line. */
#define DEFAULT_BITS        2048
static guint32 bits = 0;

static int quiet = 0;

static char *identity_file_peer = NULL;

static char *host_str = NULL;

/* argv0 */
static char *program_name = NULL;


static void make_configure_file (const char *config_file);

static const char *short_opts = "hc:H:F:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "config-dir", required_argument, NULL, 'c' },
    { "central-config-dir", required_argument, NULL, 'F' },
    { "host", required_argument, NULL, 'H' },
    { 0, 0, 0, 0 },
};

void usage (int exit_status)
{
    printf ("Usage: %s [OPTION]...\n", program_name);

    fputs ("Init ccnet configuration directory.\n\n", stdout);

    fputs ("Mandatory arguments to long options are mandatory "
           "for short options too.\n", stdout);

    fputs (""
"  -c, --config-dir=DIR      use DIR as the output ccnet configuration\n"
"                              directory. Default is ~/.ccnet\n"
           , stdout);
    fputs (""
"  -H, --host=<ip or domain> Public addr. Only useful for server.\n"
           , stdout);

    exit (exit_status);
}

int
main(int argc, char **argv)
{
    char *config_dir;
    char *central_config_dir = NULL;
    char *config_file;
    int c;

    program_name = argv[0];

    config_dir = DEFAULT_CONFIG_DIR;

    while ((c = getopt_long(argc, argv,
        short_opts, long_opts, NULL)) != EOF) {
        switch (c) {
        case 'h':
            usage (1);
            break;
        case 'F':
            central_config_dir = strdup(optarg);
            break;
        case 'c':
            config_dir = strdup(optarg);
            break;
        case 'H':
            host_str = strdup (optarg);
            break;
        default:
            usage(1);
        }
    }

    OpenSSL_add_all_algorithms();  

    if (RAND_status() != 1) {   /* it should be seeded automatically */
        fprintf(stderr, "PRNG is not seeded\n");
        exit (1);
    }

    if (bits == 0)
        bits = DEFAULT_BITS;

    /* create dir */
    if (g_mkdir(config_dir, 0700) < 0) {
        fprintf (stderr, "Make dir %s error: %s\n",
                 config_dir, strerror(errno));
        exit(-ERR_PERMISSION);
    }

    struct stat st;
    if (central_config_dir && g_stat(central_config_dir, &st) < 0 &&
        g_mkdir(central_config_dir, 0700) < 0) {
        fprintf(stderr, "Make dir %s error: %s\n", central_config_dir,
                strerror(errno));
        exit(-ERR_PERMISSION);
    }

    /* make configure file */
    config_file = g_build_filename (central_config_dir ? central_config_dir : config_dir, CONFIG_FILE_NAME, NULL);
    make_configure_file (config_file);

    printf ("Successly create configuration dir %s.\n", config_dir);
    exit(0);
}


static void
make_configure_file (const char *config_file)
{
    FILE *fp;

    if ((fp = g_fopen(config_file, "wb")) == NULL) {
        fprintf (stderr, "Open config file %s error: %s\n",
                 config_file, strerror(errno));
        exit(-ERR_CONF_FILE);
    }

    fprintf (fp, "[General]\n");
    if (host_str)
        fprintf (fp, "SERVICE_URL = http://%s:8000\n", host_str);

    fprintf (fp, "\n");
    fclose (fp);

    fprintf (stdout, "done\n");
}
