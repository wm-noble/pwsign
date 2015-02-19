
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "getopt.h"
#include "dirent.h"
#include "sys/types.h"
#include "sys/stat.h"

static char vers_msg[] =
	"pwsign version 1\n"
	"Written by Will Noble.\n",
	help_msg[] =
	"Usage: pwsign [OPTION] CODE [FILE]...\n"
	"Sign specified files with password CODE.\n\n"
	"Options:\n"
	"  -d, --delete         Delete the input files after signing (or unsigning).\n"
	"      --help           Print this message and exit.\n"
	"  -o, --output=<file>  Output to specified file (when reading from stdin).\n"
	"  -r, --recursive      Sign the contents of a directory recursively.\n"
	"  -u, --unsign         Unsign the specified files rather than sign them.\n"
	"                       (the algorithm is the same, but this option handles the\n"
	"                       \'.pws\' file extension)\n"
	"  -v, --verbose        Explain what is happening.\n"
	"      --version        Print version information and exit.\n\n"
	"For each file specified, pwsign encrypts the file using a simple xor-cipher,\n"
	"storing the output in a new file with extension \'.pws\'.\n"
	"THIS IS NOT MEANT TO BE A SECURE ENCRYPTION; it's basic shit.\n"
	"If the --unsign flag is set, pwsign unencrypts each file, which is the same\n"
	"algorithm as encryption, but stores the output in a new file without the \'.pws\'\n"
	"extension. If an output file already exists, it is overwritten. If no input\n"
	"files are specified, pwsign reads from stdin and writes to stdout (unless\n"
	"otherwise indicated via --output).\n\n"
	"Examples:\n"
	"  pwsign 12345 foo.txt     - signs \'foo.txt\' with code \'12345\' to \'foo.txt.pws\'\n"
	"  pwsign -ud abc *.txt.pws - unsigns all encrypted text files in current\n"
	"                             directory with code \'abc\', storing output as *.txt\n"
	"                             and deleting all processed files when done",
	more_info[] = "Try `pwsign --help' for more information.\n",
	fout_err[] = "error opening output file \"%s\"\n";

static char *arg_perms[] = {
	"-r", "-rd", "-ru", "-rdu", "-rv", "-rdv", "-ruv", "-rduv"
};
static int del_fl = 0, help_fl = 0, recu_fl = 0, uns_fl = 0, verb_fl = 0, vers_fl = 0;

int main(int argc, char **argv);

static int is_dir(char *path, char *name) {
	char *full = (char*)malloc(strlen(path) + strlen(name) + 2);
	sprintf(full, "%s/%s", path, name);
	struct stat *s = (struct stat*)malloc(sizeof(struct stat));
	int r = !stat(full, s) && S_ISDIR(s->st_mode);
	free(s);
	free(full);
	return r;
}
static int do_dir(char *path, char *code) {
	DIR *dir;
	if ((dir = opendir(path))) {
		if (recu_fl) {
			int fix_len = strlen(path) + 2;
			struct dirent *de;
			char **argv = (char**)malloc(4 * sizeof(char*));
			argv[0] = "pwsign";
			argv[1] = arg_perms[2 * (2 * verb_fl + uns_fl) + del_fl];
			argv[2] = code;
			argv[3] = NULL;
			while ((de = readdir(dir)) != NULL) {
				if (strcmp(de->d_name, "..") && strcmp(de->d_name, ".")) {
					char *cu = de->d_name, *next;
					while ((next = strchr(cu + 1, '.')))
						cu = next;
					if (!(uns_fl || cu == de->d_name || strcmp(cu + 1, "pws") || is_dir(path, de->d_name)))
						continue;
					else if (uns_fl && (cu == de->d_name || strcmp(cu + 1, "pws")))
						if (!is_dir(path, de->d_name))
							continue;
					if ((argv[3] = (char*)realloc(argv[3], fix_len + strlen(de->d_name)))) {
						sprintf(argv[3], "%s/%s", path, de->d_name);
						main(4, argv);
					} else {
						fputs("memory error\n", stderr);
						return -1;
					}
				}
			}
			if (argv[3])
				free(argv[3]);
			free(argv);
		}
		closedir(dir);
		return 1;
	} else
		return 0;
}

static char *init_buffer(int *buff_size) {
	char *buff;
	while (!(buff = (char*)malloc(*buff_size)))
		if (!(*buff_size /= 2)) {
			fputs("memory error\n", stderr);
			break;
		}
	return buff;
}

int encode_string(char *dat, unsigned int dl, char *code, int place) {
	int cl = strlen(code);
	int i = 0;
	while (dl--) {
        char c = code[(i + place) % cl];
		dat[i++] ^= c;
    }
	return (i + place) % cl;
}
static int encode(FILE *in, FILE *out, char *code, char *buff, int buff_size, int place) {
	int cont = 1;
	do {
		unsigned int r = fread(buff, sizeof(char), buff_size, in);
		if (r != buff_size) {
			if (!feof(in)) {
				fputs("error reading from input\n", stderr);
				return 1;
			}
			cont = 0;
		}
		place = encode_string(buff, r, code, place);
		if (fwrite(buff, sizeof(char), r, out) != r) {
			fputs("error writing to output\n", stderr);
			return 2;
		}
	} while (cont);
	return 0;
}

static char *new_filenm(char *old) {
	char *r = NULL;
	if (old) {
		char *cu = old, *next;
		while ((next = strchr(cu + 1, '/')))
			cu = next;
		if (old[cu == old ? 0 : ((int)(cu - old) + 1)] == '-' && (r = (char*)malloc(strlen(old)))) {
			if (cu == old)
				strcpy(r, old + 1);
			else {
				int l = (int)(cu - old) + 1;
				strncpy(r, old, l);
				strcpy(r + l, cu + 2);
			}
		} else if ((r = (char*)malloc(strlen(old) + 5))) {
			strcpy(r, old);
			strcat(r, ".pws");
		}
	}
	return r;
}
static char *new_filenm_uns(char *old) {
	char *r = NULL;
	if (old) {
		char *cu = old, *next;
		while ((next = strchr(cu + 1, '.')))
			cu = next;
		int l;
		if (cu == old) { /* no file extension: prepend name with '-' */
__prepend :
			l = strlen(old);
			r = (char*)malloc(l + 2);
			if (r) {
				while ((next = strchr(cu + 1, '/')))
					cu = next;
				if (cu != old) { /* filename contains directories */
					l = (int)(cu - old) + 1;
					strncpy(r, old, l);
					r[l] = '-';
					strcpy(r + l + 1, old + l);
				} else {
					r[0] = '-';
					strcpy(r + 1, old);
				}
			}
		} else {
			/* check that extension is .pws */
			l = (int)(cu - old);
			if (strcmp(old + l + 1, "pws")) { /* extension is NOT .pws: prepend name with '-' */
				cu = old;
				goto __prepend;
			}
			r = (char*)malloc(l + 1);
			if (r) {
				strncpy(r, old, l);
				r[l] = '\0';
			}
		}
	}
	return r;
}
int sign(char *file, char *code, char *buff, int buff_size) {
	int r = 0;
	if (verb_fl)
		fprintf(stderr, uns_fl ? "unsigning file \"%s\" from code \"%s\".\n"
		              : "signing file \"%s\" with code \"%s\".\n", file, code);
	FILE *in = fopen(file, "r");
	if (!in) {
		fprintf(stderr, "error opening input file \"%s\"\n", file);
		r = -1;
		goto __fuck_0;
	}
	char *outnm = uns_fl ? new_filenm_uns(file) : new_filenm(file);
	if (!outnm) {
		fputs("memory error\n", stderr);
		r = -1;
		goto __fuck_1;
	}
	if (verb_fl)
		fprintf(stderr, "output = file \"%s\"\n", outnm);
	FILE *out = fopen(outnm, "w");
	if (!out) {
		fprintf(stderr, fout_err, outnm);
		r = -1;
		goto __fuck_2;
	}
	if ((r = encode(in, out, code, buff, buff_size, 0))) {
		fprintf(stderr, "%s file: \"%s\"\n", r == 1 ? "input" : "output", r == 1 ? file : outnm);
		r = -1;
	} else if (del_fl) {
		char *cmd = (char*)malloc(strlen(file) + 4);
		if (cmd) {
			cmd[0] = 'r';
			cmd[1] = 'm';
			cmd[2] = ' ';
			strcpy(cmd + 3, file);
			if (verb_fl)
				fprintf(stderr, "%s\n", cmd);
			system(cmd);
			free(cmd);
		} else
			fprintf(stderr, "memory error: couldn't remove file \"%s\"\n", file);
		
	}
	fclose(out);
__fuck_2 :
	free(outnm);
__fuck_1 :
	fclose(in);
__fuck_0 :
	return r;
}

int main(int argc, char **argv) {
	/* options used by getopt_long */
	static struct option long_opts[] = {
		{"delete", no_argument, &del_fl, 1},
		{"help", no_argument, &help_fl, 1},
		{"output", required_argument, NULL, 'o'},
		{"recursive", no_argument, &recu_fl, 1},
		{"unsign", no_argument, &uns_fl, 1},
		{"verbose", no_argument, &verb_fl, 1},
		{"version", no_argument, &vers_fl, 1},
		{0, 0, 0, 0}
	};

	char *filter_out = NULL;
	int opt_ind = 0,
		c;
	while ((c = getopt_long(argc, argv, "dho:ruv", long_opts, &opt_ind)) != -1)
		switch (c) {
		case 0 :
			/* When a flag has been automatically set */
			continue;
		case 'd' :
			del_fl = 1;
			break;
		case 'h' :
			help_fl = 1;
			break;
		case 'o' :
			filter_out = optarg;
			break;
		case 'r' :
			recu_fl = 1;
			break;
		case 'u' :
			uns_fl = 1;
			break;
		case 'v' :
			verb_fl = 1;
			break;
		case '?' :
			fputs(more_info, stderr);
			return -1;
		}
	int r = 0;
	if (help_fl) {
		puts(vers_msg);
		puts(help_msg);
	} else if (vers_fl)
		puts(vers_msg);
	else if (optind < argc) {
		int buff_size = 2048;
		char *buff = init_buffer(&buff_size);
		if (buff) {
			char *code = argv[optind];
			if (optind + 1 < argc) {
				int i = optind + 1;
				do {
					if (do_dir(argv[i], code))
						continue;
					else if (sign(argv[i], code, buff, buff_size))
						r = -1;
				} while (++i < argc);
			} else { /* no input files specified: read from stdin */
				FILE *out = filter_out ? fopen(filter_out, "w") : stdout;
				if (out) {
					if ((r = encode(stdin, out, code, buff, buff_size, 0))) {
						fprintf(stderr, "%s file: \"%s\"\n",
							r == 1 ? "input" : "output",
							r == 1 ? "<stdin>" : (filter_out ? filter_out : "<stdout>"));
						r = -1;
					}
				} else {
					fprintf(stderr, fout_err, filter_out);
					r = -1;
				}
			}
			free(buff);
		} else
			r = -1;
	} else {
		fputs("pwsign: missing argument\n", stderr);
		fputs(more_info, stderr);
		r = -1;
	}
	return r;
}

