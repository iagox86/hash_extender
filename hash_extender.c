#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "buffer.h"
#include "util.h"

#include "hash_extender_md4.h"
#include "hash_extender_md5.h"
#include "hash_extender_ripemd160.h"
#include "hash_extender_sha.h"
#include "hash_extender_sha1.h"
#include "hash_extender_sha256.h"
#include "hash_extender_sha512.h"

#ifndef DISABLE_WHIRLPOOL
#include "hash_extender_whirlpool.h"
#endif

#define NAME "Hash Extender"
#define VERSION "0.01"
#define AUTHOR "Ron Bowes"
#define EMAIL "ron@skullsecurity.net"

/* Define the types of the append, signature, and evil signature functions so
 * we can use them as function pointers later. */
typedef uint8_t *(append_data_t)(uint8_t *data, uint64_t data_length, uint64_t secret_length, uint8_t *append, uint64_t append_length, uint64_t *new_length);
typedef void(gen_signature_t)(uint8_t *secret, uint64_t secret_length, uint8_t *data, uint64_t data_length, uint8_t signature[]);
typedef void(gen_signature_evil_t)(uint64_t secret_length, uint64_t data_length, uint8_t original_signature[], uint8_t *append, uint64_t append_length, uint8_t new_signature[]);

/* Define a list of structs. */
typedef struct
{
  char                 *name;
  uint64_t              hash_size;
  append_data_t        *append_data;
  gen_signature_t      *gen_signature;
  gen_signature_evil_t *gen_signature_evil;
} hash_type_t;

hash_type_t hash_types[] = {
  {"md4",       MD4_DIGEST_LENGTH,       md4_append_data,       md4_gen_signature,       md4_gen_signature_evil},
  {"md5",       MD5_DIGEST_LENGTH,       md5_append_data,       md5_gen_signature,       md5_gen_signature_evil},
  {"ripemd160", RIPEMD160_DIGEST_LENGTH, ripemd160_append_data, ripemd160_gen_signature, ripemd160_gen_signature_evil},
  {"sha",       SHA_DIGEST_LENGTH,       sha_append_data,       sha_gen_signature,       sha_gen_signature_evil},
  {"sha1",      SHA_DIGEST_LENGTH,       sha1_append_data,      sha1_gen_signature,      sha1_gen_signature_evil},
  {"sha256",    SHA256_DIGEST_LENGTH,    sha256_append_data,    sha256_gen_signature,    sha256_gen_signature_evil},
  {"sha512",    SHA512_DIGEST_LENGTH,    sha512_append_data,    sha512_gen_signature,    sha512_gen_signature_evil},
#ifndef DISABLE_WHIRLPOOL
  {"whirlpool", WHIRLPOOL_DIGEST_LENGTH, whirlpool_append_data, whirlpool_gen_signature, whirlpool_gen_signature_evil},
#endif
  {0, 0, 0, 0, 0}
};

#define MAX_DIGEST_LENGTH SHA512_DIGEST_LENGTH

/* Define the various options we can set. */
typedef struct {
  char     *data_raw;
  format_t  data_format;
  uint8_t  *data;
  uint64_t  data_length;

  char     *append_raw;
  format_t  append_format;
  uint8_t  *append;
  uint64_t  append_length;

  char     *filename;

  char     *signature_raw;
  format_t  signature_format;
  uint8_t  *signature;
  uint64_t  signature_length;

  uint8_t   formats[sizeof(hash_types) / sizeof(hash_type_t)];
  uint8_t   format_count;

  uint64_t  secret_min;
  uint64_t  secret_max;

  uint8_t   out_table;
  format_t  out_data;
  format_t  out_signature;

  uint8_t   quiet;
} options_t;

/* Output the data in the chosen format. */
void output(options_t *options, char *type, uint64_t secret_length, uint8_t *new_data, uint64_t new_data_length, uint8_t *new_signature, uint64_t new_signature_length)
{
  if(options->quiet)
  {
    output_format(options->out_signature, new_signature, new_signature_length);
    output_format(options->out_data, new_data, new_data_length);
  }
  else if(options->out_table)
  {
    printf("%-9s ", type);
    output_format(options->out_signature, new_signature, new_signature_length);
    printf(" ");
    output_format(options->out_data, new_data, new_data_length);
    printf("\n");
  }
  else
  {
    printf("Type: %s\n", type);

    printf("Secret length: %"PRId64"\n", secret_length);

    printf("New signature: ");
    output_format(options->out_signature, new_signature, new_signature_length);
    printf("\n");

    printf("New string: ");
    output_format(options->out_data, new_data, new_data_length);
    printf("\n");

    printf("\n");
  }
}

void go(options_t *options)
{
  uint32_t i;
  size_t secret_length;

  /* Loop through the possible lengths of 'secret'. */
  for(secret_length = options->secret_min; secret_length <= options->secret_max; secret_length++)
  {
    uint8_t *new_data;
    uint8_t new_signature[MAX_DIGEST_LENGTH];
    uint64_t new_length;

    /* Loop through the possible hashtypes. */
    for(i = 0; hash_types[i].name; i++)
    {
      /* If the hashtype is enabled, ... */
      if(options->formats[i])
      {
        /* Generate the new data. */
        new_data = hash_types[i].append_data(options->data, options->data_length, secret_length, options->append, options->append_length, &new_length);

        /* Generate the signature for it.  */
        hash_types[i].gen_signature_evil(secret_length, options->data_length, options->signature, options->append, options->append_length, new_signature);

        /* Display the result to the user. */
        output(options, hash_types[i].name, secret_length, new_data, new_length, new_signature, hash_types[i].hash_size);

        /* Free the buffer. */
        free(new_data);
      }
    }
  }
}

void usage(char *program)
{
  printf("\n");
  printf("--------------------------------------------------------------------------------\n");
  printf("HASH EXTENDER\n");
  printf("--------------------------------------------------------------------------------\n");
  printf("\n");
  printf("By Ron Bowes <ron @ skullsecurity.net>\n");
  printf("\n");
  printf("See LICENSE.txt for license information.\n");
  printf("\n");
  printf("Usage: %s <--data=<data>|--file=<file>> --signature=<signature> --format=<format> [options]\n", program);
  printf("\n");
  printf("INPUT OPTIONS\n");
  printf("-d --data=<data>\n");
  printf("      The original string that we're going to extend.\n");
  printf("--data-format=<raw|html|hex|cstr>\n");
  printf("      The format the string is being passed in as. Default: raw.\n");
  printf("--file=<file>\n");
  printf("      As an alternative to specifying a string, this reads the original string\n");
  printf("      as a file.\n");
  printf("-s --signature=<sig>\n");
  printf("      The original signature.\n");
  printf("--signature-format=<raw|html|hex|cstr>\n");
  printf("      The format the signature is being passed in as. Default: hex.\n");
  printf("-a --append=<data>\n");
  printf("      The data to append to the string. Default: raw.\n");
  printf("--append-format=<raw|html|hex|cstr>\n");
  printf("-f --format=<all|md4|md5|ripemd160|sha|sha1|sha256|sha512|whirlpool> [REQUIRED]\n");
  printf("      The hash_type of the signature. This can be given multiple times if you\n");
  printf("      want to try multiple signatures. 'all' will base the chosen types off\n");
  printf("      the size of the signature and use the hash(es) that make sense.\n");
  printf("-l --secret=<length>\n");
  printf("      The length of the secret, if known. Default: 8.\n");
  printf("--secret-min=<min>\n");
  printf("--secret-max=<max>\n");
  printf("      Try different secret lengths (both options are required)\n");
  printf("\n");
  printf("OUTPUT OPTIONS\n");
  printf("--table\n");
  printf("      Output the string in a table format.\n");
  printf("--out-data-format=<raw|html|html-pure|hex|cstr|cstr-pure|none>\n");
  printf("      Output data format.\n");
  printf("--out-signature-format=<raw|htmlhtml-pure||hex|cstr|cstr-pure|none>\n");
  printf("      Output signature format.\n");
  printf("\n");
  printf("OTHER OPTIONS\n");
  printf("-h --help \n");
  printf("      Display the usage (this).\n");
  printf("--test\n");
  printf("      Run the test suite.\n");
  printf("-q --quiet\n");
  printf("      Only output what's absolutely necessary (the output string and the\n");
  printf("      signature)\n");
}

void error(char *program, char *message)
{
  usage(program);
  printf("\n");
  printf("ERROR: %s\n", message);
  exit(1);
}

int main(int argc, char *argv[])
{
  options_t    options;
  char         c;
  int          option_index;
  const char  *option_name;
  uint32_t     i;

  struct option long_options[] =
  {
    {"data",                 required_argument, 0, 0}, /* Input string. */
    {"d",                    required_argument, 0, 0},
    {"file",                 required_argument, 0, 0}, /* Input file. */
    {"data-format",          required_argument, 0, 0}, /* Input string format. */
    {"append",               required_argument, 0, 0}, /* Append string. */
    {"a",                    required_argument, 0, 0}, 
    {"append-format",        required_argument, 0, 0}, /* Append format. */
    {"signature",            required_argument, 0, 0}, /* Input signature. */
    {"s",                    required_argument, 0, 0},
    {"signature-format",     required_argument, 0, 0}, /* Input signature format. */
    {"format",               required_argument, 0, 0}, /* Hash format. */
    {"f",                    required_argument, 0, 0},
    {"secret",               required_argument, 0, 0}, /* Secret length. */
    {"l",                    required_argument, 0, 0},
    {"secret-min",           required_argument, 0, 0}, /* Secret min length. */
    {"secret-max",           required_argument, 0, 0}, /* Secret max length. */
    {"table",                no_argument,       0, 0}, /* Output as a table. */
    {"out-data-format",      required_argument, 0, 0}, /* Output string format. */
    {"out-signature-format", required_argument, 0, 0}, /* Output signature format. */
    {"help",                 no_argument,       0, 0}, /* Help. */
    {"h",                    no_argument,       0, 0},
    {"H",                    no_argument,       0, 0},
    {"test",                 no_argument,       0, 0}, /* Test. */
    {"quiet",                no_argument,       0, 0}, /* Quiet. */
    {"q",                    no_argument,       0, 0},
    {"version",              no_argument,       0, 0}, /* Version. */
    {"V",                    no_argument,       0, 0},
    {0, 0, 0, 0}
  };

  memset(&options, 0, sizeof(options_t));

  opterr = 0;
  while((c = getopt_long_only(argc, argv, "", long_options, &option_index)) != EOF)
  {
    switch(c)
    {
      case 0:
        option_name = long_options[option_index].name;

        if(!strcmp(option_name, "data") || !strcmp(option_name, "d"))
        {
          options.data_raw = optarg;
        }
        else if(!strcmp(option_name, "data-format"))
        {
          if(!strcmp(optarg, "raw"))
            options.data_format = FORMAT_RAW;
          else if(!strcmp(optarg, "hex"))
            options.data_format = FORMAT_HEX;
          else if(!strcmp(optarg, "html"))
            options.data_format = FORMAT_HTML;
          else if(!strcmp(optarg, "cstr"))
            options.data_format = FORMAT_CSTR;
          else
            error(argv[0], "Unknown option passed to --data-format");
        }
        else if(!strcmp(option_name, "file"))
        {
          options.filename = optarg;
        }
        else if(!strcmp(option_name, "append") || !strcmp(option_name, "a"))
        {
          options.append_raw = optarg;
        }
        else if(!strcmp(option_name, "append-format"))
        {
          if(!strcmp(optarg, "raw"))
            options.append_format = FORMAT_RAW;
          else if(!strcmp(optarg, "hex"))
            options.append_format = FORMAT_HEX;
          else if(!strcmp(optarg, "html"))
            options.append_format = FORMAT_HTML;
          else if(!strcmp(optarg, "cstr"))
            options.append_format = FORMAT_CSTR;
          else
            error(argv[0], "Unknown option passed to --append-format");
        }
        else if(!strcmp(option_name, "signature") || !strcmp(option_name, "s"))
        {
          options.signature_raw = optarg;
        }
        else if(!strcmp(option_name, "signature-format"))
        {
          if(!strcmp(optarg, "raw"))
            options.signature_format = FORMAT_RAW;
          else if(!strcmp(optarg, "hex"))
            options.signature_format = FORMAT_HEX;
          else if(!strcmp(optarg, "html"))
            options.signature_format = FORMAT_HTML;
          else if(!strcmp(optarg, "cstr"))
            options.signature_format = FORMAT_CSTR;
          else
            error(argv[0], "Unknown option passed to --signature-format");
        }
        else if(!strcmp(option_name, "format") || !strcmp(option_name, "f"))
        {
          for(i = 0; hash_types[i].name; i++)
          {
            if(!strcmp(optarg, hash_types[i].name))
            {
              options.formats[i] = 1;
              options.format_count++;
              break;
            }
          }
        }
        else if(!strcmp(option_name, "secret"))
        {
          if(options.secret_min != 0 || options.secret_max != 0)
            error(argv[0], "--secret is not compatible with --secret-min or --secret-max");
          options.secret_min = atoi(optarg);
          options.secret_max = atoi(optarg);
        }
        else if(!strcmp(option_name, "secret-min"))
        {
          if(options.secret_min != 0)
            error(argv[0], "--secret is not compatible with --secret-min or --secret-max");
          options.secret_min = atoi(optarg);
        }
        else if(!strcmp(option_name, "secret-max"))
        {
          if(options.secret_max != 0)
            error(argv[0], "--secret is not compatible with --secret-min or --secret-max");
          options.secret_max = atoi(optarg);
        }
        else if(!strcmp(option_name, "table"))
        {
          options.out_table = 1;
        }
        else if(!strcmp(option_name, "out-data-format"))
        {
          if(!strcmp(optarg, "raw"))
            options.out_data = FORMAT_RAW;
          else if(!strcmp(optarg, "html"))
            options.out_data = FORMAT_HTML;
          else if(!strcmp(optarg, "html-pure"))
            options.out_data = FORMAT_HTML_PURE;
          else if(!strcmp(optarg, "hex"))
            options.out_data = FORMAT_HEX;
          else if(!strcmp(optarg, "cstr"))
            options.out_data = FORMAT_CSTR;
          else if(!strcmp(optarg, "cstr-pure"))
            options.out_data = FORMAT_CSTR_PURE;
          else if(!strcmp(optarg, "none"))
            options.out_data = FORMAT_NONE;
          else
            error(argv[0], "Unknown option passed to --out-data-format");
        }
        else if(!strcmp(option_name, "out-signature-format"))
        {
          if(!strcmp(optarg, "raw"))
            options.out_signature = FORMAT_RAW;
          else if(!strcmp(optarg, "html"))
            options.out_signature = FORMAT_HTML;
          else if(!strcmp(optarg, "html-pure"))
            options.out_signature = FORMAT_HTML_PURE;
          else if(!strcmp(optarg, "hex"))
            options.out_signature = FORMAT_HEX;
          else if(!strcmp(optarg, "cstr"))
            options.out_signature = FORMAT_CSTR;
          else if(!strcmp(optarg, "cstr-pure"))
            options.out_signature = FORMAT_CSTR_PURE;
          else if(!strcmp(optarg, "none"))
            options.out_signature = FORMAT_NONE;
          else
            error(argv[0], "Unknown option passed to --out-signature-format");
        }
        else if(!strcmp(option_name, "help") || !strcmp(option_name, "h"))
        {
          usage(argv[0]);
          exit(0);
        }
        else if(!strcmp(option_name, "test"))
        {
          if(system("hash_extender_test"))
          {
            if(system("./hash_extender_test"))
            {
              fprintf(stderr, "Can't figure out how to run hash_extender_test!");
            }
          }
          exit(0);
        }
        else if(!strcmp(option_name, "quiet") || !strcmp(option_name, "q"))
        {
          options.quiet = 1;
        }
        else if(!strcmp(option_name, "version") || !strcmp(option_name, "V"))
        {
          printf("%s v%s by %s <%s>\n", NAME, VERSION, AUTHOR, EMAIL);
          exit(0);
        }
        else
        {
          error(argv[0], "Unknown option");
        }

        break;

      case '?':
      default:
        error(argv[0], "Couldn't parse argument");
    }
  }

  /* Sanity checks. */
  if(options.data_raw == NULL && options.filename == NULL)
  {
    error(argv[0], "--data or --file is required");
  }
  if(options.data_raw != NULL && options.filename != NULL)
  {
    error(argv[0], "--data and --file cannot be used together");
  }
  if(options.filename != NULL && options.data_format != 0)
  {
    error(argv[0], "--file amd --data-format cannot be used together");
  }
  if(options.append_raw == NULL)
  {
    error(argv[0], "--append is required");
  }
  if(options.signature_raw == NULL)
  {
    error(argv[0], "--signature is required");
  }
  if(options.out_table && options.quiet)
  {
    error(argv[0], "--table and --quiet are not compatible");
  }

  /* Set some sane defaults. */
  if(options.secret_min == 0 && options.secret_max == 0)
  {
    options.secret_min = 8;
    options.secret_max = 8;
  }
  else if(options.secret_min == 0 || options.secret_max == 0)
  {
    error(argv[0], "--secret-min and --secret-max can't be used separately, please specify both.");
  }

  if(options.data_format == 0)      options.data_format      = FORMAT_RAW;
  if(options.append_format == 0)    options.append_format    = FORMAT_RAW;
  if(options.signature_format == 0) options.signature_format = FORMAT_HEX;
  if(options.out_data == 0)         options.out_data         = FORMAT_HEX;
  if(options.out_signature == 0)    options.out_signature    = FORMAT_HEX;

  /* Convert the data appropriately. */
  if(options.data_raw)
    options.data = format_to_raw(options.data_raw, options.data_format, &options.data_length);
  else
    options.data = read_file(options.filename, &options.data_length);

  /* Convert the appended data. */
  options.append = format_to_raw(options.append_raw, options.append_format, &options.append_length);

  /* Convert the signature. */
  options.signature = format_to_raw(options.signature_raw, options.signature_format, &options.signature_length);

  /* If no formats were given, try to guess it. */
  if(options.format_count == 0)
  {
    /* If no signature was given, figure out which, if any, make sense. */
    for(i = 0; hash_types[i].name; i++)
    {
      if(options.signature_length == hash_types[i].hash_size)
      {
        options.formats[i] = 1;
        options.format_count++;
      }
    }
  }
  if(options.format_count == 0)
  {
    error(argv[0], "No valid hash formats were found");
  }

  /* Sanity check the length of the signature. */
  for(i = 0; hash_types[i].name; i++)
  {
    if(options.formats[i] && options.signature_length != hash_types[i].hash_size)
    {
      fprintf(stderr, "%s's signature needs to be %"PRId64" bytes", hash_types[i].name, hash_types[i].hash_size);
      exit(1);
    }
  }

  go(&options);

  free(options.data);
  free(options.append);
  free(options.signature);

  return 0;
}

