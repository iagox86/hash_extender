#include <ctype.h>
#include <err.h>
#include <getopt.h>

#include "buffer.h"
#include "formats.h"
#include "util.h"

#include "hash_extender_engine.h"

#define NAME    "Hash Extender"
#define VERSION "0.02"
#define AUTHOR  "Ron Bowes"
#define EMAIL   "ron@skullsecurity.net"

/* Define the various options we can set. */
typedef struct {
  char     *data_raw;
  char     *data_format;
  uint8_t  *data;
  uint64_t  data_length;

  char     *append_raw;
  char     *append_format;
  uint8_t  *append;
  uint64_t  append_length;

  char     *filename;

  char     *signature_raw;
  char     *signature_format;
  uint8_t  *signature;
  uint64_t  signature_length;

  char    **formats;
  uint8_t   format_count;

  uint64_t  secret_min;
  uint64_t  secret_max;

  uint8_t   out_table;
  char     *out_data_format;
  char     *out_signature_format;

  uint8_t   quiet;
} options_t;

static const char *program;

static void output_format(char *format, uint8_t *data, uint64_t data_length)
{
  uint8_t *out_data;
  uint64_t out_length;

  out_data = format_encode(format, data, data_length, &out_length);
  fwrite(out_data, sizeof(uint8_t), out_length, stdout);
  free(out_data);
}

/* Output the data in the chosen format. */
static void output(options_t *options, char *type, uint64_t secret_length, uint8_t *new_data, uint64_t new_data_length, uint8_t *new_signature)
{
  if(options->quiet)
  {
    output_format(options->out_signature_format, new_signature, hash_type_digest_size(type));
    output_format(options->out_data_format, new_data, new_data_length);
  }
  else if(options->out_table)
  {
    printf("%-9s ", type);
    output_format(options->out_signature_format, new_signature, hash_type_digest_size(type));
    printf(" ");
    output_format(options->out_data_format, new_data, new_data_length);
    printf("\n");
  }
  else
  {
    printf("Type: %s\n", type);

    printf("Secret length: %"PRId64"\n", secret_length);

    printf("New signature: ");
    output_format(options->out_signature_format, new_signature, hash_type_digest_size(type));
    printf("\n");

    printf("New string: ");
    output_format(options->out_data_format, new_data, new_data_length);
    printf("\n");

    printf("\n");
  }
}

static void go(options_t *options)
{
  size_t secret_length;

  /* Loop through the possible lengths of 'secret'. */
  for(secret_length = options->secret_min; secret_length <= options->secret_max; secret_length++)
  {
    uint8_t *new_data;
    uint8_t new_signature[MAX_DIGEST_LENGTH];
    uint64_t new_length;
    uint32_t i;

    /* Loop through the possible hashtypes. */
    for(i = 0; i < options->format_count; i++)
    {
      char *format = options->formats[i];

      /* Generate the new data. */
      new_data = hash_append_data(format, options->data, options->data_length, secret_length, options->append, options->append_length, &new_length);

      /* Generate the signature for it.  */
      hash_gen_signature_evil(format, secret_length, options->data_length, options->signature, options->append, options->append_length, new_signature);

      /* Display the result to the user. */
      output(options, format, secret_length, new_data, new_length, new_signature);

      /* Free the buffer. */
      free(new_data);
    }
  }
}

static void usage(void)
{
  printf(
    "\n"
    "--------------------------------------------------------------------------------\n"
    "HASH EXTENDER\n"
    "--------------------------------------------------------------------------------\n"
    "\n"
    "By Ron Bowes <ron @ skullsecurity.net>\n"
    "\n"
    "See LICENSE.txt for license information.\n"
    "\n"
    );

  printf(
    "Usage: %s <--data=<data>|--file=<file>> --signature=<signature> --format=<format> [options]\n",
    program);

  printf(
    "\n"
    "INPUT OPTIONS\n"
    "-d --data=<data>\n"
    "      The original string that we're going to extend.\n"
    "--data-format=<format>\n"
    "      The format the string is being passed in as. Default: raw.\n"
    "      Valid formats: %s\n"
    "--file=<file>\n"
    "      As an alternative to specifying a string, this reads the original string\n"
    "      as a file.\n"
    "-s --signature=<sig>\n"
    "      The original signature.\n"
    "--signature-format=<format>\n"
    "      The format the signature is being passed in as. Default: hex.\n"
    "      Valid formats: %s\n"
    "-a --append=<data>\n"
    "      The data to append to the string. Default: raw.\n"
    "--append-format=<format>\n"
    "      Valid formats: %s\n"
    "-f --format=<all|format> [REQUIRED]\n"
    "      The hash_type of the signature. This can be given multiple times if you\n"
    "      want to try multiple signatures. 'all' will base the chosen types off\n"
    "      the size of the signature and use the hash(es) that make sense.\n"
    "      Valid types: %s\n",
    decode_formats,
    decode_formats,
    decode_formats,
    hash_type_list
    );

  printf(
    "-l --secret=<length>\n"
    "      The length of the secret, if known. Default: 8.\n"
    "--secret-min=<min>\n"
    "--secret-max=<max>\n"
    "      Try different secret lengths (both options are required)\n"
    "\n"
    "OUTPUT OPTIONS\n"
    "--table\n"
    "      Output the string in a table format.\n"
    "--out-data-format=<format>\n"
    "      Output data format.\n"
    "      Valid formats: %s\n"
    "--out-signature-format=<format>\n"
    "      Output signature format.\n"
    "      Valid formats: %s\n"
    "\n"
    "OTHER OPTIONS\n"
    "-h --help \n"
    "      Display the usage (this).\n"
    "--test\n"
    "      Run the test suite.\n"
    "-q --quiet\n"
    "      Only output what's absolutely necessary (the output string and the\n"
    "      signature)\n",
    encode_formats,
    encode_formats
  );

  printf("\n"
    "The arguments you probably want to give are (see above for more details):\n"
    "-d <data>\n"
    "-s <original signature>\n"
    "-a <data to append>\n"
    "-f <hash format>\n"
    "-l <length of secret>\n");

  printf("\n");


  exit(EXIT_FAILURE);
}

static void error(const char *message)
{
  warnx("%s", message);
  usage();
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
  options.formats = (char**) malloc(hash_type_count * sizeof(char*));

  program = argv[0];

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
          if(format_exists(optarg))
            options.data_format = optarg;
          else
            error("Unknown option passed to --data-format");
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
          if(format_exists(optarg))
            options.append_format = optarg;
          else
            error("Unknown option passed to --append-format");
        }
        else if(!strcmp(option_name, "signature") || !strcmp(option_name, "s"))
        {
          options.signature_raw = optarg;
        }
        else if(!strcmp(option_name, "signature-format"))
        {
          if(format_exists(optarg))
            options.signature_format = optarg;
          else
            error("Unknown option passed to --signature-format");
        }
        else if(!strcmp(option_name, "format") || !strcmp(option_name, "f"))
        {
          if(!hash_type_exists(optarg))
            error("Invalid hash type passed to --format");
          options.formats[options.format_count++] = optarg;
        }
        else if(!strcmp(option_name, "secret") || !strcmp(option_name, "l"))
        {
          if(options.secret_min != 0 || options.secret_max != 0)
            error("--secret is not compatible with --secret-min or --secret-max");
          options.secret_min = atoi(optarg);
          options.secret_max = atoi(optarg);
        }
        else if(!strcmp(option_name, "secret-min"))
        {
          if(options.secret_min != 0)
            error("--secret is not compatible with --secret-min or --secret-max");
          options.secret_min = atoi(optarg);
        }
        else if(!strcmp(option_name, "secret-max"))
        {
          if(options.secret_max != 0)
            error("--secret is not compatible with --secret-min or --secret-max");
          options.secret_max = atoi(optarg);
        }
        else if(!strcmp(option_name, "table"))
        {
          options.out_table = 1;
        }
        else if(!strcmp(option_name, "out-data-format"))
        {
          if(format_exists(optarg))
            options.out_data_format = optarg;
          else
            error("Unknown option passed to --out-data-format");
        }
        else if(!strcmp(option_name, "out-signature-format"))
        {
          if(format_exists(optarg))
            options.out_signature_format = optarg;
          else
            error("Unknown option passed to --out-signature-format");
        }
        else if(!strcmp(option_name, "help") || !strcmp(option_name, "h"))
        {
          usage();
        }
        else if(!strcmp(option_name, "test"))
        {
          if(system("hash_extender_test"))
          {
            if(system("./hash_extender_test"))
            {
              errx(EXIT_FAILURE, "Can't figure out how to run hash_extender_test!");
            }
          }
          exit(EXIT_SUCCESS);
        }
        else if(!strcmp(option_name, "quiet") || !strcmp(option_name, "q"))
        {
          options.quiet = 1;
        }
        else if(!strcmp(option_name, "version") || !strcmp(option_name, "V"))
        {
          printf("%s v%s by %s <%s>\n", NAME, VERSION, AUTHOR, EMAIL);
          exit(EXIT_SUCCESS);
        }
        else
        {
          error("Unknown option");
        }

        break;

      case '?':
      default:
        error("Couldn't parse argument");
    }
  }

  /* Sanity checks. */
  if(options.data_raw == NULL && options.filename == NULL)
  {
    error("--data or --file is required");
  }
  if(options.data_raw != NULL && options.filename != NULL)
  {
    error("--data and --file cannot be used together");
  }
  if(options.filename != NULL && options.data_format != 0)
  {
    error("--file amd --data-format cannot be used together");
  }
  if(options.append_raw == NULL)
  {
    error("--append is required");
  }
  if(options.signature_raw == NULL)
  {
    error("--signature is required");
  }
  if(options.out_table && options.quiet)
  {
    error("--table and --quiet are not compatible");
  }

  /* Set some sane defaults. */
  if(options.secret_min == 0 && options.secret_max == 0)
  {
    options.secret_min = 8;
    options.secret_max = 8;
  }
  else if(options.secret_min == 0 || options.secret_max == 0)
  {
    error("--secret-min and --secret-max can't be used separately, please specify both.");
  }

  if(!options.data_format)          options.data_format          = "raw";
  if(!options.append_format)        options.append_format        = "raw";
  if(!options.signature_format)     options.signature_format     = "hex";
  if(!options.out_data_format)      options.out_data_format      = "hex";
  if(!options.out_signature_format) options.out_signature_format = "hex";

  /* Convert the data appropriately. */
  if(options.data_raw)
    options.data = format_decode(options.data_format, (uint8_t*)options.data_raw, strlen(options.data_raw), &options.data_length);
  else
    options.data = read_file(options.filename, &options.data_length);

  /* Convert the appended data. */
  options.append = format_decode(options.append_format, (uint8_t*)options.append_raw, strlen(options.append_raw), &options.append_length);

  /* Convert the signature. */
  options.signature = format_decode(options.signature_format, (uint8_t*)options.signature_raw, strlen(options.signature_raw), &options.signature_length);

  /* If no formats were given, try to guess it. */
  if(options.format_count == 0)
  {
    /* If no signature was given, figure out which, if any, make sense. */
    for(i = 0; hash_type_array[i]; i++)
    {
      if(options.signature_length == hash_type_digest_size(hash_type_array[i]))
      {
        options.formats[options.format_count++] = hash_type_array[i];
      }
    }
  }
  if(options.format_count == 0)
  {
    error("No valid hash formats were found");
  }

  /* Sanity check the length of the signature. */
  for(i = 0; i < options.format_count; i++)
  {
    uint64_t digest_size = hash_type_digest_size(options.formats[i]);
    if(options.signature_length != digest_size)
      errx(EXIT_FAILURE, "%s's signature needs to be %"PRId64" bytes", options.formats[i], digest_size);
  }

  go(&options);

  free(options.data);
  free(options.append);
  free(options.signature);

  return EXIT_SUCCESS;
}
