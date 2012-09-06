#include <getopt.h>
#include <stdio.h>

#include "hash_extender_md4.h"
#include "hash_extender_md5.h"
#include "hash_extender_ripemd160.h"
#include "hash_extender_sha.h"
#include "hash_extender_sha1.h"
#include "hash_extender_sha256.h"
#include "hash_extender_sha512.h"
#include "hash_extender_whirlpool.h"

typedef enum {
  FORMAT_NONE = 1,
  FORMAT_RAW,
  FORMAT_HTML,
  FORMAT_HEX,
  FORMAT_CSTR
} format_t;

typedef struct {
  char     *str;
  format_t  str_format;
  char     *signature;
  format_t  signature_format;

  uint8_t   format_all;
  uint8_t   format_md4;
  uint8_t   format_md5;
  uint8_t   format_ripemd160;
  uint8_t   format_sha;
  uint8_t   format_sha1;
  uint8_t   format_sha256;
  uint8_t   format_sha512;
  uint8_t   format_whirlpool;

  uint64_t  secret_min;
  uint64_t  secret_max;

  format_t  out_str;
  format_t  out_signature;

  uint8_t   quiet;
} options_t;

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
  printf("Usage: %s --str=<str> --signature=<signature> --format=<format> [options]\n", program);
  printf("\n");
  printf("INPUT OPTIONS\n");
  printf("-s --str=<str> [REQUIRED]\n");
  printf("      The original string that we're going to extend.\n");
  printf("--str-format=<raw|html|hex>\n");
  printf("      The format the string is being passed in as. Default: raw.\n");
  printf("-S --signature=<sig> [REQUIRED]\n");
  printf("      The original signature.\n");
  printf("--signature-format=<raw|html|hex>\n");
  printf("      The format the signature is being passed in as. Default: hex.\n");
  printf("-f --format=<all|md4|md5|ripemd160|sha|sha1|sha256|sha512|whirlpool> [REQUIRED]\n");
  printf("      The hashtype of the signature. This can be given multiple times if you\n");
  printf("      want to try multiple signatures. 'all' will base the chosen types off\n");
  printf("      the size of the signature and use the hash(es) that make sense.");
  printf("-l --secret=<length>\n");
  printf("      The length of the secret, if known (if no secret length is given, a\n");
  printf("      variety of possible lengths are tried (4 - 32)\n");
  printf("--secret-min=<min>\n");
  printf("--secret-max=<max>\n");
  printf("      Try different secret lengths (both options are required)\n");
  printf("\n");
  printf("OUTPUT OPTIONS\n");
  printf("--out-str=<raw|html|hex|cstr|none>\n");
  printf("      Output the string as raw, html (%%nn), hex, c-style string (\\xNN), or not\n");
  printf("      output at all.\n");
  printf("--out-signature=<raw|html|hex|cstr|none>\n");
  printf("      Output the signature as raw, html (%%nn), hex, c-style string (\\xNN) or not\n");
  printf("      output at all.\n");
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
  options_t   options;
  char        c;
  int         option_index;
  const char *option_name;

  struct option long_options[] =
  {
    {"str",              required_argument, 0, 0}, /* Input string. */
    {"s",                required_argument, 0, 0},
    {"str-format",       required_argument, 0, 0}, /* Input string format. */
    {"signature",        required_argument, 0, 0}, /* Input signature. */
    {"S",                required_argument, 0, 0},
    {"signature-format", required_argument, 0, 0}, /* Input signature format. */
    {"format",           required_argument, 0, 0}, /* Hash format. */
    {"f",                required_argument, 0, 0},
    {"secret",           required_argument, 0, 0}, /* Secret length. */
    {"l",                required_argument, 0, 0},
    {"secret-min",       required_argument, 0, 0}, /* Secret min length. */
    {"secret-max",       required_argument, 0, 0}, /* Secret max length. */
    {"out-str",          required_argument, 0, 0}, /* Output string format. */
    {"out-signature",    required_argument, 0, 0}, /* Output signature format. */
    {"help",             no_argument,       0, 0}, /* Help. */
    {"h",                no_argument,       0, 0},
    {"H",                no_argument,       0, 0},
    {"test",             no_argument,       0, 0}, /* Test. */
    {"quiet",            no_argument,       0, 0}, /* Quiet. */
    {"q",                no_argument,       0, 0},
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

        if(!strcmp(option_name, "str") || !strcmp(option_name, "s"))
        {
          options.str = optarg;
        }
        else if(!strcmp(option_name, "str-format"))
        {
          if(!strcasecmp(optarg, "raw"))
            options.str_format = FORMAT_RAW;
          else if(!strcasecmp(optarg, "hex"))
            options.str_format = FORMAT_HEX;
          else if(!strcasecmp(optarg, "html"))
            options.str_format = FORMAT_HTML;
          else
            error(argv[0], "Unknown option passed to --str-format");
        }
        else if(!strcmp(option_name, "signature") || !strcmp(option_name, "S"))
        {
          options.signature = optarg;
        }
        else if(!strcmp(option_name, "signature-format"))
        {
          if(!strcasecmp(optarg, "raw"))
            options.signature_format = FORMAT_RAW;
          else if(!strcasecmp(optarg, "hex"))
            options.signature_format = FORMAT_HEX;
          else if(!strcasecmp(optarg, "html"))
            options.signature_format = FORMAT_HTML;
          else
            error(argv[0], "Unknown option passed to --signature-format");
        }
        else if(!strcmp(option_name, "format") || !strcmp(option_name, "f"))
        {
          if(!strcasecmp(optarg, "all"))
            options.format_all = 1;
          else if(!strcasecmp(optarg, "md4"))
            options.format_md4 = 1;
          else if(!strcasecmp(optarg, "md5"))
            options.format_md5 = 1;
          else if(!strcasecmp(optarg, "ripemd160"))
            options.format_ripemd160 = 1;
          else if(!strcasecmp(optarg, "sha"))
            options.format_sha = 1;
          else if(!strcasecmp(optarg, "sha1"))
            options.format_sha1 = 1;
          else if(!strcasecmp(optarg, "sha256"))
            options.format_sha256 = 1;
          else if(!strcasecmp(optarg, "sha512"))
            options.format_sha512 = 1;
          else if(!strcasecmp(optarg, "whirlpool"))
            options.format_whirlpool = 1;
          else
            error(argv[0], "Unknown type passed to --format.");
        }
        else if(!strcmp(option_name, "secret"))
        {
          if(options.secret_min != 0 || options.secret_max != 0)
            error(argv[0], "--secret is not compatable with --secret-min or --secret-max");
          options.secret_min = atoi(optarg);
          options.secret_max = atoi(optarg);
        }
        else if(!strcmp(option_name, "secret-min"))
        {
          if(options.secret_min != 0 || options.secret_max != 0)
            error(argv[0], "--secret is not compatable with --secret-min or --secret-max");
          options.secret_min = atoi(optarg);
        }
        else if(!strcmp(option_name, "secret-max"))
        {
          if(options.secret_min != 0 || options.secret_max != 0)
            error(argv[0], "--secret is not compatable with --secret-min or --secret-max");
          options.secret_max = atoi(optarg);
        }
        else if(!strcmp(option_name, "out-str"))
        {
          if(!strcasecmp(optarg, "raw"))
            options.out_str = FORMAT_RAW;
          else if(!strcasecmp(optarg, "html"))
            options.out_str = FORMAT_HTML;
          else if(!strcasecmp(optarg, "hex"))
            options.out_str = FORMAT_HEX;
          else if(!strcasecmp(optarg, "cstr"))
            options.out_str = FORMAT_CSTR;
          else if(!strcasecmp(optarg, "none"))
            options.out_str = FORMAT_NONE;
          else
            error(argv[0], "Unknown option passed to --out-str");
        }
        else if(!strcmp(option_name, "out-signature"))
        {
          if(!strcasecmp(optarg, "raw"))
            options.out_signature = FORMAT_RAW;
          else if(!strcasecmp(optarg, "html"))
            options.out_signature = FORMAT_HTML;
          else if(!strcasecmp(optarg, "hex"))
            options.out_signature = FORMAT_HEX;
          else if(!strcasecmp(optarg, "cstr"))
            options.out_signature = FORMAT_CSTR;
          else if(!strcasecmp(optarg, "none"))
            options.out_signature = FORMAT_NONE;
          else
            error(argv[0], "Unknown option passed to --out-str");
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
  if(options.str == NULL)
  {
    error(argv[0], "--str is required");
  }

  if(options.signature == NULL)
  {
    error(argv[0], "--signature is required");
  }

  if(options.format_all == 0 &&
     options.format_md4 == 0 &&
     options.format_md5 == 0 &&
     options.format_ripemd160 == 0 &&
     options.format_sha == 0 &&
     options.format_sha1 == 0 &&
     options.format_sha256 == 0 &&
     options.format_sha512 == 0 &&
     options.format_whirlpool == 0)
  {
    error(argv[0], "--format is required");
  }

  if(options.secret_min == 0 && options.secret_max == 0)
  {
    options.secret_min = 4;
    options.secret_max = 32;
  }
  else if(options.secret_min == 0 || options.secret_max == 0)
  {
    error(argv[0], "--secret-min and --secret-max can't be used separately, please specify both.");
  }

  /* TODO: Convert the str / signature to binary. */
  /* TODO: Check the length of the signature. */

  return 0;
}

