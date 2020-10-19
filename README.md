# Hash Extender by Ron Bowes <ron@skullsecurity.net>

This will be a blog post on http://www.skullsecurity.org/. For now, it's a README file.

## Intro

**You can grab the hash_extender tool on [Github](https://github.com/iagox86/hash_extender)!**

Awhile back, my friend [mogigoma](http://twitter.com/mogigoma) and I were doing a capture-the-flag contest at [https://stripe-ctf.com](https://stripe-ctf.com). One of the levels of the contest required us to perform a hash length extension attack. I had never even heard of the attack at the time, and after some reading I realized that not only is it a super cool (and conceptually easy!) attack to perform, there is also a total lack of good tools for performing said attack!  After hours of adding the wrong number of null bytes or incorrectly adding length values, I vowed to write a tool to make this easy for myself and anybody else who's trying to do it. So, after a couple weeks of work, here it is!

Now I'm gonna release the tool, and hope I didn't totally miss a good tool that does the same thing! It's called `hash_extender`, and implements a length extension attack against every algorithm I could think of:

- MD4
- MD5
- RIPEMD-160
- SHA-0
- SHA-1
- SHA-256
- SHA-512
- WHIRLPOOL

I'm more than happy to extend this to cover other hashing algorithms as well, provided they are "vulnerable" to this attack -- MD2, SHA-224, and SHA-384 are not. Please contact me if you have other candidates and I'll add them ASAP!

## The attack

An application is susceptible to a hash length extension attack if it prepends a secret value to a string, hashes it with a vulnerable algorithm, and entrusts the attacker with both the string and the hash, but not the secret.  Then, the server relies on the secret to decide whether or not the data returned later is the same as the original data.

It turns out, even though the attacker doesn't know the value of the prepended secret, he can still generate a valid hash for `{secret || data || attacker_controlled_data}`! This is done by simply picking up where the hashing algorithm left off; it turns out, 100% of the state needed to continue a hash is in the output of most hashing algorithms! We simply load that state into the appropriate hash structure and continue hashing.

**TL;DR: given a hash that is composed of a string with an unknown prefix, an attacker can append to the string and produce a new hash that still has the unknown prefix.**

## Example

Let's look at a step-by-step example. For this example:

- let `secret    = "secret"`
- let `data      = "data"`
- let `H         = md5()`
- let `signature = hash(secret || data) = 6036708eba0d11f6ef52ad44e8b74d5b`
- let `append    = "append"`

The server sends `data` and `signature` to the attacker. The attacker guesses that `H` is MD5 simply by its length (it's the most common 128-bit hashing algorithm), based on the source, or the application's specs, or any way they are able to.

Knowing only `data`, `H`, and `signature`, the attacker's goal is to append `append` to `data` and generate a valid signature for the new data. And that's easy to do! Let's see how.

### Padding

Before we look at the actual attack, we have to talk a little about padding.

When calculating `H`(`secret` + `data`), the string (`secret` + `data`) is padded with a '1' bit and some number of '0' bits, followed by the length of the string. That is, in hex, the padding is a 0x80 byte followed by some number of 0x00 bytes and then the length. The number of 0x00 bytes, the number of bytes reserved for the length, and the way the length is encoded, depends on the particular algorithm and blocksize.

With most algorithms (including MD4, MD5, RIPEMD-160, SHA-0, SHA-1, and SHA-256), the string is padded until its length is congruent to 56 bytes (mod 64). Or, to put it another way, it's padded until the length is 8 bytes less than a full (64-byte) block (the 8 bytes being size of the encoded length field). There are two hashes implemented in hash_extender that don't use these values: SHA-512 uses a 128-byte blocksize and reserves 16 bytes for the length field, and WHIRLPOOL uses a 64-byte blocksize and reserves 32 bytes for the length field.

The endianness of the length field is also important. MD4, MD5, and RIPEMD-160 are little-endian, whereas the SHA family and WHIRLPOOL are big-endian. Trust me, that distinction cost me days of work!

In our example, `length(secret || data) = length("secretdata")` is 10 (0x0a) bytes, or 80 (0x50) bits. So, we have 10 bytes of data (`"secretdata"`), 46 bytes of padding (80 00 00 ...), and an 8-byte little-endian length field (50 00 00 00 00 00 00 00), for a total of 64 bytes (or one block). Put together, it looks like this:

    0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......

Breaking down the string, we have:

- `"secret" = secret`
- `"data" = data`
- 80 00 00 ... -- The 46 bytes of padding, starting with 0x80
- 50 00 00 00 00 00 00 00 -- The bit length in little endian

This is the exact data that `H` hashed in the original example.

### The attack

Now that we have the data that `H` hashes, let's look at how to perform the actual attack.

First, let's just append `append` to the string. Easy enough!  Here's what it looks like:

    0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
    0040  61 70 70 65 6e 64                                append

The hash of that block is what we ultimately want to a) calculate, and b) get the server to calculate. The value of that block of data can be calculated in two ways:

- By sticking it in a buffer and performing `H(buffer)`
- By starting at the end of the first block, using the state we already know from `signature`, and hashing `append` starting from that state

The first method is what the server will do, and the second is what the attacker will do. Let's look at the server, first, since it's the easier example.

#### Server's calculation

We know the server will prepend `secret` to the string, so we send it the string minus the `secret` value:

    0000  64 61 74 61 80 00 00 00 00 00 00 00 00 00 00 00  data............
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 50 00 00 00 00 00 00 00 61 70 70 65 6e 64  ..P.......append

Don't be fooled by this being exactly 64 bytes (the blocksize) -- that's only happening because `secret` and `append` are the same length. Perhaps I shouldn't have chosen that as an example, but I'm not gonna start over!

The server will prepend `secret` to that string, creating:

    0000  73 65 63 72 65 74 64 61 74 61 80 00 00 00 00 00  secretdata......
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 00 00 00 00 00 00 50 00 00 00 00 00 00 00  ........P.......
    0040  61 70 70 65 6e 64                                append

And hashes it to the following value:

    6ee582a1669ce442f3719c47430dadee

For those of you playing along at home, you can prove this works by copying and pasting this into a terminal:

    echo '
    #include <stdio.h>
    #include <openssl/md5.h>
  
    int main(int argc, const char *argv[])
    {
      MD5_CTX c;
      unsigned char buffer[MD5_DIGEST_LENGTH];
      int i;
  
      MD5_Init(&c);
      MD5_Update(&c, "secret", 6);
      MD5_Update(&c, "data"
                     "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                     "\x00\x00\x00\x00"
                     "\x50\x00\x00\x00\x00\x00\x00\x00"
                     "append", 64);
      MD5_Final(buffer, &c);
  
      for (i = 0; i < 16; i++) {
        printf("%02x", buffer[i]);
      }
      printf("\n");
      return 0;
    }' > hash_extension_1.c
  
    gcc -o hash_extension_1 hash_extension_1.c -lssl -lcrypto
  
    ./hash_extension_1

All right, so the server is going to be checking the data we send against the signature `6ee582a1669ce442f3719c47430dadee`. Now, as the attacker, we need to figure out how to generate that signature!

#### Client's calculation

So, how do we calculate the hash of the data shown above without actually having access to `secret`?

Well, first, we need to look at what we have to work with: `data`, `append`, `H`, and `H(secret || data)`.

We need to define a new function, `H'`, which uses the same hashing algorithm as `H`, but whose starting state is the final state of `H(secret || data)`, i.e., `signature`. Once we have that, we simply calculate `H'(append)` and the output of that function is our hash. It sounds easy (and is!); have a look at this code:

    echo '
    #include <stdio.h>
    #include <openssl/md5.h>
  
    int main(int argc, const char *argv[])
    {
      int i;
      unsigned char buffer[MD5_DIGEST_LENGTH];
      MD5_CTX c;
  
      MD5_Init(&c);
      MD5_Update(&c, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64);
  
      c.A = htonl(0x6036708e); /* <-- This is the hash we already had */
      c.B = htonl(0xba0d11f6);
      c.C = htonl(0xef52ad44);
      c.D = htonl(0xe8b74d5b);
  
      MD5_Update(&c, "append", 6); /* This is the appended data. */
      MD5_Final(buffer, &c);
      for (i = 0; i < 16; i++) {
        printf("%02x", buffer[i]);
      }
      printf("\n");
      return 0;
    }' > hash_extension_2.c
  
    gcc -o hash_extension_2 hash_extension_2.c -lssl -lcrypto
  
    ./hash_extension_2

The the output is, just like before:

    6ee582a1669ce442f3719c47430dadee

So we know the signature is right. The difference is, we didn't use `secret` at all! What's happening!?

Well, we create a `MD5_CTX` structure from scratch, just like normal.  Then we take the MD5 of 64 'A's. We take the MD5 of a full (64-byte) block of 'A's to ensure that any internal values -- other than the state of the hash itself -- are set to what we expect.

Then, after that is done, we replace `c.A`, `c.B`, `c.C`, and `c.D` with the values that were found in `signature`: `6036708eba0d11f6ef52ad44e8b74d5b`. This puts the MD5_CTX structure in the same state as it finished in originally, and means that anything else we hash -- in this case `append` -- will produce the same output as it would have had we hashed it the usual way.

We use `htonl()` on the values before setting the state variables because MD5 -- being little-endian -- outputs its values in little-endian as well.

#### Result

So, now we have this string:

    0000  64 61 74 61 80 00 00 00 00 00 00 00 00 00 00 00  data............
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    0030  00 00 50 00 00 00 00 00 00 00 61 70 70 65 6e 64  ..P.......append

And this signature for `H(secret || data || append)`:

   6ee582a1669ce442f3719c47430dadee

And we can generate the signature without ever knowing what the secret was!  So, we send the string to the server along with our new signature. The server will prepend the signature, hash it, and come up with the exact same hash we did (victory!).

## The tool

**You can grab the hash_extender tool on [Github](https://github.com/iagox86/hash_extender)!**

This example took me hours to write. Why? Because I made about a thousand mistakes writing the code. Too many NUL bytes, not enough NUL bytes, wrong endianness, wrong algorithm, used bytes instead of bits for the length, and all sorts of other stupid problems. The first time I worked on this type of attack, I spent from 2300h till 0700h trying to get it working, and didn't figure it out till after sleeping (and with Mak's help). And don't even get me started on how long it took to port this attack to MD5. Endianness can die in a fire.

Why is it so difficult? Because this is crypto, and crypto is `immensely` complicated and notoriously difficult to troubleshoot. There are lots of moving parts, lots of side cases to remember, and it's never clear why something is wrong, just that the result isn't right. What a pain!

So, I wrote hash_extender. hash_extender is (I hope) the first free tool that implements this type of attack. It's easy to use and implements this attack for every algorithm I could think of.

Here's an example of its use:

    $ ./hash_extender --data data --secret 6 --append append --signature 6036708eba0d11f6ef52ad44e8b74d5b --format md5
    Type: md5
    Secret length: 6
    New signature: 6ee582a1669ce442f3719c47430dadee
    New string: 64617461800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000617070656e64

If you're unsure about the hash type, you can let it try different types by leaving off the --format argument. I recommend using the --table argument as well if you're trying multiple algorithms:

    $ ./hash_extender --data data --secret 6 --append append --signature 6036708eba0d11f6ef52ad44e8b74d5b --out-data-format html --table
    md4       89df68618821cd4c50dfccd57c79815b data80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000P00000000000000append
    md5       6ee582a1669ce442f3719c47430dadee data80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000P00000000000000append

There are plenty of options for how you format inputs and outputs, including HTML (where you use `%NN` notation), CString (where you use `\xNN` notation, as well as `\r`, `\n`, `\t`, etc.), hex (such as how the hashes were specified above), etc.

By default I tried to choose what I felt were the most reasonable options:

- Input data: raw
- Input hash: hex
- Output data: hex
- Output hash: hex

Here's the help page for reference:

    --------------------------------------------------------------------------------
    HASH EXTENDER
    --------------------------------------------------------------------------------
    
    By Ron Bowes <ron @ skullsecurity.net>
    
    See LICENSE.txt for license information.
    
    Usage: ./hash_extender <--data=<data>|--file=<file>> --signature=<signature> --format=<format> [options]
    
    INPUT OPTIONS
    -d --data=<data>
          The original string that we're going to extend.
    --data-format=<format>
          The format the string is being passed in as. Default: raw.
          Valid formats: raw, hex, html, cstr
    --file=<file>
          As an alternative to specifying a string, this reads the original string
          as a file.
    -s --signature=<sig>
          The original signature.
    --signature-format=<format>
          The format the signature is being passed in as. Default: hex.
          Valid formats: raw, hex, html, cstr
    -a --append=<data>
          The data to append to the string. Default: raw.
    --append-format=<format>
          Valid formats: raw, hex, html, cstr
    -f --format=<all|format> [REQUIRED]
          The hash_type of the signature. This can be given multiple times if you
          want to try multiple signatures. 'all' will base the chosen types off
          the size of the signature and use the hash(es) that make sense.
          Valid types: md4, md5, ripemd160, sha, sha1, sha256, sha512, whirlpool
    -l --secret=<length>
          The length of the secret, if known. Default: 8.
    --secret-min=<min>
    --secret-max=<max>
          Try different secret lengths (both options are required)
    
    OUTPUT OPTIONS
    --table
          Output the string in a table format.
    --out-data-format=<format>
          Output data format.
          Valid formats: none, raw, hex, html, html-pure, cstr, cstr-pure, fancy
    --out-signature-format=<format>
          Output signature format.
          Valid formats: none, raw, hex, html, html-pure, cstr, cstr-pure, fancy
    
    OTHER OPTIONS
    -h --help 
          Display the usage (this).
    --test
          Run the test suite.
    -q --quiet
          Only output what's absolutely necessary (the output string and the
          signature)

## Defense

So, as a programmer, how do you solve this? It's actually pretty simple. There are two ways:

- Don't trust a user with encrypted data or signatures, if you can avoid it.
- If you can't avoid it, then use HMAC instead of trying to do it yourself.  HMAC is `designed` for this.

HMAC is the real solution. HMAC is designed for securely hashing data with a secret key.

As usual, use constructs designed for what you're doing rather than doing it yourself. The key to all crypto! [pun intended]

**And finally, you can grab the hash_extender tool on [Github](https://github.com/iagox86/hash_extender)!**
