# File Checker



- Category : `pwn`
- Difficulty : :star: :star: :star:

- Solves : `2`

- Author : `XeR`



**Description**

> Entre les ACL et les LSM, on ne peut plus faire confiance aux permissions Unix.
>
> Voici un programme qui essaye d'ouvrir un fichier de votre choix pour pallier ce problème.



**Attachments**

- `Dockerfile` , `docker-compose.yml` 
- `public/file-checker`
- `public/ld-2.39.so`, `public/libc-2.39.do`
- `src/file-checker.c`, `src/Makefile`



**TL;DR**

The double free vulnerability could be abused to perform `House of Muney` to corrupt already mmaped pages (loaded libraries, mmaped files, ...) with nearly arbitrary content. I used this to corrupt `libc`'s `.dynsym` section so that next loaded libraries will get their GOT corrupted. The `House of Muney` mechanism can also be used to corrupt the `gconv-modules.cache` mmaped file which is loaded when calling `fopen` with a mode including `ccs=`. The OOB within the `modes` array allowed to specify arbitrary `fopen` mode. Putting the `gconv-modulles.cache` overwrite and the arbitrary `fopen` `mode` argument allows the loading of any libraries on the system within the process address space. I finally targeted a library with a specific constructor to call a manually found one gadget.



---



`File Checker` was a hard (more like really hard) difficulty pwn challenge written by `XeR`. It looked like a classic glibc heap menu-based challenge at first, but it turned into an incredibly hard and interesting challenge (probably the most interesting I've ever done). I learned many things by solving it and had the joy to first blood it.



### Source code analysis

The source code for this challenge was provided which make the analysis easier.

Let's start with the `main` function : 

```c
int main(void)
{
	// Ubuntu's libc is not relro
	// Baddies use that to hijack pointers to e.g. strlen *in the libc*
	// So we add an additional layer of protection here
	if(NULL == getenv("LD_BIND_NOW")) {
		fprintf(stderr, "LD_BIND_NOW is not set!\n");
		return EXIT_FAILURE;
	}

	setbuf(stdout, NULL);

	while(1) {
		menu();

		size_t choice;
		if(!getInt(&choice)) {
			fprintf(stderr, "Error: could not read integer\n");
			return EXIT_FAILURE;
		}
		choice--;

		static void (*const f[])(void) = {
			prepare,
			clean,
			handle,
		};
		const size_t count = sizeof(f) / sizeof(*f);

		if(count == choice)
			return EXIT_SUCCESS;

		if(choice < count)
			f[choice]();
	}
}
```

There is a classic menu structure that allows us to do 4 actions which will be detailed next :

- `Prepare a file`
- `Clean a file`
- `Handle a file`
- `Exit`



There are some interesting things to note :

First, the program is checking the presence of the `LD_BIND_NOW` environment variable. Here is an explanation from [the manual](https://man7.org/linux/man-pages/man8/ld.so.8.html) : 

``` 
LD_BIND_NOW (since glibc 2.1.1)

If set to a nonempty string, causes the dynamic linker to resolve all symbols at program startup instead of deferring function  call resolution to the point when they are first referenced. This is useful when using a debugger.
```

That means that even with the binary / libc compiled as`Partial RelRO`, all the symbols would be resolved at startup (no more lazy loading). As the comment in the code suggests, this might be here to prevent direct libc GOT overwriting.



Next, a function array is used to call the matching function this usually is a good target in binary exploitation as it can provide a quick way to gain PC control. However, it is defined with a `const` keyword, placing it inside a read only section.



The `getInt` function is a simple wrapper that converts a string provided by the user to a 64-bit unsigned integer using `scanf` : 

```c
__attribute__((nonnull, access(write_only, 1)))
static bool getInt(size_t *n)
{
	return 1 == scanf("%lu", n);
}
```



#### Prepare a file

Here is the code of the `prepare` function : 

```c
static void prepare(void)
{
	size_t index;
	if(!getIndex(&index))
		return;

	size_t size;
	printf("size: ");
	if(!getInt(&size)) {
		fprintf(stderr, "Could not read size\n");
		return;
	}

	char *buffer = malloc(size + 1);
	if(NULL == buffer) {
		perror("malloc");
		return;
	}

	memset(buffer, 0, size + 1);

	// drop the newline
	fgetc(stdin);

	printf("file name: ");
	if(NULL == fgets(buffer, size + 1, stdin)) {
		perror("fgets");
		free(buffer);
		return;
	}

	buffer[strcspn(buffer, "\n")] = 0;
	files[index] = buffer;
}
```

This function allows the user to allocate a filename with an arbitrary size and fill it with controlled data using `fgets`. It finally stores the allocated buffer address at an arbitrary index inside the `files` array which is defined as the following : 

```c
static char *files[5];
```



Here, the `getIndex` function is used to get the filename index. It is a simple wrapper of `getInt`, with some checks to prevent placing the filename pointer out of the bounds of the `files` array :

```c
__attribute__((nonnull, access(write_only, 1)))
static bool getIndex(size_t *n)
{
	const size_t count = sizeof(files) / sizeof(*files);

	size_t index;

	printf("index: ");
	if(!getInt(&index)) {
		fprintf(stderr, "Could not read index\n");
		return false;
	}

	if(index >= count) {
		fprintf(stderr, "Index out of bounds\n");
		return false;
	}

	*n = index;
	return true;
}
```



Finally there is some things to note down : 

- The allocated filename is nulled-out just after allocating it using `memset(buffer, 0, size + 1)`
  - This would make the leaking of data harder

- The input is retrieved using `fgets` which stops at a newline (`\n`) character
- The terminating newline is replaced with a null byte
  - No off by null here, `strcspn` returns the position of the first `\n` occurence.



#### Clean a file

Here is the code of the `clean` function : 

```c
static void clean(void)
{
	size_t index;
	if(!getIndex(&index))
		return;

	free(files[index]);
}
```



It simply frees the filename at the provided offset (still using the `getIndex` function).



#### Prepare a file

This is the most interesting function of the program : 

```c
static void handle(void)
{
	size_t index;
	if(!getIndex(&index))
		return;

	static const char *const modes[] = {
		"r",
		"r+",
		"a"
	};

	printf("Mode:\n");
	puts("1. read-only");
	puts("2. read + write");
	puts("3. read + write + create + append"); // useful for dirs

	size_t mode;
	if(!getInt(&mode))
		return;

	// Open the file with the specified mode
	FILE *fp = fopen(files[index], modes[mode - 1]);
	if(NULL == fp)
		return perror("fopen");

	if(0 != fclose(fp))
		return perror("fclose");

	puts("Permission check passed!");
}
```

It asks an index and a mode from the user and try to open the corresponding file with a mode inside the `modes` array. Note that nothing more is done between the opening of the file and its closing.



### Bug Hunting

Now let's hunt for bugs ! 



You probably spotted the obvious `Double Free` vulnerability inside the `clean` function by reading the first section :

```c
static void clean(void)
{
	size_t index;
	if(!getIndex(&index))
		return;

	free(files[index]);
}
```

The `files[index]` entry is not set to `NULL` after freeing it, allowing the free of already freed filename.



The second bug lies in the `prepare` function. A wrapper function is correctly used to get the `index` of the file to handle. However for the `mode`, `getInt` is used which doesn't apply any checks to the provided value. This leads to OOB access in the `modes` array.

The `modes` array is declared as `static const`, it will be located inside a global section of the binary (the same as the actions array). As the `files` array is global as well, the OOB can be used to make the `mode` point to a `files` entry such as `modes[offset] == &files[0]`. This allows full control over the `fopen`'s  `mode`  parameter.



No other bugs were spotted in this program, only these two bugs might be required to gain RCE on the remote instance.

As these bugs were very easy to find, I guess the most complicated part of this challenge will be to exploit them to gain RCE.



### House Of Fail

Usually, `double free` bugs are very powerful and can be quickly transformed into a strong primitive such as arbitrary write and so on...

However there are some constraints here :

- The version of the libc used in this challenge is `2.39`. Since version `2.29` [a check](https://elixir.bootlin.com/glibc/glibc-2.39.9000/source/malloc/malloc.c#L4527) was added to prevent double frees inside the `tcache` bins.
  - Double frees might still be exploitable inside `fastbins`, but there are only 5 `files` slots available. To obtain a fastbin free chunk, the corresponding `tcache` freelist must have at least 7 entries. 
- There is no obvious way to obtain a memory leak (libc, heap, ...)
  - Partial overwrites could be a solution, but [safe linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/) (introduced in libc 2.34) prevents partial overwrites on `tcache` bins and `fastbins`, and force the attacker to obtain a leak before corrupting anything.
  -  Nowadays some attacks (House of Rust, House of Water, ...) have been developed to obtain an arbitrary write without leaks. However the requirements for these techniques are too high for this challenge.



As mentioned in the `handle` function code, `fopen` is used to open an arbitrary file. Internally `fopen` allocates a `FILE` structure on the heap. This structure is also known to be a great target to construct strong primitives (Arbitrary [Read / Write / Code Execution]). 

However, there is nothing we can do during the lifetime of these `FILE` objects as the file is closed just after the opening.

Seems like there is not so much classic glibc heap tricks we can do here... And by solving the challenge this way, the OOB vulnerability inside the `modes` array would be totally useless, which is kinda unusual for a CTF challenge.



### House of Muney

While I was thinking about crazy heap techniques I could do to exploit the double free vulnerability, I just noticed that we could actually allocate a chunk of **any size **, that means that `mmaped` chunks are also in-scope !

In the `ptmalloc2` algorithm, when calling `malloc` with a big size (`> mp_.mmap_threshold`), the allocated chunk won't be allocated within the `main_arena`  , here`mmap` is actually called to obtain memory for the new chunk. In the same way, when freeing an `mmaped` chunk,  `munmap` is called to release the chunk memory.

The exploitation of `mmaped` chunks is less documented. However some techniques exists ! The first documented exploit against `mmaped` chunks has been done by [`Qualys` while exploiting a vulnerability in QMail](https://www.qualys.com/2020/05/19/cve-2005-1513/remote-code-execution-qmail.txt). Since, Maxwell Dulin documented a generic technique that take advantage of these `mmaped` chunks called [`House of Muney`](https://maxwelldulin.com/BlogPost?post=6967456768). The article is very well written, I encourage you to read it to understand more easily the next parts of this writeup.



The principle is to corrupt the header of an in-use `mmaped` chunk with an arbitrary size, and then calling `free`  to `munmap` a greater size than the original chunk, causing the unmapping of other memory regions ! These unmapped regions can then be remapped by calling `mmap` once again.

This is a beautiful technique which is **leakless** and allows the overwrite of read-only pages ! This sounds perfect for our needs.



This technique seems clearly to be the one to use in this context, however the original House of Muney exploits the fact that the used `libc` relies on lazy loading (`Partial RelRO`) to corrupt the `libc` GOT at runtime. It is not the case here due to the check done in the `main` function, ensuring the presence of the `LD_BIND_NOW` environment variable, which resolves **at startup** the address of every symbols.



### Arbitrary `fopen` mode

Now that we have a good idea for exploiting the double free vulnerability, let's focus on the `fopen`'s mode `OOB`.

The first thing I did was opening the  [`fopen` manual](https://man7.org/linux/man-pages/man3/fopen.3.html) and reading the definition of the `mode` parameter. There was nothing really interesting until I stumbled across this paragraph :

```
In addition to the above characters, fopen() and freopen() support the following syntax in mode:

,ccs=string

   The given string is taken as the name of a coded character set
   and the stream is marked as wide-oriented.  Thereafter, internal
   conversion functions convert I/O to and from the character set
   string.  If the ,ccs=string syntax is not specified, then the
   wide-orientation of the stream is determined by the first file
   operation.  If that operation is a wide-character operation, the
   stream is marked wide-oriented, and functions to convert to the
   coded character set are loaded.

```

This was something I didn't know about, so I quickly googled `fopen mode ccs exploit`, and I luckily found [this great article by `hugeh0ge` : Getting Arbitrary Code Execution from fopen's 2nd Argument](https://hugeh0ge.github.io/2019/11/04/Getting-Arbitrary-Code-Execution-from-fopen-s-2nd-Argument/). This seems to exactly fit to the challenge !

I won't detail the technique in this writeup as hugeh0ge already did in his article. But the key points are : 

- Controlling the `GCONV_PATH` environment variable the modification of the default `gconv-modules` file, which is used to link `ccs` module names to shared libraries on the system
- An attacker controlled library is then loaded by specifying  a custom`ccs` encoding (provided inside the evil `gconv-modules`)
  - The `gconv_init` functions is called by the `libc` when after loading the library using `dlopen`
    - `system("/bin/sh")` is executed

I was so excited when I discovered this article ! However there are still some problems... (else it wouldn't be fun !)

The scenario presented in the article supposes that the attacker already has a local access to the system in order to write files, which we don't have.

Moreover, this technique relies on the overwriting of an environment variable, in our case this would require an arbitrary write (or better, an arbitrary call to `putenv`). With an arbitrary write at our disposal, this would already been game over as there are more interesting things to target inside the `libc` to gain arbitrary code execution.

At this point I decided to look deeper inside the `libc` code, especially how the handling of GCONV modules works.



### GCONV modules cache

I started to look where the `GCONV_PATH` was used. The `__gconv_load_cache` function is checking that the `GCONV_PATH` environment variable is not set. If it is not set (the usual case) it starts the loading of the default `gconv-modules.cache` file (located at `/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache`). This file is a compiled version of the ASCII `gconv-modules`, and is used to be more efficient during the parsing of a `ccs` parameter.

Here is a simplified snippet of the relevant code inside the libc : 

```c

int
__gconv_load_cache (void)
{
  int fd;
  struct __stat64_t64 st;
  struct gconvcache_header *header;

  /* We cannot use the cache if the GCONV_PATH environment variable is
     set.  */
  __gconv_path_envvar = getenv ("GCONV_PATH");
  if (__gconv_path_envvar != NULL)
    return -1;

  /* See whether the cache file exists.  */
  fd = __open_nocancel (GCONV_MODULES_CACHE, O_RDONLY | O_CLOEXEC, 0);
  if (__builtin_expect (fd, 0) == -1)
    /* Not available.  */
    return -1;
  
  // ...
  gconv_cache = __mmap (NULL, cache_size, PROT_READ, MAP_SHARED, fd, 0);
  
  // ...

  return 0;
}
```



This file is actually mapped into memory using `mmap` ! Does that remind you of anything ?

> The principle is to corrupt the header of an in-use `mmaped` chunk with an arbitrary size, and then calling `free`  to `munmap` a greater size than the original chunk, causing the unmapping of other memory regions ! These unmapped regions can then be remapped by calling `mmap` once again.



Exactly ! We can abuse the mechanism of the House of Muney technique to replace the mmaped `gconv-modules.cache` file by our own !



To compile my own `gconv-modules.cache` file, I just used the `iconvconfig` utility that takes a `gconv-module` ASCII file and converts it to a valid `gconv-modules.cache` file : 

```shell
./iconvconfig --nostdlib --prefix='/' -o gconv-config.cache ./gconv-modules/
```



Basically this allows us to load any library inside the process address space, for example with the following `gconv-module` file, we can load dynamically `/usr/lib/x86_64-linux-gnu/libfoo.so` by calling `fopen(filename, "r,ccs=pwn")`

```
module  PWN//    INTERNAL      usr/lib/x86_64-linux-gnu/libfoo.so    1
module  INTERNAL    PWN//      usr/lib/x86_64-linux-gnu/libfoo.so    1
```

You can read the `find_module` (`iconv/gconv_cache.c`) / `__gconv_find_shlib` (`iconv/gconv_dl.c`) in the libc sources to have a better understanding of the dynamic loading of gconv modules. 



At this point, I thought this was game over. By making the `pwn` module pointing to `/proc/self/fd/0`, I thought I could just send my fake gconv library over `stdin` and a shell would pop ! But instead, I've got nothing but an error message from `fopen`... After investigating, it seems that `/proc/self/fd/0` can't be opened if `stdin` is a socket. As the remote challenge is using socat that forwards standard I/Os to socket, this might explain this. However I did not success to do this locally neither...

From that, I just <strike>fell into depression and alcoholism</strike> had some rest hoping that a brillant idea would come to me during the night.



### House of Muney - Revenge

Now, we've got an interesting primitive : arbitrary `dlopen`, the only constraint is that the library must be already on the system. 

I ran out of ideas for a while, but then I started opening the available GCONV libraries available on the provided container. All of these libraries were very similar in their structure, and the imported functions were almost always the same (to name them : `malloc`, `free`, `strncasecmp`, `strlen`). This was the moment I realized "Wait, these functions are **imported** from the libc ! How their address is resolved ?".

After reading some code from the loader, the answer was "the same way as any program, by leveraging the `.strtab` and `.dynsym` ELF sections". 

The difference is that now, we can control **when** these libraries are loaded ! If we manage to apply House of Muney to corrupt `libc` `.dynsym` section, and **then** load a library, its GOT will be successfully corrupted with controlled data ! All of this by keeping the advantages of the House of Muney : leakless, data-only technique.



Now, another question arises : "How code inside the libraries is actually executed ?"

The answer is inside the libc and loader code ! During the loading of a `gconv` module library, the [following symbols are resolved](https://elixir.bootlin.com/glibc/glibc-2.39.9000/source/iconv/gconv_dl.c#L127) : 

- `gconv_init` : The initialization function of a gconv module
- `gconv` : The actual function used to encode / decode data
- `gconv_end` : De-initialization function of a gconv module

When loading a module, the `gconv_init` function is called (following the `fopen` call). When a module is unloaded (by calling `fclose`), the `gconv_end` function is called. These functions actually use the imported functions listed above, which is perfect for us !

Another way to execute the code located inside the library during its loading / unloading are `constructors` / `destructors` which are present inside the `.init_array` / `.fini_array` sections of an ELF. 



As the `strncasecmp` function was called using a partially controlled string as the first parameter, I tried to modify its GOT entry by `system`. However, `strncasecmp` is defined as an `IFUNC` from the libc symbols. This mean that this function will be called once by the loader to determine what function should be used (this is used to take a specific implementation of a function, in this case, there are many implementations of `strncasecmp` which are system specific). So `system` would only be called during the symbol resolution by the loader with an uncontrolled parameter.

This was the only candidate I found along with `strlen` which was also an `IFUNC` symbol. So my last chance was to find a one gadget that would execute a shell when calling a corrupted function.

After trying many one gadgets [the reference one gadget tool](https://github.com/david942j/one_gadget) found, I couldn't find one which met every requirements.



At that moment I was a little desperate, and tried to read as much resource as I could, in order to find another idea... I ended up reading [this beautiful article from Qualys](https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt) where they abused the loading of libraries located under the `/usr/lib*` path inside the `ssh-agent` process to get remote code execution. Their approach is very interesting as they target legitimate libraries constructors to do some black magic (I won't spoil the article :D read it !). This inspired me, so I started analyzing every library available inside the provided `Docker` container, in order to find a magic constructor !

There were not as many available libraries as in the article, but I ended up finding something interesting !

The library `/usr/lib/x86_64-linux-gnu/libdrop_ambient.so.0.0.0` has 2 constructors, one of them is a user-defined function `init`, its code is very simple : 

```assembly
00001060  f30f1efa           endbr64 
00001064  4531c0             xor     r8d, r8d  {0x0}
00001067  31c9               xor     ecx, ecx  {0x0}
00001069  31d2               xor     edx, edx  {0x0}
0000106b  be04000000         mov     esi, 0x4
00001070  bf2f000000         mov     edi, 0x2f
00001075  31c0               xor     eax, eax  {0x0}
00001077  e9d4ffffff         jmp     prctl
```

But there is something special here : 

- Many registers are set to `0` : `r8`, `rcx`, `rdx`
- A function imported from the `libc` is called

That seems promising for a one gadget call ! Unfortunately, the conditions required for the one gadgets found by `one-gadget` were not met... But at this point I was convinced I could do something from this.



### Finding a one gadget

The last step of this challenge was just finding a perfect one gadget, I just started to load the `libc` inside `Binary Ninja` and searched for cross references to `/bin/sh`. Surprisingly, there were some functions that were not present in the results of the `one-gadget` tool. After spending some time I finally found the perfect one : 

```
000ef52b  lea     r11, [rel data_1cb42f]  {"/bin/sh"}
000ef532  lea     r10, [rbp-0x50 {var_58}]
000ef536  mov     qword [rbp-0x50 {var_58}], r11  {data_1cb42f, "/bin/sh"}
000ef53a  mov     qword [rbp-0x48 {var_50_1}], rax ; r10 point to { /bin/sh", NULL }
000ef53e  jmp     0xef431
...
000ef431  mov     qword [r10+0x10], 0x0
000ef439  mov     rdx, qword [rbp-0x78 {envp_1}] ; rdx = [rbp - 0x78] = 0
000ef43d  mov     rsi, r10 ; rsi = {"/bin/sh", NULL}
000ef440  mov     rdi, r11 ; rdi = "/bin/sh"
000ef443  call    __GI___execve ; execve("/bin/sh", {"/bin/sh", NULL}, NULL)
```



And we finally get our well deserved shell !

```
[*] Switching to interactive mode
$ id && cat flag.txt
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
FCSC{93aa742b341b591bb4a6cad5c1b9c63ba382ec6f8dd373ca82fd7c777443fe44}
```



### Conclusion

`File Checker` was a wonderful challenge that made me learn a ton of things. As `Super Factorizer` (another challenge of the FCSC2024 made by XeR), it's amazing how data-only exploit can be used when classic memory corruption exploits are not usable. Congratulations to XeR for creating this challenge I really loved it !