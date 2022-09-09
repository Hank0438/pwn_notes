

## Steps

* printf
    fmt vuln -> arbitrary read / write

* gain more printf
    _dl_fini -> read func_ptr on stack

* overwrite _IO_2_1_stdout_ to _IO_2_1_stderr_
    now we can see the stdout to leak
    leak libc_base

* get shell
    overwrite got of exit


## Setup Environment
```
docker run --rm -v /home/hank/pwnable_tw/printable:/printable --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it ubuntu:16.04 /bin/bash
```
* ref: https://prodisup.com/posts/2021/03/installing-python3.9-on-ubuntu-16.04-xenial/


## Solution
* https://www.cjovi.icu/WP/1265.html
* https://0xffff.one/d/410/2

