# Dependencies

Required:

* libelf
* libssl-dev
* zlib
* clang
* libcrypto
* libcap

# Kernel configuration

* CONFIG_BPF
* CONFIG_BPF_SYSCALL
* CONFIG_BPF_EVENTS
* CONFIG_TRACEPOINTS
* CONFIG_HAVE_PERF_EVENTS
* CONFIG_HAVE_SYSCALL_TRACEPOINTS
* CONFIG_DEBUG_INFO_BTF
* CONFIG_PAHOLE_HAS_SPLIT_BTF

# Build

Clone the repo:

~~~
git clone --recurse-submodules https://github.com/hivernal/logger.git
~~~

Go to the repository:

~~~
cd ./system_logger
~~~

Building:

~~~
make
~~~

Start:

~~~
sudo ./system_logger
~~~
