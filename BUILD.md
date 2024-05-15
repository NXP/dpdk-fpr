# Build instructions

## DPDK

For building DPDK, you may follow those instructions http://dpdk.org/doc/guides/linux_gsg/build_dpdk.html

## Normal binary
For building Packet-journey, you may just run `make`, default build settings are good enough.
You can use DPDK command line variables described here http://dpdk.org/doc/guides/prog_guide/ext_app_lib_make_help.html
You will find the generated apps here : app/dpdk-fpr

# Build Debian packages
You will need to build DPDK Debian packages using our debian/ files, you may find them here https://github.com/Gandi/dpdk-debian

Then just build FPR the normal Debian way, for example `debuild -us -uc`
