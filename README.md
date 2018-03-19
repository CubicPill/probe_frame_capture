# probe_frame_capture

A program used to collect probe frames.    
Monitor mode is required.     

## Building
### Building for local machine
Just use cmake to help the building. The ```libpcap``` and ```libradiotap``` has already be included in the source.     

```
mkdir bin
cd bin
cmake ..
make -j4
```
Then you'll get two executables, and ```libpcap.so```, ```libradiotap.so```

### Cross compiling
First, you need to setup the toolchain for cross compiling.    
In my case, I want to compile it for MIPS arch, running on OpenWrt, So I downloaded the [OpenWrt Toolchain](https://archive.openwrt.org/snapshots/trunk/ar71xx/generic/OpenWrt-Toolchain-ar71xx-generic_gcc-5.3.0_musl-1.1.16.Linux-x86_64.tar.bz2) for my router's chipset.    
(Find the toolchain you need by yourself, or use [Buildroot](http://buildroot.uclibc.org).)    
#### Compile the main program
Then write your own toolchain file, here is an example:
```cmake
set(CMAKE_C_COMPILER x86_64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILERx86_64-linux-gnu-g++)
``` 
Save, and tell cmake which one you would use:
```
cmake CMakeList.txt -DCMAKE_TOOLCHAIN_FILE=<YOUR OWN TOOLCHAIN FILE>

```
The toolchain files for mips_openwrt and x86_64 are already provided. You can use them with
```
cmake CMakeList.txt -DCMAKE_TOOLCHAIN_FILE=mips_openwrt.cmake #MIPS-OpenWrt
```
or
```
cmake CMakeList.txt -DCMAKE_TOOLCHAIN_FILE=linux_x86_64.cmake #Linux-x86_64
```
## Usage
```
./probe_frame_capture list //list all interfaces avaliable
./probe_frame_capture <interface name> 
Optional:
-s <server>
-p <port>
--filter <MAC address>
```