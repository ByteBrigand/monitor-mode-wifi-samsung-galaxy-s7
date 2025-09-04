export MAKEFLAGS="-j$(nproc)"
export ANDROID_API=24
export ANDROID_ARCH=arm64

# Install required packages
sudo apt-get install -y git gawk qpdf adb flex bison
sudo apt-get install -y libc6:i386 libncurses5:i386 libstdc++6:i386
sudo apt-get install -y vim-common xxd autoconf automake libtool pkg-config
sudo apt-get install -y libgcrypt-dev
sudo apt-get install -y build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre2-dev libhwloc-dev libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils expect

# Get Android NDK
cd ~
wget https://dl.google.com/android/repository/android-ndk-r27d-linux.zip
unzip android-ndk-r27d-linux.zip
export ANDROID_NDK_ROOT=~/android-ndk-r27d
export PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# Set compiler variables for Android API 24 (LineageOS 16)
export CC=aarch64-linux-android24-clang
export CXX=aarch64-linux-android24-clang++
export AR=llvm-ar
export AS=llvm-as
export RANLIB=llvm-ranlib
export STRIP=llvm-strip




# Build OpenSSL
cd ~
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout OpenSSL_1_1_1-stable

./Configure android-arm64 \
    -D__ANDROID_API__=24 \
    --prefix=$ANDROID_NDK_ROOT/sysroot/usr \
    -fPIC \
    -pie \
    shared \
    no-ssl2 \
    no-ssl3 \
    no-comp \
    no-hw \
    no-engine \
    --openssldir=$ANDROID_NDK_ROOT/sysroot/usr

make clean
make depend
make -j$(nproc)
make install_sw






# Build zlib
cd ~
wget https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
tar xzf zlib-1.3.1.tar.gz
cd ~/zlib-1.3.1

export CHOST=aarch64-linux-android
export CC=aarch64-linux-android24-clang
export CXX=aarch64-linux-android24-clang++
export CFLAGS="-fPIC -pie"
export LDFLAGS="-pie"

./configure --prefix=$ANDROID_NDK_ROOT/sysroot/usr

make -j$(nproc)
make install




# Build PCRE2
cd ~
wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.42/pcre2-10.42.tar.gz
tar xzf pcre2-10.42.tar.gz
cd ~/pcre2-10.42

./configure \
    --host=aarch64-linux-android \
    --prefix=$ANDROID_NDK_ROOT/sysroot/usr \
    --enable-shared \
    --enable-static \
    --enable-pcre2-8 \
    --enable-pcre2-16 \
    --enable-pcre2-32 \
    CC=aarch64-linux-android24-clang \
    CXX=aarch64-linux-android24-clang++ \
    CFLAGS="-fPIC -pie" \
    LDFLAGS="-pie"

make -j$(nproc)
make install



cd ~
wget https://download.open-mpi.org/release/hwloc/v2.9/hwloc-2.9.1.tar.gz
tar xzf hwloc-2.9.1.tar.gz
cd ~/hwloc-2.9.1

# Set compiler variables again to be sure
export CC=aarch64-linux-android24-clang
export CXX=aarch64-linux-android24-clang++
export CFLAGS="-fPIC -pie"
export LDFLAGS="-pie"

# Configure hwloc
./configure \
    --host=aarch64-linux-android \
    --prefix=$ANDROID_NDK_ROOT/sysroot/usr \
    --disable-cairo \
    --disable-opencl \
    --disable-cuda \
    --disable-nvml \
    --disable-gl \
    --disable-libudev \
    --disable-plugin-dlopen \
    --disable-plugin-ltdl

make -j$(nproc)
make install








# Build libnl
cd ~
wget https://github.com/thom311/libnl/releases/download/libnl3_11_0/libnl-3.11.0.tar.gz
tar xzf libnl-3.11.0.tar.gz
cd ~/libnl-3.11.0

export CC=aarch64-linux-android26-clang
export CXX=aarch64-linux-android26-clang++
export CFLAGS="-fPIC -pie -include $PWD/android_compat.h -D_GNU_SOURCE -DANDROID"
export CPPFLAGS="-I$ANDROID_NDK_ROOT/sysroot/usr/include"
export LDFLAGS="-pie -L$ANDROID_NDK_ROOT/sysroot/usr/lib"

# Create android compatibility header
cat > android_compat.h << 'EOF'
#ifndef _ANDROID_COMPAT_H
#define _ANDROID_COMPAT_H

#include <sys/types.h>
#include <netinet/in.h>

#ifndef _IN_ADDR_T_DEFINED
#define _IN_ADDR_T_DEFINED
typedef uint32_t in_addr_t;
#endif

#endif /* _ANDROID_COMPAT_H */
EOF

./configure \
    --host=aarch64-linux-android \
    --prefix=$ANDROID_NDK_ROOT/sysroot/usr \
    --disable-static \
    --enable-shared \
    --disable-cli \
    --disable-pthreads

make -j$(nproc)
make install





# Build nexmon
git clone https://github.com/seemoo-lab/nexmon.git
cd ~/nexmon
source setup_env.sh
make

# Build firmware patch
cd patches/bcm43596a0/9.96.4_sta_c0/nexmon/
make


mkdir -p ~/nexmon/utilities/libnexmonitor
cd ~/nexmon/utilities/libnexmonitor

# Create Android.mk for libnexmonitor
cat > Android.mk << 'EOF'
LOCAL_PATH := $(call my-dir)
PATCHES_PATH := $(LOCAL_PATH)/../../patches

include $(CLEAR_VARS)
LOCAL_MODULE := libnexmonitor
LOCAL_SRC_FILES := libnexmonitor.c
LOCAL_CFLAGS := -std=c99
LOCAL_C_INCLUDES := \
    $(PATCHES_PATH)/include \
    $(LOCAL_PATH)/../libnexio
LOCAL_LDLIBS := -ldl
LOCAL_STATIC_LIBRARIES := libnexio

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libnexio
LOCAL_SRC_FILES := $(LOCAL_PATH)/../libnexio/local/$(TARGET_ARCH_ABI)/libnexio.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../libnexio
include $(PREBUILT_STATIC_LIBRARY)
EOF

# Create Application.mk
cat > Application.mk << 'EOF'
APP_ABI := arm64-v8a
APP_PLATFORM := android-24
APP_STL := c++_static
EOF

# Create libnexmonitor.c
cat > libnexmonitor.c << 'EOF'
#include <stdarg.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <nexioctls.h>
#include <monitormode.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1l)
#endif

#define REAL_LIBC RTLD_NEXT
#define WLC_GET_MONITOR                 107
#define WLC_SET_MONITOR                 108

#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801
#endif

#ifndef ARPHRD_IEEE80211_RADIOTAP
#define ARPHRD_IEEE80211_RADIOTAP 803
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

typedef int request_t;

struct nexio {
    struct ifreq *ifr;
    int sock_rx_ioctl;
    int sock_rx_frame;
    int sock_tx;
};

extern int nex_ioctl(struct nexio *nexio, int cmd, void *buf, int len, bool set);
extern struct nexio *nex_init_ioctl(const char *ifname);

static struct nexio *nexio = NULL;
static const char *ifname = "wlan0";

static int (*real_sendto) (int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_ioctl) (int, request_t, void *) = NULL;
static int (*real_socket) (int, int, int) = NULL;
static int (*real_bind) (int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_write) (int, const void *, size_t) = NULL;

static int socket_to_type[100] = { 0 };
static char bound_to_correct_if[100] = { 0 };

static void _libnexmonitor_init() __attribute__ ((constructor));
static void _libnexmonitor_init() {
    nexio = nex_init_ioctl(ifname);

    if (!real_ioctl)
        real_ioctl = (int (*) (int, request_t, void *)) dlsym(REAL_LIBC, "ioctl");
    if (!real_socket)
        real_socket = (int (*) (int, int, int)) dlsym(REAL_LIBC, "socket");
    if (!real_bind)
        real_bind = (int (*) (int, const struct sockaddr *, socklen_t)) dlsym(REAL_LIBC, "bind");
    if (!real_write)
        real_write = (int (*) (int, const void *, size_t)) dlsym(REAL_LIBC, "write");
    if (!real_sendto)
        real_sendto = (int (*) (int, const void *, size_t, int, const struct sockaddr *, socklen_t)) dlsym(REAL_LIBC, "sendto");
}

int ioctl(int fd, request_t request, ...) {
    va_list args;
    void *argp;
    int ret;
    
    va_start(args, request);
    argp = va_arg(args, void *);
    va_end(args);

    ret = real_ioctl(fd, request, argp);

    switch (request) {
        case SIOCGIFHWADDR: {
            int buf;
            struct ifreq* p_ifr = (struct ifreq *) argp;
            if (!strncmp(p_ifr->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
                nex_ioctl(nexio, WLC_GET_MONITOR, &buf, 4, false);
                
                if (buf & MONITOR_IEEE80211) 
                    p_ifr->ifr_hwaddr.sa_family = ARPHRD_IEEE80211;
                else if (buf & MONITOR_RADIOTAP) 
                    p_ifr->ifr_hwaddr.sa_family = ARPHRD_IEEE80211_RADIOTAP;
                else if (buf & MONITOR_DISABLED || buf & MONITOR_LOG_ONLY || 
                         buf & MONITOR_DROP_FRM || buf & MONITOR_IPV4_UDP)
                    p_ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
                ret = 0;
            }
            break;
        }

        case SIOCGIWMODE: {
            int buf;
            struct iwreq* p_wrq = (struct iwreq*) argp;
            
            if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
                nex_ioctl(nexio, WLC_GET_MONITOR, &buf, 4, false);
                if (buf & MONITOR_RADIOTAP || buf & MONITOR_IEEE80211 || 
                    buf & MONITOR_LOG_ONLY || buf & MONITOR_DROP_FRM || 
                    buf & MONITOR_IPV4_UDP) {
                    p_wrq->u.mode = IW_MODE_MONITOR;
                }
                ret = 0;
            }
            break;
        }

        case SIOCSIWMODE: {
            int buf;
            struct iwreq* p_wrq = (struct iwreq*) argp;

            if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
                buf = (p_wrq->u.mode == IW_MODE_MONITOR) ? MONITOR_RADIOTAP : MONITOR_DISABLED;
                ret = nex_ioctl(nexio, WLC_SET_MONITOR, &buf, 4, true);
            }
            break;
        }
    }
    return ret;
}

int socket(int domain, int type, int protocol) {
    int ret = real_socket(domain, type, protocol);
    if (ret >= 0 && ret < sizeof(socket_to_type)/sizeof(socket_to_type[0]))
        socket_to_type[ret] = type;
    return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    int ret = real_bind(sockfd, addr, addrlen);
    struct sockaddr_ll *sll = (struct sockaddr_ll *) addr;
    
    char sll_ifname[IFNAMSIZ] = { 0 };
    if_indextoname(sll->sll_ifindex, sll_ifname);

    if ((sockfd < sizeof(bound_to_correct_if)/sizeof(bound_to_correct_if[0])) && 
        !strncmp(ifname, sll_ifname, strlen(ifname)))
        bound_to_correct_if[sockfd] = 1;

    return ret;
}

struct inject_frame {
    unsigned short len;
    unsigned char pad;
    unsigned char type;
    char data[];
};

ssize_t write(int fd, const void *buf, size_t count) {
    if ((fd > 2) && (fd < sizeof(socket_to_type)/sizeof(socket_to_type[0])) && 
        (socket_to_type[fd] == SOCK_RAW) && (bound_to_correct_if[fd] == 1)) {
        
        struct inject_frame *buf_dup = malloc(count + sizeof(struct inject_frame));
        if (!buf_dup) return -1;

        buf_dup->len = count + sizeof(struct inject_frame);
        buf_dup->pad = 0;
        buf_dup->type = 1;
        memcpy(buf_dup->data, buf, count);

        nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, count + sizeof(struct inject_frame), true);
        free(buf_dup);
        return count;
    }
    return real_write(fd, buf, count);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    if ((sockfd > 2) && (sockfd < sizeof(socket_to_type)/sizeof(socket_to_type[0])) && 
        (socket_to_type[sockfd] == SOCK_RAW) && (bound_to_correct_if[sockfd] == 1)) {
        
        struct inject_frame *buf_dup = malloc(len + sizeof(struct inject_frame));
        if (!buf_dup) return -1;

        buf_dup->len = len + sizeof(struct inject_frame);
        buf_dup->pad = 0;
        buf_dup->type = 1;
        memcpy(buf_dup->data, buf, len);

        nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, len + sizeof(struct inject_frame), true);
        free(buf_dup);
        return len;
    }
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
EOF

# Build utilities
cd ~/nexmon/utilities/
make nexutil
make libnexmon
make libfakeioctl
make libnexio
cd libnexmonitor
$ANDROID_NDK_ROOT/ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_PLATFORM=android-24 NDK_APPLICATION_MK=./Application.mk







# Build aircrack-ng
cd ~
git clone https://github.com/aircrack-ng/aircrack-ng.git
cd ~/aircrack-ng
make clean
autoreconf -i

export CC=aarch64-linux-android26-clang
export CXX=aarch64-linux-android26-clang++
export PKG_CONFIG_PATH=$ANDROID_NDK_ROOT/sysroot/usr/lib/pkgconfig
export CFLAGS="-fPIC -pie -I$ANDROID_NDK_ROOT/sysroot/usr/include"
export LDFLAGS="-pie -L$ANDROID_NDK_ROOT/sysroot/usr/lib"
export LIBS="-lz -lnl-3 -lnl-genl-3"

./configure \
    --host=aarch64-linux-android \
    --with-android-sdk=$ANDROID_NDK_ROOT \
    --with-android-ndk=$ANDROID_NDK_ROOT \
    --with-android-api=26 \
    --with-experimental \
    --with-ext-scripts \
    --enable-libnl \
    --disable-static \
    --without-opt \
    --with-pcre2=$ANDROID_NDK_ROOT/sysroot/usr \
    --with-zlib=$ANDROID_NDK_ROOT/sysroot/usr

make -j$(nproc)














# Create module directory structure
rm -rf ~/nexmon_magisk*
mkdir -p ~/nexmon_magisk
cd ~/nexmon_magisk
mkdir -p META-INF/com/google/android
mkdir -p system/bin
mkdir -p system/lib64
mkdir -p system/lib64/aircrack
mkdir -p system/etc/wifi

# Create module.prop
cat > module.prop << 'EOF'
id=nexmon_aircrack
name=Nexmon + Aircrack-ng
version=v0.1
versionCode=1
author=ByteBrigand
description=Nexmon WiFi driver modifications and Aircrack-ng suite for wireless security testing on Samsung Galaxy S7 running LineageOS 16
EOF

# Create update-binary
cat > META-INF/com/google/android/update-binary << 'EOF'
#!/sbin/sh
TMPDIR=/dev/tmp
MOUNTPATH=/dev/magisk_img

# Default permissions
umask 022

# Initial cleanup
rm -rf $TMPDIR 2>/dev/null
mkdir -p $TMPDIR

# Extract files
unzip -o "$3" -d $TMPDIR 2>/dev/null

# Set up environmental variables
OUTFD=$2
ZIPFILE=$3

# Define functions
ui_print() { echo -e "ui_print $1\nui_print" >> /proc/self/fd/$OUTFD; }

# Define permission setting function
set_perm() {
  uid=$1; gid=$2; mod=$3; file=$4
  chown $uid:$gid $file
  chmod $mod $file
}

set_perm_recursive() {
  uid=$1; gid=$2; dmod=$3; fmod=$4; dir=$5
  find "$dir" -type d -exec chmod $dmod {} \;
  find "$dir" -type f -exec chmod $fmod {} \;
  chown -R $uid:$gid "$dir"
}

# Mount partitions
mount /data 2>/dev/null

# Extract the module files
ui_print "- Extracting module files"
mkdir -p $MOUNTPATH 2>/dev/null
cd $TMPDIR
cp -af * $MOUNTPATH

# Set permissions
ui_print "- Setting permissions"
set_perm_recursive $MOUNTPATH/system 0 0 0755 0644
set_perm_recursive $MOUNTPATH/system/bin 0 0 0755 0755
set_perm_recursive $MOUNTPATH/system/lib64 0 0 0755 0755

# Unmount partitions
umount /data 2>/dev/null

# Cleanup
rm -rf $TMPDIR 2>/dev/null

ui_print "- Done"
exit 0
EOF

chmod 755 META-INF/com/google/android/update-binary

# Create install.sh
cat > install.sh << 'EOF'
##########################################################################################
#
# Magisk Module Installer Script
#
##########################################################################################

SKIPMOUNT=false
PROPFILE=true
POSTFSDATA=true
LATESTARTSERVICE=true

print_modname() {
  ui_print "*******************************"
  ui_print "     Nexmon + Aircrack-ng     "
  ui_print "*******************************"
}

on_install() {
  ui_print "- Installing module files"
  unzip -o "$ZIPFILE" 'system/*' -d $MODPATH >&2

  # Create proper SELinux contexts
  ui_print "- Setting SELinux contexts"
  chcon -R u:object_r:system_file:s0 $MODPATH/system
  chcon -R u:object_r:system_lib_file:s0 $MODPATH/system/lib64
  chcon -R u:object_r:system_bin_file:s0 $MODPATH/system/bin
  chcon -R u:object_r:firmware_file:s0 $MODPATH/system/etc/wifi
}

set_permissions() {
  set_perm_recursive $MODPATH 0 0 0755 0644
  set_perm_recursive $MODPATH/system/bin 0 0 0755 0755
  set_perm_recursive $MODPATH/system/lib64 0 0 0755 0755
}
EOF

# Create post-fs-data.sh
cat > post-fs-data.sh << 'EOF'
#!/system/bin/sh
# This script will be executed in post-fs-data mode

# Set proper SELinux contexts for libraries
chcon -R u:object_r:system_lib_file:s0 /data/adb/modules/nexmon_aircrack/system/lib64

# Make sure firmware is accessible
if [ -f /data/adb/modules/nexmon_aircrack/system/etc/wifi/bcmdhd_sta.bin_c0 ]; then
  chcon u:object_r:firmware_file:s0 /data/adb/modules/nexmon_aircrack/system/etc/wifi/bcmdhd_sta.bin_c0
  chmod 0644 /data/adb/modules/nexmon_aircrack/system/etc/wifi/bcmdhd_sta.bin_c0
fi

exit 0
EOF
chmod 755 post-fs-data.sh

# Copy nexmon files
cp ~/nexmon/utilities/nexutil/libs/arm64-v8a/nexutil system/bin/
cp ~/nexmon/patches/bcm43596a0/9.96.4_sta_c0/nexmon/fw_bcmdhd.bin system/etc/wifi/bcmdhd_sta.bin_c0
cp ~/nexmon/utilities/libnexmon/libs/arm64-v8a/libnexmon.so system/lib64/
cp ~/nexmon/utilities/libfakeioctl/libs/arm64-v8a/libfakeioctl.so system/lib64/
cp ~/nexmon/utilities/libnexmonitor/libs/arm64-v8a/libnexmonitor.so system/lib64/





# Copy aircrack binaries and create wrappers
cd ~/aircrack-ng/.libs
for bin in aircrack-ng aireplay-ng airodump-ng airbase-ng airdecap-ng \
          airdecloak-ng airserv-ng airtun-ng airventriloquist-ng \
          wpaclean makeivs-ng packetforge-ng; do
    cp $bin ~/nexmon_magisk/system/bin/$bin.bin
    if [ "$bin" = "airodump-ng" ]; then
        cat > ~/nexmon_magisk/system/bin/$bin << 'EOF'
#!/system/bin/sh
export LD_LIBRARY_PATH=/system/lib64/aircrack:$LD_LIBRARY_PATH
export LD_PRELOAD=/system/lib64/libnexmonitor.so

# Save current monitor mode
PREVIOUS_MODE=$(nexutil --monitor | cut -d' ' -f2)

# Setup monitor mode properly
nexutil --monitor=1 >/dev/null 2>&1

# Initialize variables
CHANNEL=""
INTERFACE=""
OTHER_ARGS=""

# Parse all arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--channel)
            CHANNEL="$2"
            shift 2
            ;;
        wlan*)
            INTERFACE="$1"
            shift
            ;;
        *)
            OTHER_ARGS="$OTHER_ARGS $1"
            shift
            ;;
    esac
done

# Set channel if specified
if [ -n "$CHANNEL" ]; then
    nexutil --chanspec=$CHANNEL >/dev/null 2>&1
fi

# Run the actual command, ensuring interface is the first argument if present
if [ -n "$INTERFACE" ]; then
    /system/bin/airodump-ng.bin "$INTERFACE" $OTHER_ARGS
else
    /system/bin/airodump-ng.bin $OTHER_ARGS
fi
RESULT=$?

# Restore previous monitor mode
nexutil --monitor=$PREVIOUS_MODE >/dev/null 2>&1

exit $RESULT
EOF
    elif [ "$bin" = "aireplay-ng" ]; then
        cat > ~/nexmon_magisk/system/bin/$bin << 'EOF'
#!/system/bin/sh
export LD_LIBRARY_PATH=/system/lib64/aircrack:$LD_LIBRARY_PATH
export LD_PRELOAD=/system/lib64/libnexmonitor.so

# Save current monitor mode
PREVIOUS_MODE=$(nexutil --monitor | cut -d' ' -f2)

# Setup injection mode
nexutil --monitor=2 >/dev/null 2>&1

# Run the actual command
/system/bin/aireplay-ng.bin "$@"
RESULT=$?

# Restore previous monitor mode
nexutil --monitor=$PREVIOUS_MODE >/dev/null 2>&1

exit $RESULT
EOF
    else
        cat > ~/nexmon_magisk/system/bin/$bin << EOF
#!/system/bin/sh
export LD_LIBRARY_PATH=/system/lib64/aircrack:\$LD_LIBRARY_PATH
export LD_PRELOAD=/system/lib64/libnexmonitor.so
exec /system/bin/${bin}.bin "\$@"
EOF
    fi
    chmod 755 ~/nexmon_magisk/system/bin/$bin
done








# Copy aircrack libraries and dependencies
cd ~/aircrack-ng/.libs
cp libaircrack-ce-wpa-1.7.0.so ~/nexmon_magisk/system/lib64/aircrack/
cp libaircrack-ce-wpa-arm-neon-1.7.0.so ~/nexmon_magisk/system/lib64/aircrack/
cp libaircrack-osdep-1.7.0.so ~/nexmon_magisk/system/lib64/aircrack/

# Copy NDK dependencies
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libhwloc.so* ~/nexmon_magisk/system/lib64/aircrack/
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libpcre2-8.so* ~/nexmon_magisk/system/lib64/aircrack/
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libpcre2-16.so* ~/nexmon_magisk/system/lib64/aircrack/
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libpcre2-32.so* ~/nexmon_magisk/system/lib64/aircrack/
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libpcre2-posix.so* ~/nexmon_magisk/system/lib64/aircrack/
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libssl.so.1.1 ~/nexmon_magisk/system/lib64/aircrack/
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libcrypto.so.1.1 ~/nexmon_magisk/system/lib64/aircrack/
cp $ANDROID_NDK_ROOT/sysroot/usr/lib/libnl*.so ~/nexmon_magisk/system/lib64/aircrack/

# Create symbolic links
cd ~/nexmon_magisk/system/lib64/aircrack
ln -sf libaircrack-ce-wpa-1.7.0.so libaircrack-ce-wpa.so
ln -sf libaircrack-ce-wpa-arm-neon-1.7.0.so libaircrack-ce-wpa-arm-neon.so
ln -sf libaircrack-osdep-1.7.0.so libaircrack-osdep.so
ln -sf libssl.so.1.1 libssl.so
ln -sf libcrypto.so.1.1 libcrypto.so

# Set final permissions
cd ~/nexmon_magisk
chmod -R 755 system/bin/*
chmod -R 755 system/lib64/*
chmod 644 system/etc/wifi/bcmdhd_sta.bin_c0

# Create the module zip
rm -f ../nexmon_magisk.zip
zip -r9 ../nexmon_magisk.zip .
echo "Module has been created as nexmon_magisk.zip"

cd ..
adb push nexmon_magisk.zip /sdcard/

