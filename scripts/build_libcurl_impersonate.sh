#!/usr/bin/env bash
# Build the fork's libcurl-impersonate for x86_64 Linux (glibc 2.17): upstream
# curl-impersonate at the release pinned in native/curl-impersonate.env plus
# the patches in native/patches. The result is laid out like the upstream
# release archive, ready for IMPERSONATE_BUILD_DIR:
#
#   <out>/libdir/libcurl-impersonate.a   (curl and all dependencies)
#   <out>/libdir/include/curl/*.h
#
# usage: scripts/build_libcurl_impersonate.sh <out_dir>
# needs: zig on PATH, cmake, ninja, autoconf, automake, libtool, gperf, go
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../native/curl-impersonate.env
source "$root/native/curl-impersonate.env"

out=$(realpath -m "${1:?usage: $0 <out_dir>}")
src="$out/curl-impersonate"
install_dir="$out/install"
zig_target=${ZIG_TARGET:-x86_64-linux-gnu.2.17.0}

rm -rf "$src" "$install_dir" "$out/libdir"
mkdir -p "$out" "$install_dir"
git clone --quiet --depth 1 --branch "$CURL_IMPERSONATE_REF" \
  "$CURL_IMPERSONATE_REPO" "$src"

for dep in curl ngtcp2 nghttp3 boringssl; do
  for p in "$root"/native/patches/"$dep"/*.patch; do
    [[ -e "$p" ]] || continue
    echo "appending $(basename "$p") to patches/$dep.patch"
    printf '\n' >> "$src/patches/$dep.patch"
    cat "$p" >> "$src/patches/$dep.patch"
  done
done

export CC="$src/zigshim/cc" CXX="$src/zigshim/cxx" AR="$src/zigshim/ar"
export ZIG_FLAGS="-target $zig_target"
cmake_args="-G Ninja -DCMAKE_INSTALL_PREFIX=$install_dir"
cmake_args="$cmake_args -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=x86_64"
cmake_args="$cmake_args -DCURL_CA_PATH=/etc/ssl/certs"
cmake_args="$cmake_args -DCURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"
cmake_args="$cmake_args -DCURL_IMPERSONATE_VERSION=$CURL_IMPERSONATE_VERSION"

cd "$src"
make prepare-libidn2 BUILD_DIR=build
make configure BUILD_DIR=build CMAKE_CONFIGURE_ARGS="$cmake_args"
make build BUILD_DIR=build CMAKE_CONFIGURE_ARGS="$cmake_args"
make checkbuild BUILD_DIR=build CMAKE_CONFIGURE_ARGS="$cmake_args"
make install-strip BUILD_DIR=build CMAKE_CONFIGURE_ARGS="$cmake_args"

# Merge curl and its dependencies into one relocatable archive, as the
# upstream release workflow does.
lib_dir="$install_dir/lib"
deps_lib_dir="$src/build/deps/install/lib"
libs=(libz.a libzstd.a libbrotlidec.a libbrotlicommon.a libbrotlienc.a
      libnghttp2.a libnghttp3.a libngtcp2.a libngtcp2_crypto_boringssl.a
      libssl.a libcrypto.a libcares.a libidn2.a)
for l in "${libs[@]}"; do
  cp "$deps_lib_dir/$l" "$lib_dir/"
done
cd "$lib_dir"
mv libcurl-impersonate.a libcurl-impersonate.orig.a
cxx_link="$($CXX -### -shared -o probe.so libcurl-impersonate.orig.a 2>&1)"
libcxx="$(printf '%s\n' "$cxx_link" | grep -oE '/[^[:space:]]+/libc\+\+\.a' | head -n 1)"
libcxxabi="$(printf '%s\n' "$cxx_link" | grep -oE '/[^[:space:]]+/libc\+\+abi\.a' | head -n 1)"
libunwind="$(printf '%s\n' "$cxx_link" | grep -oE '/[^[:space:]]+/libunwind\.a' | head -n 1)"
"$CC" -r -o libcurl-impersonate.full.o \
  -Wl,--whole-archive libcurl-impersonate.orig.a "${libs[@]}" -Wl,--no-whole-archive \
  -Wl,--start-group "$libcxx" "$libcxxabi" "$libunwind" -Wl,--end-group
"$AR" rcs libcurl-impersonate.a libcurl-impersonate.full.o
if nm -u libcurl-impersonate.a | grep -E '[[:space:]]U (_Z|__cxa|__gxx|_Unwind)'; then
  echo "unresolved C++ runtime symbols in libcurl-impersonate.a" >&2
  exit 1
fi
rm -f libcurl-impersonate.full.o libcurl-impersonate.orig.a "${libs[@]}"

mkdir -p "$out/libdir"
cp libcurl-impersonate.a "$out/libdir/"
cp -R "$install_dir/include" "$out/libdir/"
mkdir -p "$out/bin"
cp "$install_dir/bin/curl-impersonate" "$out/bin/curl-impersonate"
echo "built $out/libdir/libcurl-impersonate.a"
