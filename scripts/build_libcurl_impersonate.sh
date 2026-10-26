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

# Security backports: pull vulnerable bundled dependencies up to patched
# releases. curl-impersonate pins each dependency's version and archive hash
# in its CMakeLists.txt, so rewrite those two lines before the build fetches
# the sources. Fail loudly if a pin is not found, so a silent fall back to the
# vulnerable version cannot happen.
bump_dependency() {
  local name=$1 version=$2 hash=$3 cml="$src/CMakeLists.txt"
  grep -q "set(${name}_VERSION \"" "$cml" || {
    echo "no ${name}_VERSION pin in $cml" >&2; exit 1; }
  sed -i \
    -e "s|set(${name}_VERSION \"[^\"]*\")|set(${name}_VERSION \"${version}\")|" \
    -e "s|set(${name}_URL_HASH \"[^\"]*\")|set(${name}_URL_HASH \"SHA256=${hash}\")|" \
    "$cml"
  grep -q "set(${name}_VERSION \"${version}\")" "$cml" || {
    echo "failed to set ${name}_VERSION to ${version}" >&2; exit 1; }
  echo "bumped ${name} to ${version}"
}
# brotli 1.2.1 (CVE-2026-111497) and c-ares 1.34.9 are pure version bumps.
# nghttp2 and ngtcp2 keep their pinned versions so the HTTP/2 and QUIC output
# stays byte-identical: nghttp2 1.68.1 would adopt the shared sfparse symbol
# names that collide with nghttp3 1.15.0 at static link time, so CVE-2026-27135
# and the ngtcp2 qlog overflow (CVE-2026-40170) are carried as patches instead.
bump_dependency BROTLI 1.2.1 \
  98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f
bump_dependency CARES 1.34.9 \
  9364b70a12eb59a06830fb488d9357f90100dff0d98b23ea3593a183d43e6f2f

# curl-impersonate applies patches/<dep>.patch for these deps but not for
# nghttp2, so add a patch step to its nghttp2 ExternalProject. The marker line
# is unique to the nghttp2 block (nghttp3 uses a different source dir).
sed -i \
  's|SOURCE_DIR "${DEPS_SRC_DIR}/nghttp2"|&\n  PATCH_COMMAND ${PATCH_EXE} -p1 -i "${CMAKE_SOURCE_DIR}/patches/nghttp2.patch"|' \
  "$src/CMakeLists.txt"
grep -q 'patches/nghttp2.patch' "$src/CMakeLists.txt" || {
  echo "failed to add nghttp2 PATCH_COMMAND" >&2; exit 1; }

for dep in curl nghttp2 ngtcp2 nghttp3 boringssl; do
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
