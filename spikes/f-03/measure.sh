#!/usr/bin/env bash
# Throwaway measurement driver for spike F-03. Clean release build per target and stack, no
# sccache, 4 jobs, then records sizes. Output: results/<target>-<stack>.txt
set -euo pipefail
cd "$(dirname "$0")"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$HOME/Android/Sdk/ndk/28.2.13676358}"
export CARGO_BUILD_JOBS=4
unset RUSTC_WRAPPER
API=24
mkdir -p results
STRIP="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
for target in ${TARGETS:-aarch64-linux-android x86_64-linux-android}; do
  for stack in ${STACKS:-core stack-reqwest stack-hyper}; do
    features=""; [ "$stack" != core ] && features="$stack"
    tdir="target-measure/$target-$stack"
    rm -rf "$tdir"
    out="results/$target-$stack.txt"
    cmd=(cargo ndk -t "$target" -P "$API" build --release --lib --target-dir "$tdir")
    [ -n "$features" ] && cmd+=(--features "$features")
    start=$(date +%s)
    "${cmd[@]}" > "results/$target-$stack.log" 2>&1
    end=$(date +%s)
    rel="$tdir/$target/release"
    cp "$rel/libf03_spike.a" "$rel/libf03_spike.stripped.a"
    "$STRIP" --strip-debug "$rel/libf03_spike.stripped.a"
    {
      echo "command: ANDROID_NDK_HOME=${ANDROID_NDK_HOME/#$HOME/\~} CARGO_BUILD_JOBS=4 ${cmd[*]}"
      echo "build_seconds: $((end - start))"
      echo "cdylib_stripped_bytes: $(stat -c %s "$rel/libf03_spike.so")"
      echo "staticlib_bytes: $(stat -c %s "$rel/libf03_spike.a")"
      echo "staticlib_strip_debug_bytes: $(stat -c %s "$rel/libf03_spike.stripped.a")"
    } > "$out"
    cat "$out"
  done
done
