// Bundles the prebuilt lepic-ffi library for the Android or iOS target being built, so an app gets
// it by depending on this package. `cargo xtask mobile --package` puts the libraries in
// `native/<rust target>/`; the `native_dir` user define points elsewhere.
//
// Desktop and `flutter test` builds get no asset: the generated loader then opens the library from
// its `ioDirectory`, and the package tests open it by path.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

/// The library file stem flutter_rust_bridge opens (`stem` in `lib/src/rust/frb_generated.dart`).
const libraryStem = 'lepic_ffi';

/// Must match `ANDROID_API_LEVEL` in `xtask/src/mobile.rs`: the libraries link against this API.
const androidApiLevel = 24;

void main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }
    final code = input.config.code;
    final target = rustTarget(code);
    if (target == null) {
      return;
    }
    if (code.linkModePreference == LinkModePreference.static) {
      throw UnsupportedError(
        'package:lepic ships $libraryStem as a dynamic library only.',
      );
    }

    final definedDir = input.userDefines.path('native_dir');
    // Directory.uri ends in a slash, so a user define written without one still resolves inside.
    final nativeDir = definedDir == null
        ? input.packageRoot.resolve('native/')
        : Directory.fromUri(definedDir).uri;
    final library = File.fromUri(
      nativeDir.resolve('$target/${code.targetOS.dylibFileName(libraryStem)}'),
    );
    if (!library.existsSync()) {
      throw StateError(
        'No $target library at ${library.path}. Run '
        '`cargo xtask mobile --package --target $target` in the LEPIC repository.',
      );
    }

    output.dependencies.add(library.uri);
    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: 'src/rust/frb_generated.io.dart',
        linkMode: DynamicLoadingBundled(),
        file: library.uri,
      ),
    );
  });
}

/// The Rust target triple for a mobile build, or null when this package bundles nothing for the
/// target. Throws for a mobile target LEPIC does not build.
String? rustTarget(CodeConfig code) {
  final arch = code.targetArchitecture;
  switch (code.targetOS) {
    case OS.android:
      final api = code.android.targetNdkApi;
      if (api < androidApiLevel) {
        throw UnsupportedError(
          'package:lepic needs Android API $androidApiLevel or later; '
          'the app builds for API $api (raise minSdk).',
        );
      }
      return switch (arch) {
        Architecture.arm64 => 'aarch64-linux-android',
        Architecture.arm => 'armv7-linux-androideabi',
        Architecture.x64 => 'x86_64-linux-android',
        _ => throw UnsupportedError(
          'package:lepic has no Android $arch build.',
        ),
      };
    case OS.iOS:
      final simulator = code.iOS.targetSdk == IOSSdk.iPhoneSimulator;
      return switch ((arch, simulator)) {
        (Architecture.arm64, false) => 'aarch64-apple-ios',
        (Architecture.arm64, true) => 'aarch64-apple-ios-sim',
        _ => throw UnsupportedError(
          'package:lepic has no iOS ${simulator ? 'simulator ' : ''}$arch build.',
        ),
      };
    default:
      return null;
  }
}
