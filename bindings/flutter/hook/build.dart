// Bundles the prebuilt lepic-ffi library for the Android, iOS, Linux or Windows target being
// built, so an app gets it by depending on this package. `cargo xtask mobile --package` puts the
// libraries in `native/<rust target>/` next to a `SHA256SUMS` manifest, which is checked before
// bundling; the `native_dir` user define points elsewhere.
//
// `flutter test` on Linux runs this hook for the host too, so the package's own tests load the
// library it bundles. macOS builds get no asset.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';

/// The library file stem flutter_rust_bridge opens (`stem` in `lib/src/rust/frb_generated.dart`).
const libraryStem = 'lepic_ffi';

/// Must match `ANDROID_API_LEVEL` in `xtask/src/mobile.rs`: the libraries link against this API.
const androidApiLevel = 24;

/// Must match `MANIFEST_FILE` in `xtask/src/mobile.rs`: the `sha256sum` file written next to
/// each library.
const manifestFileName = 'SHA256SUMS';

/// Throws unless [manifest] exists and records the SHA-256 of [library], so a truncated,
/// mixed-up or replaced library is not bundled into the app.
void verifyLibrary(File library, File manifest, String target) {
  final repackage =
      'Run `cargo xtask mobile --package --target $target` in the LEPIC repository.';
  if (!manifest.existsSync()) {
    throw StateError(
      'No $manifestFileName next to ${library.path}. $repackage',
    );
  }
  final name = library.uri.pathSegments.last;
  final entry = RegExp(r'^([0-9a-f]{64}) [ *](.+)$');
  final recorded = [
    for (final line in manifest.readAsLinesSync())
      if (entry.firstMatch(line) case final match? when match[2] == name)
        match[1],
  ];
  if (recorded.length != 1) {
    throw StateError(
      '${manifest.path} does not record one SHA-256 for $name. $repackage',
    );
  }
  final actual = sha256.convert(library.readAsBytesSync()).toString();
  if (actual != recorded.single) {
    throw StateError(
      '${library.path} does not match its SHA-256 in ${manifest.path}. $repackage',
    );
  }
}

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
    final manifest = File.fromUri(library.uri.resolve(manifestFileName));
    verifyLibrary(library, manifest, target);

    output.dependencies
      ..add(library.uri)
      ..add(manifest.uri);
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

/// The Rust target triple for a build, or null when this package bundles nothing for the target.
/// Throws for an Android, iOS, Linux or Windows target LEPIC does not build.
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
    case OS.linux:
      return switch (arch) {
        Architecture.x64 => 'x86_64-unknown-linux-gnu',
        _ => throw UnsupportedError('package:lepic has no Linux $arch build.'),
      };
    case OS.windows:
      return switch (arch) {
        Architecture.x64 => 'x86_64-pc-windows-msvc',
        _ => throw UnsupportedError(
          'package:lepic has no Windows $arch build.',
        ),
      };
    default:
      return null;
  }
}
