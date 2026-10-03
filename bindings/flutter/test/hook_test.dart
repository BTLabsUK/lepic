// Runs hook/build.dart in isolation for each target it handles. Needs no native library: the
// mobile cases point the `native_dir` user define at stand-in files.

import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks/hooks.dart';

import '../hook/build.dart' as hook;

late Directory nativeDir;

PackageUserDefines nativeDirDefine() => PackageUserDefines(
  workspacePubspec: PackageUserDefinesSource(
    defines: {'native_dir': nativeDir.path},
    basePath: nativeDir.uri,
  ),
);

File standIn(String target, String fileName) =>
    File('${nativeDir.path}/$target/$fileName')
      ..createSync(recursive: true)
      ..writeAsBytesSync([0]);

Future<List<CodeAsset>> bundled({
  required OS os,
  required Architecture arch,
  IOSSdk iosSdk = IOSSdk.iPhoneOS,
  int androidApi = 30,
  LinkModePreference linkMode = LinkModePreference.dynamic,
}) async {
  late List<CodeAsset> assets;
  await testCodeBuildHook(
    mainMethod: hook.main,
    targetOS: os,
    targetArchitecture: arch,
    targetIOSSdk: iosSdk,
    targetAndroidNdkApi: androidApi,
    linkModePreference: linkMode,
    userDefines: nativeDirDefine(),
    check: (input, output) => assets = output.assets.code,
  );
  return assets;
}

void main() {
  setUp(() => nativeDir = Directory.systemTemp.createTempSync('lepic_native_'));
  tearDown(() => nativeDir.deleteSync(recursive: true));

  test('bundles the android library for each abi as the frb asset', () async {
    for (final (arch, target) in [
      (Architecture.arm64, 'aarch64-linux-android'),
      (Architecture.arm, 'armv7-linux-androideabi'),
      (Architecture.x64, 'x86_64-linux-android'),
    ]) {
      final library = standIn(target, 'liblepic_ffi.so');
      final assets = await bundled(os: OS.android, arch: arch);
      expect(assets, hasLength(1));
      expect(assets.single.id, 'package:lepic/src/rust/frb_generated.io.dart');
      expect(assets.single.linkMode, isA<DynamicLoadingBundled>());
      expect(assets.single.file, library.uri);
    }
  });

  test('bundles the ios device and simulator libraries', () async {
    final device = standIn('aarch64-apple-ios', 'liblepic_ffi.dylib');
    final simulator = standIn('aarch64-apple-ios-sim', 'liblepic_ffi.dylib');
    expect(
      (await bundled(os: OS.iOS, arch: Architecture.arm64)).single.file,
      device.uri,
    );
    expect(
      (await bundled(
        os: OS.iOS,
        arch: Architecture.arm64,
        iosSdk: IOSSdk.iPhoneSimulator,
      )).single.file,
      simulator.uri,
    );
  });

  test('bundles nothing for desktop and host test builds', () async {
    expect(await bundled(os: OS.linux, arch: Architecture.x64), isEmpty);
  });

  test('fails with the packaging command when the library is missing', () {
    expect(
      bundled(os: OS.android, arch: Architecture.arm64),
      throwsA(
        isA<StateError>().having(
          (e) => e.message,
          'message',
          contains('cargo xtask mobile --package'),
        ),
      ),
    );
  });

  test('rejects targets lepic does not build', () async {
    standIn('aarch64-linux-android', 'liblepic_ffi.so');
    await expectLater(
      bundled(os: OS.android, arch: Architecture.arm64, androidApi: 23),
      throwsUnsupportedError,
    );
    await expectLater(
      bundled(
        os: OS.android,
        arch: Architecture.arm64,
        linkMode: LinkModePreference.static,
      ),
      throwsUnsupportedError,
    );
    await expectLater(
      bundled(
        os: OS.iOS,
        arch: Architecture.x64,
        iosSdk: IOSSdk.iPhoneSimulator,
      ),
      throwsUnsupportedError,
    );
  });
}
