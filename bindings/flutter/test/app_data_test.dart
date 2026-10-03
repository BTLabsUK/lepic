// Runs on Linux against the library the build hook bundles from `test_native/`, which holds
// lepic-ffi built with the mock node. From the repository root:
//   cargo xtask mobile --host-test

import 'dart:convert';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lepic/lepic.dart';

import 'wallet_test.dart'
    show MemoryStore, configFor, libraryPath, password, throwsWalletError;

/// A `.wfeh` file sealed by an implementation independent of LEPIC's, and the phrase of its
/// wallet (`testdata/vectors/app_data`).
Map<String, dynamic> goldenVector() => jsonDecode(
  File('../../testdata/vectors/app_data/wfeh_seed_a.json').readAsStringSync(),
) as Map<String, dynamic>;

Uint8List unhex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

void main() {
  late Directory root;
  late LepicRuntime runtime;

  setUpAll(() async {
    await RustLib.init(externalLibrary: ExternalLibrary.open(libraryPath()));
  });

  setUp(() {
    root = Directory.systemTemp.createTempSync('lepic-flutter-app-data-');
    runtime = MockChain(height: BigInt.one).runtime(logLevel: LogLevel.info);
  });

  tearDown(() {
    root.deleteSync(recursive: true);
  });

  Future<EpicWallet> wallet(String name, {String? mnemonic}) {
    final dir = Directory('${root.path}/$name')..createSync();
    return EpicWallet.create(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(MemoryStore()),
      mnemonic: mnemonic,
      password: password,
    );
  }

  final payload = Uint8List.fromList(utf8.encode('{"format":"wfe-history"}'));

  test('the golden wfeh file opens to its payload', () async {
    final vector = goldenVector();
    final inputs = vector['inputs'] as Map<String, dynamic>;
    final expected = vector['expected'] as Map<String, dynamic>;
    final restored = await wallet(
      'golden',
      mnemonic: inputs['mnemonic'] as String,
    );
    final opened = await restored.openAppData(
      file: unhex(expected['file'] as String),
    );
    expect(utf8.decode(opened), inputs['payload']);
  });

  test('a sealed file opens again and differs on every seal', () async {
    final own = await wallet('own');
    final first = await own.sealAppData(payload: payload);
    final second = await own.sealAppData(payload: payload);
    expect(first.sublist(0, 4), utf8.encode('WFEH'));
    expect(first, isNot(equals(second)));
    expect(await own.openAppData(file: first), payload);
    expect(await own.openAppData(file: second), payload);
  });

  test(
    'another wallet\'s file and a flipped byte have their own errors',
    () async {
      final own = await wallet('own');
      final other = await wallet('other');
      final file = await own.sealAppData(payload: payload);

      await expectLater(
        other.openAppData(file: file),
        throwsWalletError(WalletErrorKind.foreignAppData),
      );
      final flipped = Uint8List.fromList(file)..[file.length - 1] ^= 1;
      await expectLater(
        own.openAppData(file: flipped),
        throwsWalletError(WalletErrorKind.damagedAppData),
      );
      final newer = Uint8List.fromList(file)..[4] = 2;
      await expectLater(
        own.openAppData(file: newer),
        throwsWalletError(WalletErrorKind.unsupported),
      );
      await expectLater(
        own.openAppData(file: Uint8List.fromList(utf8.encode('not a file'))),
        throwsWalletError(WalletErrorKind.invalidArgument),
      );
    },
  );

  test('a locked wallet neither seals nor opens', () async {
    final own = await wallet('locked');
    final file = await own.sealAppData(payload: payload);
    own.lock();
    await expectLater(
      own.sealAppData(payload: payload),
      throwsWalletError(WalletErrorKind.locked),
    );
    await expectLater(
      own.openAppData(file: file),
      throwsWalletError(WalletErrorKind.locked),
    );
  });
}
