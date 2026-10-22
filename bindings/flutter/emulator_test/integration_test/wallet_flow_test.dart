// Runs on an Android device or emulator against the bundled liblepic_ffi.so built with the mock
// node. Start it with `cargo xtask mobile --emulator-test` from the repository root.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:lepic/lepic.dart';

const password = 'correct horse battery staple';

/// A valid BIP-39 phrase for the restored wallet. Not a real wallet.
const bobPhrase =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon '
    'abandon abandon abandon abandon abandon art';
const epic = 100000000;

class MemoryStore implements SecretStore {
  final Map<String, String> values = {};

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<void> delete(String key) async => values.remove(key);
}

WalletConfig configFor(Directory dir) => WalletConfig(
  dataDir: dir.path,
  chain: Chain.floonet,
  nodeUrl: 'http://127.0.0.1:1',
  epicboxDomain: '',
  epicboxPort: 443,
);

Future<void> scanToEnd(EpicWallet wallet) async {
  final events = await wallet.scan(deleteUnconfirmed: false).toList();
  expect(events.last.finished, isTrue);
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  late Directory root;

  setUpAll(() async {
    // The default loader: the library comes from the APK, as it does in the app.
    await RustLib.init();
  });

  setUp(() {
    root = Directory.systemTemp.createTempSync('lepic-emulator-test-');
  });

  tearDown(() {
    root.deleteSync(recursive: true);
  });

  Directory walletDir(String name) =>
      Directory('${root.path}/$name')..createSync();

  testWidgets(
    'creates, restores, sends, receives and finalizes through files',
    (tester) async {
      final chain = MockChain(height: BigInt.one);
      final runtime = chain.runtime(logLevel: LogLevel.info);

      // Alice: a new wallet, funded on chain, then found by a scan.
      final alice = await EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('alice')),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      final phrase = await alice.mnemonic(password: password);
      expect(validateMnemonic(phrase: phrase), isTrue);
      chain.fund(
        mnemonic: phrase,
        chain: Chain.floonet,
        amount: BigInt.from(10 * epic),
        child: 0,
      );
      chain.setHeight(height: BigInt.from(20));
      await scanToEnd(alice);
      expect(
        (await alice.summary(refresh: true)).spendable,
        BigInt.from(10 * epic),
      );

      // Bob: restored from a typed-in phrase.
      final bob = await EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('bob')),
        store: lepicSecretStore(MemoryStore()),
        mnemonic: bobPhrase,
        password: password,
      );
      expect(await bob.mnemonic(password: password), bobPhrase);
      await scanToEnd(bob);

      // Alice sends 3 EPIC through a slate file, Bob answers, Alice finalizes and posts.
      final file = '${root.path}/to-bob.slate';
      final sent = await alice.sendFile(
        amount: BigInt.from(3 * epic),
        minimumConfirmations: BigInt.one,
        path: file,
      );
      final answer = await bob.receiveFile(path: file);
      expect(answer.slateId, sent.slateId);
      expect(File('$file.response').existsSync(), isTrue);
      final posted = await alice.finalizeFile(path: '$file.response');
      expect(posted.txId, sent.txId);
      expect(chain.pushedCount(), 1);

      chain.minePushed();
      chain.setHeight(height: BigInt.from(40));
      final aliceAfter = await alice.summary(refresh: true);
      expect(aliceAfter.total, BigInt.from(7 * epic) - sent.fee);
      expect((await bob.summary(refresh: true)).total, BigInt.from(3 * epic));

      // Alice's phrase restores her funds into a fresh directory.
      alice.dispose();
      final restored = await EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('alice-restored')),
        store: lepicSecretStore(MemoryStore()),
        mnemonic: phrase,
        password: 'another password',
      );
      await scanToEnd(restored);
      expect((await restored.summary(refresh: true)).total, aliceAfter.total);

      restored.dispose();
      bob.dispose();
    },
  );
}
