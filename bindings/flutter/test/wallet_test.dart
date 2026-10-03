// Runs against the native library built with the mock node:
//   cargo build -p lepic-ffi --features mock
//   flutter test
// LEPIC_FFI_LIB overrides the library path.

import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:flutter_test/flutter_test.dart';
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

class FailingStore implements SecretStore {
  @override
  Future<String?> read(String key) async => throw StateError('keystore locked');

  @override
  Future<void> write(String key, String value) async =>
      throw StateError('keystore locked');

  @override
  Future<void> delete(String key) async => throw StateError('keystore locked');
}

String libraryPath() =>
    Platform.environment['LEPIC_FFI_LIB'] ??
    '${Directory.current.path}/../../target/debug/liblepic_ffi.so';

WalletConfig configFor(Directory dir) => WalletConfig(
  dataDir: dir.path,
  chain: Chain.floonet,
  nodeUrl: 'http://127.0.0.1:1',
  epicboxDomain: '',
  epicboxPort: 443,
);

Matcher throwsWalletError(WalletErrorKind kind) => throwsA(
  isA<WalletError>()
      .having((e) => e.kind, 'kind', kind)
      .having((e) => e.code, 'code', isPositive),
);

Future<void> scanToEnd(EpicWallet wallet) async {
  final events = await wallet.scan().toList();
  expect(events.last.finished, isTrue);
}

void main() {
  late Directory root;
  late MockChain chain;
  late LepicRuntime runtime;

  setUpAll(() async {
    await RustLib.init(externalLibrary: ExternalLibrary.open(libraryPath()));
  });

  setUp(() {
    root = Directory.systemTemp.createTempSync('lepic-flutter-test-');
    chain = MockChain(height: BigInt.one);
    runtime = chain.runtime(logLevel: LogLevel.info);
  });

  tearDown(() {
    root.deleteSync(recursive: true);
  });

  Directory walletDir(String name) =>
      Directory('${root.path}/$name')..createSync();

  test('creates, restores, sends and receives through files', () async {
    final logs = <LogEntry>[];
    final logSubscription = runtime.logs().listen(logs.add);

    // Alice: a new wallet, funded on chain, then found by a scan.
    final aliceStore = MemoryStore();
    final aliceConfig = configFor(walletDir('alice'));
    final alice = await EpicWallet.create(
      runtime: runtime,
      config: aliceConfig,
      store: lepicSecretStore(aliceStore),
      password: password,
    );
    final phrase = await alice.mnemonic(password: password);
    expect(validateMnemonic(phrase: phrase), isTrue);
    expect(aliceStore.values.keys, ['lepic.vault']);
    expect(aliceStore.values.values.single, isNot(contains(phrase)));

    chain.fund(
      mnemonic: phrase,
      chain: Chain.floonet,
      amount: BigInt.from(10 * epic),
      child: 0,
    );
    chain.setHeight(height: BigInt.from(20));
    await scanToEnd(alice);
    final funded = await alice.summary(refresh: true);
    expect(funded.total, BigInt.from(10 * epic));
    expect(funded.spendable, BigInt.from(10 * epic));

    // Bob: restored from a typed-in phrase.
    expect(validateMnemonic(phrase: bobPhrase), isTrue);
    final bob = await EpicWallet.create(
      runtime: runtime,
      config: configFor(walletDir('bob')),
      store: lepicSecretStore(MemoryStore()),
      mnemonic: bobPhrase,
      password: password,
    );
    expect(await bob.mnemonic(password: password), bobPhrase);
    await scanToEnd(bob);

    // Alice sends 3 EPIC as text, Bob signs it, Alice finalizes and posts.
    final s1 = await alice.createSendSlate(
      amount: BigInt.from(3 * epic),
      minimumConfirmations: BigInt.one,
    );
    expect(s1.json, contains(s1.slateId));
    final s2 = await bob.receiveSlate(slateJson: s1.json);
    expect(s2.slateId, s1.slateId);
    final posted = await alice.finalizeAndPost(slateJson: s2.json);
    expect(posted.slateId, s1.slateId);
    expect(posted.txId, s1.txId);
    expect(chain.pushedCount(), 1);

    // Bob sends 1 EPIC back through slate files, as epic-wallet names them.
    chain.minePushed();
    chain.setHeight(height: BigInt.from(40));
    final bobBalance = await bob.summary(refresh: true);
    expect(bobBalance.spendable, BigInt.from(3 * epic));
    final file = '${root.path}/to-alice.slate';
    final sent = await bob.sendFile(
      amount: BigInt.from(epic),
      minimumConfirmations: BigInt.one,
      path: file,
    );
    final answer = await alice.receiveFile(path: file);
    expect(answer.slateId, sent.slateId);
    expect(File('$file.response').existsSync(), isTrue);
    final back = await bob.finalizeFile(path: '$file.response');
    expect(back.txId, sent.txId);
    expect(chain.pushedCount(), 2);

    chain.minePushed();
    chain.setHeight(height: BigInt.from(60));
    final aliceAfter = await alice.summary(refresh: true);
    final bobAfter = await bob.summary(refresh: true);
    // Alice paid 3 EPIC plus a fee and got 1 EPIC back; Bob paid 1 EPIC plus a fee.
    expect(aliceAfter.total < BigInt.from(8 * epic), isTrue);
    expect(aliceAfter.total > BigInt.from(7 * epic), isTrue);
    expect(bobAfter.total, BigInt.from(2 * epic) - sent.fee);

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
    final restoredBalance = await restored.summary(refresh: true);
    expect(restoredBalance.total, aliceAfter.total);

    // The original directory opens again with the stored vault, and only with its password.
    await expectLater(
      EpicWallet.open(
        runtime: runtime,
        config: aliceConfig,
        store: lepicSecretStore(aliceStore),
        password: 'wrong',
      ),
      throwsWalletError(WalletErrorKind.wrongPassword),
    );
    final reopened = await EpicWallet.open(
      runtime: runtime,
      config: aliceConfig,
      store: lepicSecretStore(aliceStore),
      password: password,
    );
    expect((await reopened.summary(refresh: true)).total, aliceAfter.total);

    runtime.stopLogs();
    await logSubscription.cancel();
    expect(logs.map((entry) => entry.message), contains('slate finalized'));
    final logText = logs
        .map((e) => '${e.message} ${e.fields.map((f) => f.value).join(' ')}')
        .join('\n');
    expect(logText, isNot(contains(phrase)));
    expect(logText, isNot(contains(bobPhrase)));
    expect(logText, isNot(contains(password)));
  });

  test('a panic inside the engine reaches Dart as an error', () async {
    final wallet = await EpicWallet.create(
      runtime: runtime,
      config: configFor(walletDir('panics')),
      store: lepicSecretStore(MemoryStore()),
      password: password,
    );
    chain.panicOnNextNodeCall();
    await expectLater(
      wallet.summary(refresh: true),
      throwsWalletError(WalletErrorKind.panic),
    );
    // The wallet and the runtime keep working after the panic.
    final summary = await wallet.summary(refresh: true);
    expect(summary.total, BigInt.zero);
  });

  test('errors carry stable kinds and codes', () async {
    final dir = walletDir('errors');
    final store = MemoryStore();
    await EpicWallet.create(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      password: password,
    ).then((wallet) => wallet.dispose());
    expect(
      await walletExists(runtime: runtime, store: lepicSecretStore(store)),
      isTrue,
    );
    await expectLater(
      EpicWallet.create(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        password: password,
      ),
      throwsWalletError(WalletErrorKind.walletAlreadyExists),
    );
    await expectLater(
      EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('bad-phrase')),
        store: lepicSecretStore(MemoryStore()),
        mnemonic: 'not a recovery phrase',
        password: password,
      ),
      throwsWalletError(WalletErrorKind.invalidMnemonic),
    );
    await expectLater(
      EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('failing-store')),
        store: lepicSecretStore(FailingStore()),
        password: password,
      ),
      throwsWalletError(WalletErrorKind.secretStore),
    );
    final open = await EpicWallet.open(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      password: password,
    );
    await expectLater(
      deleteWallet(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
      ),
      throwsWalletError(WalletErrorKind.walletBusy),
    );
    await expectLater(
      open.createSendSlate(
        amount: BigInt.from(epic),
        minimumConfirmations: BigInt.one,
      ),
      throwsWalletError(WalletErrorKind.notEnoughFunds),
    );
    open.dispose();
    await deleteWallet(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
    );
    expect(store.values, isEmpty);
    expect(WalletErrorKind.panic.index, isNonNegative);
  });

  test('pin unlock keeps the wallet password inside rust', () async {
    final dir = walletDir('pin');
    final store = MemoryStore();
    final created = await EpicWallet.createWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '1234',
    );
    final sealed = created.sealedPassword;
    final phrase = await created.wallet.mnemonicWithPin(
      pin: '1234',
      sealedPassword: sealed,
    );
    expect(validateMnemonic(phrase: phrase), isTrue);
    expect(sealed, isNot(contains('1234')));
    await expectLater(
      created.wallet.mnemonicWithPin(pin: '0000', sealedPassword: sealed),
      throwsWalletError(WalletErrorKind.wrongPassword),
    );
    created.wallet.dispose();

    await expectLater(
      EpicWallet.openWithPin(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        pin: '0000',
        sealedPassword: sealed,
      ),
      throwsWalletError(WalletErrorKind.wrongPassword),
    );
    await expectLater(
      EpicWallet.openWithPin(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        pin: '1234',
        sealedPassword: 'damaged',
      ),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
    final reopened = await EpicWallet.openWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '1234',
      sealedPassword: sealed,
    );
    expect(
      await reopened.mnemonicWithPin(pin: '1234', sealedPassword: sealed),
      phrase,
    );
  });
}
