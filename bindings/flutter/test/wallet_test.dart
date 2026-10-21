// Runs on Linux against the library the build hook bundles from `test_native/`, which holds
// lepic-ffi built with the mock node. From the repository root:
//   cargo xtask mobile --host-test

import 'dart:async';
import 'dart:convert';
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

String libraryPath() {
  // `flutter test` runs hook/build.dart for the host and records where it installed each code
  // asset; opening that file proves the hook bundled the library.
  const assetId = 'package:lepic/src/rust/frb_generated.io.dart';
  final manifest = File('build/native_assets/linux/native_assets.json');
  if (!manifest.existsSync()) {
    throw StateError(
      'No ${manifest.path}: the build hook bundled no library. '
      'Run `cargo xtask mobile --host-test` from the LEPIC repository.',
    );
  }
  return switch (jsonDecode(manifest.readAsStringSync())) {
    {
      'native-assets': {
        'linux_x64': {assetId: ['absolute', final String path]},
      },
    } =>
      path,
    _ => throw StateError('${manifest.path} has no absolute path for $assetId'),
  };
}

WalletConfig configFor(Directory dir) => WalletConfig(
  dataDir: dir.path,
  chain: Chain.floonet,
  nodeUrl: 'http://127.0.0.1:1',
  epicboxDomain: '',
  epicboxPort: 443,
);

/// The stable codes of `bindings/flutter/README.md`, which apps may store.
const errorCodes = {
  WalletErrorKind.invalidMnemonic: 1,
  WalletErrorKind.wrongPassword: 2,
  WalletErrorKind.walletAlreadyExists: 3,
  WalletErrorKind.walletNotFound: 4,
  WalletErrorKind.nodeUnreachable: 5,
  WalletErrorKind.notEnoughFunds: 6,
  WalletErrorKind.invalidSlate: 7,
  WalletErrorKind.invalidArgument: 8,
  WalletErrorKind.transportFailed: 9,
  WalletErrorKind.chainBusy: 10,
  WalletErrorKind.walletBusy: 11,
  WalletErrorKind.paymentExpired: 12,
  WalletErrorKind.io: 13,
  WalletErrorKind.other: 14,
  WalletErrorKind.locked: 15,
  WalletErrorKind.foreignWallet: 16,
  WalletErrorKind.secretStore: 17,
  WalletErrorKind.notPosted: 18,
  WalletErrorKind.cancelled: 19,
  WalletErrorKind.unsupported: 20,
  WalletErrorKind.panic: 21,
  WalletErrorKind.restoreScanRequired: 22,
  WalletErrorKind.changedDuringCancel: 23,
  WalletErrorKind.onChain: 24,
  WalletErrorKind.foreignAppData: 25,
  WalletErrorKind.damagedAppData: 26,
  WalletErrorKind.inPool: 27,
  WalletErrorKind.notReleasable: 28,
  WalletErrorKind.invoiceNotFound: 29,
  WalletErrorKind.amountMismatch: 30,
  WalletErrorKind.notDelivered: 31,
};

Matcher throwsWalletError(WalletErrorKind kind) => throwsA(
  isA<WalletError>()
      .having((e) => e.kind, 'kind', kind)
      .having((e) => e.code, 'code', errorCodes[kind]),
);

Future<void> scanToEnd(EpicWallet wallet) async {
  final events = await wallet.scan().toList();
  expect(events.last.finished, isTrue);
}

/// What a stream call delivered: its events, the errors on the stream, and the errors that
/// escaped to the zone the call was made in.
typedef StreamOutcome = ({
  List<Object> events,
  List<Object> errors,
  List<Object> zoneErrors,
});

Future<StreamOutcome> collect<T extends Object>(
  Stream<T> Function() call,
) async {
  final events = <Object>[];
  final errors = <Object>[];
  final zoneErrors = <Object>[];
  final done = Completer<void>();
  runZonedGuarded(() {
    call().listen(events.add, onError: errors.add, onDone: done.complete);
  }, (error, _) => zoneErrors.add(error));
  await done.future.timeout(const Duration(seconds: 30));
  // The call's own result may arrive after the stream ended.
  await Future<void>.delayed(const Duration(milliseconds: 200));
  return (events: events, errors: errors, zoneErrors: zoneErrors);
}

Matcher isWalletError(WalletErrorKind kind) => isA<WalletError>()
    .having((e) => e.kind, 'kind', kind)
    .having((e) => e.code, 'code', errorCodes[kind]);

/// Golden vector `keys/wallet_seed_seed32`: a `wallet.seed` that `epic-wallet` wrote.
({String file, String password, String wrongPassword, String phrase})
walletSeedVector() {
  final vector = jsonDecode(
    File('../../testdata/vectors/keys/wallet_seed_seed32.json')
        .readAsStringSync(),
  ) as Map<String, dynamic>;
  final inputs = vector['inputs'] as Map<String, dynamic>;
  return (
    file: (vector['expected'] as Map<String, dynamic>)['file'] as String,
    password: inputs['password'] as String,
    wrongPassword: inputs['wrong_password'] as String,
    phrase: inputs['mnemonic'] as String,
  );
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
    final restoredHistory = await restored.transactions();
    expect(restoredHistory, isNotEmpty);
    expect(restoredHistory.every((tx) => tx.messages.isEmpty), isTrue);

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

  test(
    'a slate received again returns the stored answer as repeated',
    () async {
      final alice = await EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('repeat-alice')),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      chain.fund(
        mnemonic: await alice.mnemonic(password: password),
        chain: Chain.floonet,
        amount: BigInt.from(10 * epic),
        child: 0,
      );
      chain.setHeight(height: BigInt.from(20));
      await scanToEnd(alice);
      final bob = await EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('repeat-bob')),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );

      // As text.
      final s1 = await alice.createSendSlate(
        amount: BigInt.from(epic),
        minimumConfirmations: BigInt.one,
      );
      final first = await bob.receiveSlate(slateJson: s1.json);
      final again = await bob.receiveSlate(slateJson: s1.json);
      expect(first.repeated, isFalse);
      expect(again.repeated, isTrue);
      expect(again.txId, first.txId);
      expect(again.slateId, first.slateId);
      expect(again.json, first.json);
      await alice.finalizeAndPost(slateJson: again.json);
      chain.minePushed();
      chain.setHeight(height: BigInt.from(40));
      await alice.summary(refresh: true);

      // As a file: the answer is written again, unchanged.
      final file = '${root.path}/repeat.slate';
      await alice.sendFile(
        amount: BigInt.from(2 * epic),
        minimumConfirmations: BigInt.one,
        path: file,
      );
      final firstFile = await bob.receiveFile(path: file);
      final response = File('$file.response');
      final firstResponse = response.readAsStringSync();
      response.deleteSync();
      final againFile = await bob.receiveFile(path: file);
      expect(firstFile.repeated, isFalse);
      expect(againFile.repeated, isTrue);
      expect(againFile.txId, firstFile.txId);
      expect(againFile.txId, isNot(first.txId));
      expect(againFile.json, firstFile.json);
      expect(response.readAsStringSync(), firstResponse);

      final history = await bob.transactions();
      expect(history.length, 2, reason: 'a repeat stores no transaction');
    },
  );

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

  test(
    'a refresh with the node failing ends its stream with the error',
    () async {
      final wallet = await EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('refresh-fails')),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      chain.setNodeUnreachable(unreachable: true);
      final outcome = await collect(wallet.refresh);
      expect(outcome.errors, [isWalletError(WalletErrorKind.nodeUnreachable)]);
      expect(outcome.zoneErrors, isEmpty);
      expect(outcome.events, [isA<RefreshProgress>()]);
    },
  );

  test('a scan with the node failing ends its stream with the error', () async {
    final wallet = await EpicWallet.create(
      runtime: runtime,
      config: configFor(walletDir('scan-fails')),
      store: lepicSecretStore(MemoryStore()),
      password: password,
    );
    chain.setNodeUnreachable(unreachable: true);
    final outcome = await collect(wallet.scan);
    expect(outcome.errors, [isWalletError(WalletErrorKind.nodeUnreachable)]);
    expect(outcome.zoneErrors, isEmpty);
    expect(outcome.events, isEmpty);
  });

  test('a listener without a relay ends its stream with the error', () async {
    final wallet = await EpicWallet.create(
      runtime: runtime,
      config: configFor(walletDir('listener-no-relay')),
      store: lepicSecretStore(MemoryStore()),
      password: password,
    );
    final outcome = await collect(wallet.startListener);
    expect(outcome.errors, [isWalletError(WalletErrorKind.unsupported)]);
    expect(outcome.zoneErrors, isEmpty);
    expect(outcome.events, isEmpty);
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
  });

  test('an epicbox address needs its relay', () async {
    final wallet = await EpicWallet.create(
      runtime: runtime,
      config: WalletConfig(
        dataDir: walletDir('address').path,
        chain: Chain.floonet,
        nodeUrl: 'http://127.0.0.1:1',
        epicboxDomain: 'epicbox.example',
        epicboxPort: 443,
      ),
      store: lepicSecretStore(MemoryStore()),
      password: password,
    );
    final address = await wallet.epicboxAddress();
    final key = address.split('@').first;
    expect(address, '$key@epicbox.example');
    for (final valid in [address, '$key@epicbox.example:443']) {
      expect(
        validateEpicboxAddress(address: valid, chain: Chain.floonet),
        isTrue,
        reason: valid,
      );
    }
    for (final invalid in [key, '$key@', '$key@epicbox.example:x']) {
      expect(
        validateEpicboxAddress(address: invalid, chain: Chain.floonet),
        isFalse,
        reason: invalid,
      );
    }
    expect(
      validateEpicboxAddress(address: address, chain: Chain.mainnet),
      isFalse,
    );
  });

  Future<(EpicWallet, EpicWallet, String)> fundedPair(String name) async {
    final aliceStore = MemoryStore();
    final alice = await EpicWallet.create(
      runtime: runtime,
      config: configFor(walletDir('$name-alice')),
      store: lepicSecretStore(aliceStore),
      password: password,
    );
    final phrase = await alice.mnemonic(password: password);
    chain.fund(
      mnemonic: phrase,
      chain: Chain.floonet,
      amount: BigInt.from(10 * epic),
      child: 0,
    );
    chain.setHeight(height: BigInt.from(20));
    await scanToEnd(alice);
    final bob = await EpicWallet.create(
      runtime: runtime,
      config: configFor(walletDir('$name-bob')),
      store: lepicSecretStore(MemoryStore()),
      mnemonic: bobPhrase,
      password: password,
    );
    await scanToEnd(bob);
    return (alice, bob, phrase);
  }

  test('history, fees and offline balance follow a send', () async {
    final (alice, bob, _) = await fundedPair('history');

    final max = await alice.estimateMax(minimumConfirmations: BigInt.one);
    expect(max.amount + max.fee, BigInt.from(10 * epic));
    expect(max.change, BigInt.zero);
    expect(max.inputCount, 1);
    final estimate = await alice.estimateFee(
      amount: BigInt.from(3 * epic),
      minimumConfirmations: BigInt.one,
    );
    expect(estimate.amount, BigInt.from(3 * epic));
    expect(estimate.inputCount, 1);
    expect(
      estimate.change,
      BigInt.from(10 * epic) - estimate.amount - estimate.fee,
    );
    await expectLater(
      alice.estimateFee(
        amount: BigInt.from(10 * epic),
        minimumConfirmations: BigInt.one,
      ),
      throwsWalletError(WalletErrorKind.notEnoughFunds),
    );
    // An estimate locks nothing.
    expect((await alice.summary(refresh: false)).locked, BigInt.zero);

    final s1 = await alice.createSendSlate(
      amount: BigInt.from(3 * epic),
      minimumConfirmations: BigInt.one,
    );
    final sent = await alice.transaction(txId: s1.txId);
    expect(sent.status, TxStatus.sent);
    expect(sent.direction, TxDirection.outgoing);
    expect(sent.flow, TxFlow.payment);
    expect(sent.slateId, s1.slateId);
    expect(sent.fee, estimate.fee);
    expect(
      sent.amountDebited - sent.amountCredited,
      estimate.amount + estimate.fee,
    );
    expect(sent.kernelExcess, isNull);
    expect(sent.confirmedHeight, isNull);
    expect(sent.confirmedAtMs, isNull);
    expect(sent.counterparty, isNull);
    expect(
      DateTime.fromMillisecondsSinceEpoch(sent.createdAtMs)
          .difference(DateTime.now())
          .abs(),
      lessThan(const Duration(minutes: 5)),
    );

    final s2 = await bob.receiveSlate(slateJson: s1.json);
    await alice.finalizeAndPost(slateJson: s2.json);
    final posted = await alice.transaction(txId: s1.txId);
    expect(posted.status, TxStatus.posted);
    expect(posted.kernelExcess, matches(RegExp(r'^[0-9a-f]{66}$')));

    chain.minePushed();
    chain.setHeight(height: BigInt.from(40));
    final refreshed = await alice.summary(refresh: true);
    expect(refreshed.validatedWithNode, isTrue);
    final history = await alice.transactions();
    expect(history.first.txId, s1.txId, reason: 'newest first');
    expect(history.map((tx) => tx.txId).toSet().length, history.length);
    final confirmed = history.first;
    expect(confirmed.status, TxStatus.confirmed);
    expect(confirmed.confirmedHeight, BigInt.from(20));
    expect(confirmed.confirmedAtMs, isNotNull);
    expect(confirmed.kernelExcess, posted.kernelExcess);
    expect(history.last.direction, TxDirection.incoming);

    final bobHistory = await bob.transactions();
    expect(bobHistory.first.direction, TxDirection.incoming);
    expect(bobHistory.first.flow, TxFlow.payment);
    expect(bobHistory.first.slateId, s1.slateId);
    expect(bobHistory.first.amountCredited, BigInt.from(3 * epic));
    await expectLater(
      alice.transaction(txId: 999),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );

    // Offline: the stored balance, also on a handle that never refreshed.
    chain.setNodeUnreachable(unreachable: true);
    final offline = await alice.summary(refresh: false);
    expect(offline.total, refreshed.total);
    expect(offline.spendable, refreshed.spendable);
    expect(offline.lastConfirmedHeight, refreshed.lastConfirmedHeight);
    expect(offline.validatedWithNode, isFalse);
    await expectLater(
      alice.estimateFee(amount: BigInt.one, minimumConfirmations: BigInt.one),
      throwsWalletError(WalletErrorKind.nodeUnreachable),
    );
  });

  test(
    'a wallet that never refreshed answers summary without the node',
    () async {
      final store = MemoryStore();
      final dir = walletDir('offline');
      final wallet = await EpicWallet.create(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        password: password,
      );
      chain.setNodeUnreachable(unreachable: true);
      final summary = await wallet.summary(refresh: false);
      expect(summary.total, BigInt.zero);
      expect(summary.validatedWithNode, isFalse);
      await expectLater(
        wallet.summary(refresh: true),
        throwsWalletError(WalletErrorKind.nodeUnreachable),
      );
      expect(await wallet.transactions(), isEmpty);
    },
  );

  test(
    'a reopened wallet shows its stored balance with the node down',
    () async {
      final store = MemoryStore();
      final dir = walletDir('reopen-offline');
      final wallet = await EpicWallet.create(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        password: password,
      );
      chain.fund(
        mnemonic: await wallet.mnemonic(password: password),
        chain: Chain.floonet,
        amount: BigInt.from(5 * epic),
        child: 0,
      );
      chain.setHeight(height: BigInt.from(20));
      await scanToEnd(wallet);
      final online = await wallet.summary(refresh: true);
      expect(online.total, BigInt.from(5 * epic));
      wallet.dispose();

      chain.setNodeUnreachable(unreachable: true);
      final reopened = await EpicWallet.open(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        password: password,
      );
      final offline = await reopened.summary(refresh: false);
      expect(offline.total, online.total);
      expect(offline.spendable, online.spendable);
      expect(offline.validatedWithNode, isFalse);
    },
  );

  test('inspect_slate reads every stage of V2 and V3 slates', () async {
    final vectors = Directory('../../testdata/vectors/slates')
        .listSync()
        .whereType<File>()
        .where((file) => file.path.endsWith('.json'))
        .map(
          (file) => jsonDecode(file.readAsStringSync()) as Map<String, dynamic>,
        )
        .where((vector) => vector['expected']?['header'] != null);
    final seen = <String>{};
    for (final vector in vectors) {
      final expected = vector['expected'] as Map<String, dynamic>;
      final header = expected['header']['version'] as int;
      final shape = expected['shape'] as String;
      // The file method reads by the header's version; a V2 shape under header 3 is not a
      // slate any wallet writes to a file.
      if (shape == 'V2' && header == 3) continue;
      final name = vector['name'] as String;
      final text = expected['json'] as String;
      final json = jsonDecode(text) as Map<String, dynamic>;
      final info = await inspectSlate(json: text, chain: Chain.floonet);
      final stage = vector['inputs']['stage'] as String;
      expect(info.stage.name, stage.toLowerCase(), reason: name);
      expect(info.version, header, reason: name);
      expect(info.slateId, expected['slate_id'], reason: name);
      expect(info.amount, BigInt.parse('${json['amount']}'), reason: name);
      expect(info.fee, BigInt.parse('${json['fee']}'), reason: name);
      final ttl = header == 3 ? json['ttl_cutoff_height'] : null;
      expect(
        info.ttlCutoffHeight,
        ttl == null ? isNull : BigInt.parse('$ttl'),
        reason: name,
      );
      final messages = [
        for (final participant in json['participant_data'] as List)
          if (participant['message'] != null) participant['message'] as String,
      ];
      expect(
        info.messages.map((message) => message.text),
        unorderedEquals(messages),
        reason: name,
      );
      seen.add('${shape.toLowerCase()}-$stage');
    }
    expect(seen, {
      for (final stage in ['S1', 'S2', 'S3', 'I1', 'I2', 'I3']) ...[
        'v2-$stage',
        'v3-$stage',
      ],
    });
  });

  test('inspect_slate names the sender and receiver messages', () async {
    final vector = jsonDecode(
      File('../../testdata/vectors/slates/send_file_messages_s2_file.json')
          .readAsStringSync(),
    ) as Map<String, dynamic>;
    final options = vector['inputs']['options'] as Map<String, dynamic>;
    final info = await inspectSlate(
      json: vector['expected']['json'] as String,
      chain: Chain.mainnet,
    );
    expect(info.stage, SlateStage.s2);
    expect(
      {for (final message in info.messages) message.role: message.text},
      {
        SlateRole.sender: options['initiator_message'],
        SlateRole.receiver: options['responder_message'],
      },
    );
  });

  test('inspect_slate accepts what the file method accepts', () async {
    final vectors = Directory('../../testdata/vectors/slates')
        .listSync()
        .whereType<File>()
        .where((file) => file.path.contains('/malformed_'))
        .map(
          (file) => jsonDecode(file.readAsStringSync()) as Map<String, dynamic>,
        );
    // Refused although upstream's parser takes them, as `crates/lepic-transport/tests/vectors.rs`
    // lists: LEPIC's decode checks more than upstream's parse step.
    const stricter = {
      'malformed_duplicate_participant_id',
      'malformed_num_participants_zero',
      'malformed_offset_too_short',
    };
    var refused = 0;
    for (final vector in vectors) {
      final name = vector['name'] as String;
      final text = vector['inputs']['json'] as String;
      final accepted =
          vector['expected']['file_method']['accepted'] as bool &&
          !stricter.contains(name);
      final inspected = inspectSlate(json: text, chain: Chain.floonet);
      if (accepted) {
        await expectLater(inspected, completes, reason: name);
      } else {
        refused++;
        await expectLater(
          inspected,
          throwsWalletError(WalletErrorKind.invalidSlate),
          reason: name,
        );
      }
    }
    expect(refused, greaterThan(10));
    await expectLater(
      inspectSlate(json: ' ' * (8 * 1024 * 1024 + 1), chain: Chain.floonet),
      throwsWalletError(WalletErrorKind.invalidSlate),
    );
  });

  test('a pasted send carries its message to both parties', () async {
    final (alice, bob, _) = await fundedPair('message-text');
    final s1 = await alice.createSendSlate(
      amount: BigInt.from(epic),
      minimumConfirmations: BigInt.one,
      message: 'for the pizza',
    );
    const sender = SlateMessage(role: SlateRole.sender, text: 'for the pizza');
    expect((await alice.transaction(txId: s1.txId)).messages, [sender]);

    final s2 = await bob.receiveSlate(slateJson: s1.json);
    expect((await bob.transaction(txId: s2.txId)).messages, [sender]);
    expect((await bob.transactions()).single.messages, [sender]);

    await alice.finalizeAndPost(slateJson: s2.json);
    expect((await alice.transaction(txId: s1.txId)).messages, [sender]);
  });

  test('a long message is cut on a character boundary and still verifies', () async {
    final (alice, bob, _) = await fundedPair('message-file');
    // Three bytes each, so the 256-byte limit falls inside a character.
    final long = '€' * 100;
    final file = '${root.path}/message.slate';
    final sent = await alice.sendFile(
      amount: BigInt.from(epic),
      minimumConfirmations: BigInt.one,
      path: file,
      message: long,
    );
    final cut = SlateMessage(role: SlateRole.sender, text: '€' * 85);
    expect((await alice.transaction(txId: sent.txId)).messages, [cut]);

    // A receive refuses a message whose signature does not verify.
    final received = await bob.receiveFile(path: file);
    expect((await bob.transaction(txId: received.txId)).messages, [cut]);
  });

  test('a send without a message shows none', () async {
    final (alice, _, _) = await fundedPair('message-none');
    final s1 = await alice.createSendSlate(
      amount: BigInt.from(epic),
      minimumConfirmations: BigInt.one,
    );
    expect((await alice.transaction(txId: s1.txId)).messages, isEmpty);
  });

  test('a restored wallet must finish its scan before it receives', () async {
    final (alice, _, _) = await fundedPair('restore-scan');
    final restored = await EpicWallet.create(
      runtime: runtime,
      config: configFor(walletDir('restore-scan-carol')),
      store: lepicSecretStore(MemoryStore()),
      mnemonic:
          'legal winner thank year wave sausage worth useful legal winner thank year '
          'wave sausage worth useful legal winner thank year wave sausage worth title',
      password: password,
    );
    final s1 = await alice.createSendSlate(
      amount: BigInt.from(epic),
      minimumConfirmations: BigInt.one,
    );
    await expectLater(
      restored.receiveSlate(slateJson: s1.json),
      throwsWalletError(WalletErrorKind.restoreScanRequired),
    );
    await scanToEnd(restored);
    final s2 = await restored.receiveSlate(slateJson: s1.json);
    expect(s2.slateId, s1.slateId);
  });

  test('a send the node took cannot be cancelled', () async {
    final (alice, bob, _) = await fundedPair('on-chain');
    final s1 = await alice.createSendSlate(
      amount: BigInt.from(epic),
      minimumConfirmations: BigInt.one,
    );
    final s2 = await bob.receiveSlate(slateJson: s1.json);
    chain.loseNextPostReply();
    await expectLater(
      alice.finalizeAndPost(slateJson: s2.json),
      throwsWalletError(WalletErrorKind.notPosted),
    );
    expect((await alice.transaction(txId: s1.txId)).status, TxStatus.finalized);
    chain.minePushed();
    await expectLater(
      alice.cancelTransaction(txId: s1.txId),
      throwsWalletError(WalletErrorKind.onChain),
    );
    expect((await alice.transaction(txId: s1.txId)).status, TxStatus.finalized);
  });

  test('every error kind has its documented code', () async {
    expect(WalletErrorKind.values.toSet(), errorCodes.keys.toSet());
    for (final MapEntry(key: kind, value: code) in errorCodes.entries) {
      expect(await kind.code(), code, reason: kind.name);
    }
  });

  test('a pin shorter than six characters is refused', () async {
    for (final pin in ['', '1', '123', '12345']) {
      final store = MemoryStore();
      await expectLater(
        EpicWallet.createWithPin(
          runtime: runtime,
          config: configFor(walletDir('short-pin-${pin.length}')),
          store: lepicSecretStore(store),
          pin: pin,
        ),
        throwsWalletError(WalletErrorKind.invalidArgument),
        reason: pin,
      );
      expect(store.values, isEmpty, reason: pin);
    }
  });

  test('a locked wallet refuses calls until it is opened again', () async {
    final dir = walletDir('locked');
    final store = MemoryStore();
    final wallet = await EpicWallet.create(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      password: password,
    );
    await wallet.summary(refresh: true);
    wallet.lock();
    await expectLater(
      wallet.summary(refresh: false),
      throwsWalletError(WalletErrorKind.locked),
    );
    await expectLater(
      wallet.mnemonic(password: password),
      throwsWalletError(WalletErrorKind.locked),
    );
    wallet.dispose();
    final reopened = await EpicWallet.open(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      password: password,
    );
    expect((await reopened.summary(refresh: true)).total, BigInt.zero);
  });

  test('pin unlock keeps the wallet password inside rust', () async {
    final dir = walletDir('pin');
    final store = MemoryStore();
    final created = await EpicWallet.createWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '123456',
    );
    final sealed = created.sealedPassword;
    expect(store.values.keys.toSet(), {'lepic.vault', 'lepic.pin-key'});
    expect(store.values.values, isNot(contains(sealed)));
    final phrase = await created.wallet.mnemonicWithPin(
      pin: '123456',
      sealedPassword: sealed,
    );
    expect(validateMnemonic(phrase: phrase), isTrue);
    expect(sealed, isNot(contains('123456')));
    await expectLater(
      created.wallet.mnemonicWithPin(pin: '000000', sealedPassword: sealed),
      throwsWalletError(WalletErrorKind.wrongPassword),
    );
    expect(store.values['lepic.pin-failures'], '1');
    created.wallet.dispose();

    await expectLater(
      EpicWallet.openWithPin(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        pin: '000000',
        sealedPassword: sealed,
      ),
      throwsWalletError(WalletErrorKind.wrongPassword),
    );
    expect(store.values['lepic.pin-failures'], '2');
    await expectLater(
      EpicWallet.openWithPin(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        pin: '123456',
        sealedPassword: 'damaged',
      ),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
    final reopened = await EpicWallet.openWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '123456',
      sealedPassword: sealed,
    );
    expect(store.values.keys.toSet(), {'lepic.vault', 'lepic.pin-key'});
    expect(
      await reopened.mnemonicWithPin(pin: '123456', sealedPassword: sealed),
      phrase,
    );
  });
  test('imports an epic-wallet wallet.seed with its password', () async {
    final vector = walletSeedVector();
    final store = MemoryStore();
    await expectLater(
      EpicWallet.importWalletSeed(
        runtime: runtime,
        config: configFor(walletDir('import-wrong')),
        store: lepicSecretStore(store),
        seedFile: vector.file,
        seedPassword: vector.wrongPassword,
        password: password,
      ),
      throwsWalletError(WalletErrorKind.wrongPassword),
    );
    expect(store.values, isEmpty);
    await expectLater(
      EpicWallet.importWalletSeed(
        runtime: runtime,
        config: configFor(walletDir('import-not-a-seed')),
        store: lepicSecretStore(store),
        seedFile: '{"encrypted_seed": "00"}',
        seedPassword: vector.password,
        password: password,
      ),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );

    final imported = await EpicWallet.importWalletSeed(
      runtime: runtime,
      config: configFor(walletDir('import')),
      store: lepicSecretStore(store),
      seedFile: vector.file,
      seedPassword: vector.password,
      password: password,
    );
    expect(await imported.mnemonic(password: password), vector.phrase);
    expect(store.values.keys, ['lepic.vault']);

    final pinStore = MemoryStore();
    await expectLater(
      EpicWallet.importWalletSeedWithPin(
        runtime: runtime,
        config: configFor(walletDir('import-pin-wrong')),
        store: lepicSecretStore(pinStore),
        seedFile: vector.file,
        seedPassword: vector.wrongPassword,
        pin: '123456',
      ),
      throwsWalletError(WalletErrorKind.wrongPassword),
    );
    expect(
      await walletExists(runtime: runtime, store: lepicSecretStore(pinStore)),
      isFalse,
    );
    final pinWallet = await EpicWallet.importWalletSeedWithPin(
      runtime: runtime,
      config: configFor(walletDir('import-pin')),
      store: lepicSecretStore(pinStore),
      seedFile: vector.file,
      seedPassword: vector.password,
      pin: '123456',
    );
    expect(
      await pinWallet.wallet.mnemonicWithPin(
        pin: '123456',
        sealedPassword: pinWallet.sealedPassword,
      ),
      vector.phrase,
    );
  });

  test(
    'an imported wallet.seed signs nothing before its restore scan',
    () async {
      final alice = await EpicWallet.create(
        runtime: runtime,
        config: configFor(walletDir('import-scan-sender')),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      chain.fund(
        mnemonic: await alice.mnemonic(password: password),
        chain: Chain.floonet,
        amount: BigInt.from(5 * epic),
        child: 0,
      );
      chain.setHeight(height: BigInt.from(20));
      await scanToEnd(alice);
      final s1 = await alice.createSendSlate(
        amount: BigInt.from(epic),
        minimumConfirmations: BigInt.one,
      );

      final vector = walletSeedVector();
      final imported = await EpicWallet.importWalletSeed(
        runtime: runtime,
        config: configFor(walletDir('import-scan')),
        store: lepicSecretStore(MemoryStore()),
        seedFile: vector.file,
        seedPassword: vector.password,
        password: password,
      );
      await expectLater(
        imported.receiveSlate(slateJson: s1.json),
        throwsWalletError(WalletErrorKind.restoreScanRequired),
      );
      await scanToEnd(imported);
      // The refused attempt stored nothing, so the same slate is still new to the wallet.
      final s2 = await imported.receiveSlate(slateJson: s1.json);
      expect(s2.slateId, s1.slateId);
      final posted = await alice.finalizeAndPost(slateJson: s2.json);
      expect(posted.txId, s1.txId);
    },
  );

  test('a pin change keeps both pins working until it is confirmed', () async {
    final dir = walletDir('change-pin');
    final store = MemoryStore();
    final created = await EpicWallet.createWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '123456',
    );
    final oldSealed = created.sealedPassword;
    final phrase = await created.wallet.mnemonicWithPin(
      pin: '123456',
      sealedPassword: oldSealed,
    );
    await expectLater(
      created.wallet.changePin(
        sealedPassword: oldSealed,
        oldPin: '123456',
        newPin: '987',
      ),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
    expect(store.values['lepic.pin-failures'], isNull);
    final newSealed = await created.wallet.changePin(
      sealedPassword: oldSealed,
      oldPin: '123456',
      newPin: '987654',
    );
    expect(newSealed, isNot(oldSealed));
    expect(newSealed, isNot(contains('987654')));
    created.wallet.dispose();

    Future<EpicWallet> open(String pin, String sealed) =>
        EpicWallet.openWithPin(
          runtime: runtime,
          config: configFor(dir),
          store: lepicSecretStore(store),
          pin: pin,
          sealedPassword: sealed,
        );

    // Until the change is confirmed each pin opens its own sealed text, and only that one.
    for (final (pin, sealed) in [('123456', newSealed), ('987654', oldSealed)]) {
      await expectLater(
        open(pin, sealed),
        throwsWalletError(WalletErrorKind.wrongPassword),
        reason: pin,
      );
    }
    final withOld = await open('123456', oldSealed);
    expect(
      await withOld.mnemonicWithPin(pin: '123456', sealedPassword: oldSealed),
      phrase,
    );
    withOld.dispose();
    final withNew = await open('987654', newSealed);
    expect(
      await withNew.mnemonicWithPin(pin: '987654', sealedPassword: newSealed),
      phrase,
    );
    expect(store.values['lepic.pin-failures'], isNull);

    await expectLater(
      withNew.confirmPinChange(sealedPassword: oldSealed),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
    await withNew.confirmPinChange(sealedPassword: newSealed);
    expect(store.values.keys.toSet(), {'lepic.vault', 'lepic.pin-key'});
    withNew.dispose();
    // Two attempts, so the right pin below does not wait out a third failure.
    for (final (pin, sealed) in [('123456', oldSealed), ('987654', oldSealed)]) {
      await expectLater(
        open(pin, sealed),
        throwsWalletError(WalletErrorKind.wrongPassword),
        reason: pin,
      );
    }
    final reopened = await open('987654', newSealed);
    expect(
      await reopened.mnemonicWithPin(pin: '987654', sealedPassword: newSealed),
      phrase,
    );
    expect(store.values['lepic.pin-failures'], isNull);
  });

  test('an unconfirmed pin change survives a reopened runtime', () async {
    final dir = walletDir('change-pin-restart');
    final store = MemoryStore();
    final created = await EpicWallet.createWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '123456',
    );
    final oldSealed = created.sealedPassword;
    final newSealed = await created.wallet.changePin(
      sealedPassword: oldSealed,
      oldPin: '123456',
      newPin: '987654',
    );
    created.wallet.dispose();
    // The app stopped before it stored the new text or confirmed the change.
    runtime.dispose();

    runtime = chain.runtime(logLevel: LogLevel.info);
    for (final (pin, sealed) in [('123456', oldSealed), ('987654', newSealed)]) {
      final opened = await EpicWallet.openWithPin(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        pin: pin,
        sealedPassword: sealed,
      );
      opened.dispose();
    }
  });

  test(
    'pin failures during a pending change count once each and wait',
    () async {
      final dir = walletDir('change-pin-pending-backoff');
      final store = MemoryStore();
      final created = await EpicWallet.createWithPin(
        runtime: runtime,
        config: configFor(dir),
        store: lepicSecretStore(store),
        pin: '123456',
      );
      final oldSealed = created.sealedPassword;
      final newSealed = await created.wallet.changePin(
        sealedPassword: oldSealed,
        oldPin: '123456',
        newPin: '987654',
      );
      created.wallet.dispose();

      Future<EpicWallet> open(String pin, String sealed) =>
          EpicWallet.openWithPin(
            runtime: runtime,
            config: configFor(dir),
            store: lepicSecretStore(store),
            pin: pin,
            sealedPassword: sealed,
          );

      // One counter for both pins: a wrong pin is one failure, whichever text it is tried on,
      // and a right pin for either text clears the count.
      final wrong = [('000000', oldSealed), ('000000', newSealed)];
      for (final (index, (pin, sealed)) in wrong.indexed) {
        await expectLater(
          open(pin, sealed),
          throwsWalletError(WalletErrorKind.wrongPassword),
        );
        expect(store.values['lepic.pin-failures'], '${index + 1}');
      }
      (await open('123456', oldSealed)).dispose();
      expect(store.values['lepic.pin-failures'], isNull);

      for (var failures = 1; failures <= 3; failures++) {
        final sealed = failures.isOdd ? oldSealed : newSealed;
        final started = DateTime.now();
        await expectLater(
          open('000000', sealed),
          throwsWalletError(WalletErrorKind.wrongPassword),
        );
        expect(DateTime.now().difference(started).inSeconds, lessThan(5));
        expect(store.values['lepic.pin-failures'], '$failures');
      }
      // After three failures the next attempt, even with the right new pin, first waits 30 s.
      var finished = false;
      unawaited(
        open('987654', newSealed)
            .then((wallet) => wallet.dispose(), onError: (_) {})
            .whenComplete(() => finished = true),
      );
      await Future<void>.delayed(const Duration(seconds: 3));
      expect(finished, isFalse);
      expect(store.values['lepic.pin-failures'], '4');
    },
  );

  test('a change from the stored new text keeps that text opening', () async {
    final dir = walletDir('change-pin-twice');
    final store = MemoryStore();
    final created = await EpicWallet.createWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '123456',
    );
    final stored = await created.wallet.changePin(
      sealedPassword: created.sealedPassword,
      oldPin: '123456',
      newPin: '567890',
    );
    // The app stored `stored` in place of the first text, changed again, and stopped
    // before it stored the third text.
    await created.wallet.changePin(
      sealedPassword: stored,
      oldPin: '567890',
      newPin: '987654',
    );
    created.wallet.dispose();
    final opened = await EpicWallet.openWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '567890',
      sealedPassword: stored,
    );
    opened.dispose();
  });

  test('a confirmation for text the app never stored is refused', () async {
    final dir = walletDir('change-pin-confirm-wrong');
    final store = MemoryStore();
    final created = await EpicWallet.createWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '123456',
    );
    final held = created.sealedPassword;
    await created.wallet.changePin(
      sealedPassword: held,
      oldPin: '123456',
      newPin: '987654',
    );
    // The app stopped before it stored the new text, and confirms on its next start.
    await expectLater(
      created.wallet.confirmPinChange(sealedPassword: held),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
    created.wallet.dispose();
    final opened = await EpicWallet.openWithPin(
      runtime: runtime,
      config: configFor(dir),
      store: lepicSecretStore(store),
      pin: '123456',
      sealedPassword: held,
    );
    opened.dispose();
  });

  test('a wrong old pin is counted and delayed like any pin attempt', () async {
    final store = MemoryStore();
    final created = await EpicWallet.createWithPin(
      runtime: runtime,
      config: configFor(walletDir('change-pin-backoff')),
      store: lepicSecretStore(store),
      pin: '123456',
    );
    final sealed = created.sealedPassword;
    for (var failures = 1; failures <= 3; failures++) {
      final started = DateTime.now();
      await expectLater(
        created.wallet.changePin(
          sealedPassword: sealed,
          oldPin: '000000',
          newPin: '987654',
        ),
        throwsWalletError(WalletErrorKind.wrongPassword),
      );
      expect(DateTime.now().difference(started).inSeconds, lessThan(5));
      expect(store.values['lepic.pin-failures'], '$failures');
    }
    // A new pin that is too short is refused before the old pin is tried: no attempt is
    // counted and nothing waits, although a counted attempt would now wait 30 s.
    final refused = DateTime.now();
    await expectLater(
      created.wallet.changePin(
        sealedPassword: sealed,
        oldPin: '000000',
        newPin: '987',
      ),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
    expect(DateTime.now().difference(refused).inSeconds, lessThan(5));
    expect(store.values['lepic.pin-failures'], '3');
    // After three failures the next attempt, even with the right pin, first waits 30 s.
    var finished = false;
    unawaited(
      created.wallet
          .changePin(sealedPassword: sealed, oldPin: '123456', newPin: '987654')
          .then((_) {}, onError: (_) {})
          .whenComplete(() => finished = true),
    );
    await Future<void>.delayed(const Duration(seconds: 3));
    expect(finished, isFalse);
    expect(store.values['lepic.pin-failures'], '4');
  });

  test(
    'the support bundle holds log lines but no address, amount or key',
    () async {
      final debugRuntime = chain.runtime(logLevel: LogLevel.debug);
      final live = <LogEntry>[];
      final subscription = debugRuntime.logs().listen(live.add);
      await debugRuntime.openLogRing(
        dir: '${root.path}/logs',
        maxBytes: BigInt.from(256 * 1024),
      );

      final vector = walletSeedVector();
      final sender = await EpicWallet.importWalletSeedWithPin(
        runtime: debugRuntime,
        config: WalletConfig(
          dataDir: walletDir('bundle-sender').path,
          chain: Chain.floonet,
          nodeUrl: 'http://127.0.0.1:1',
          epicboxDomain: 'epicbox.example',
          epicboxPort: 443,
        ),
        store: lepicSecretStore(MemoryStore()),
        seedFile: vector.file,
        seedPassword: vector.password,
        pin: '123456',
      );
      final address = await sender.wallet.epicboxAddress();
      chain.fund(
        mnemonic: vector.phrase,
        chain: Chain.floonet,
        amount: BigInt.from(7 * epic),
        child: 0,
      );
      chain.setHeight(height: BigInt.from(20));
      await scanToEnd(sender.wallet);
      final receiver = await EpicWallet.create(
        runtime: debugRuntime,
        config: configFor(walletDir('bundle-receiver')),
        store: lepicSecretStore(MemoryStore()),
        mnemonic: bobPhrase,
        password: password,
      );
      await scanToEnd(receiver);
      final s1 = await sender.wallet.createSendSlate(
        amount: BigInt.from(3 * epic),
        minimumConfirmations: BigInt.one,
      );
      final s2 = await receiver.receiveSlate(slateJson: s1.json);
      await sender.wallet.finalizeAndPost(slateJson: s2.json);
      final sent = (await sender.wallet.summary(refresh: true)).total;

      final bundle = await debugRuntime.exportSupportBundle();
      debugRuntime.stopLogs();
      await subscription.cancel();

      expect(bundle, startsWith('lepic support bundle\n'));
      expect(bundle, contains('wallet imported'));
      expect(bundle, contains('slate finalized'));
      expect(bundle, contains('redacted: values of fields other than'));
      expect(live, isNotEmpty);
      final key = address.split('@').first;
      for (final secret in [
        key,
        vector.phrase,
        vector.password,
        password,
        bobPhrase,
        '${3 * epic}',
        '${7 * epic}',
        '$sent',
        s1.json,
      ]) {
        expect(bundle, isNot(contains(secret)));
      }
    },
  );

  /// A send Bob answered and the node took, posted at height 20, and the height from which a
  /// refresh that misses its kernel makes it releasable.
  Future<(EpicWallet, int, BigInt)> postedSend(String name) async {
    final (alice, bob, _) = await fundedPair(name);
    final s1 = await alice.createSendSlate(
      amount: BigInt.from(epic),
      minimumConfirmations: BigInt.one,
    );
    final s2 = await bob.receiveSlate(slateJson: s1.json);
    await alice.finalizeAndPost(slateJson: s2.json);
    final posted = await alice.transaction(txId: s1.txId);
    expect(posted.status, TxStatus.posted);
    return (alice, s1.txId, BigInt.from(20 + 1440));
  }

  /// The chain reaches `height` without the send, and two refreshes confirm that tip: the
  /// first holds a tip that far ahead as pending.
  Future<void> chainPassesWithoutIt(EpicWallet wallet, BigInt height) async {
    chain.setHeight(height: height);
    await wallet.summary(refresh: true);
    await wallet.summary(refresh: true);
  }

  test('a send the network never took is released', () async {
    final (alice, txId, from) = await postedSend('release');
    final waiting = await alice.transaction(txId: txId);
    expect(waiting.releasableFrom, from);
    expect(waiting.releasable, isFalse);
    await expectLater(
      alice.releaseTransaction(txId: txId),
      throwsWalletError(WalletErrorKind.notReleasable),
    );

    await chainPassesWithoutIt(alice, from);
    expect((await alice.transaction(txId: txId)).releasable, isTrue);
    expect((await alice.transactions()).first.releasable, isTrue);

    chain.setNodeUnreachable(unreachable: true);
    await expectLater(
      alice.releaseTransaction(txId: txId),
      throwsWalletError(WalletErrorKind.nodeUnreachable),
    );
    chain.setNodeUnreachable(unreachable: false);
    expect((await alice.transaction(txId: txId)).status, TxStatus.posted);

    await alice.releaseTransaction(txId: txId);
    final released = await alice.transaction(txId: txId);
    expect(released.status, TxStatus.cancelled);
    expect(released.releasable, isFalse);
    final balance = await alice.summary(refresh: false);
    expect(balance.locked, BigInt.zero);
    expect(balance.spendable, BigInt.from(10 * epic));
  });

  test('a send whose kernel reached the chain is not released', () async {
    final (alice, txId, from) = await postedSend('release-on-chain');
    await chainPassesWithoutIt(alice, from);
    expect((await alice.transaction(txId: txId)).releasable, isTrue);
    chain.minePushed();

    await expectLater(
      alice.releaseTransaction(txId: txId),
      throwsWalletError(WalletErrorKind.onChain),
    );
    expect((await alice.transaction(txId: txId)).status, TxStatus.posted);
  });

  test('a send the node pool holds is not released', () async {
    final (alice, txId, from) = await postedSend('release-in-pool');
    await chainPassesWithoutIt(alice, from);
    expect((await alice.transaction(txId: txId)).releasable, isTrue);
    chain.poolPushed();

    await expectLater(
      alice.releaseTransaction(txId: txId),
      throwsWalletError(WalletErrorKind.inPool),
    );
    expect((await alice.transaction(txId: txId)).status, TxStatus.posted);
  });
}
