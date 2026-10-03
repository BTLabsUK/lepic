// Runs the binding against the local interop chain: a reference node, an Epicbox relay and
// the epic-wallet funder of interop/acceptance. Skipped unless LEPIC_INTEROP=1. With the stack
// running (interop/acceptance/run.sh --stack-only, see README.md):
//   cargo build -p lepic-ffi
//   LEPIC_INTEROP=1 flutter test test/interop_test.dart
// LEPIC_FFI_LIB overrides the library path.

import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lepic/lepic.dart';

const password = 'interop test password';
const epic = 100000000;

final bool enabled = Platform.environment['LEPIC_INTEROP'] == '1';

final String chainScript =
    '${Directory.current.path}/../../interop/acceptance/chain.sh';

String libraryPath() =>
    Platform.environment['LEPIC_FFI_LIB'] ??
    '${Directory.current.path}/../../target/debug/liblepic_ffi.so';

class MemoryStore implements SecretStore {
  final Map<String, String> values = {};

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<void> delete(String key) async => values.remove(key);
}

/// Runs `chain.sh` and returns its stdout; fails the test when it exits non-zero.
Future<String> chain(List<String> args) async {
  final result = await Process.run(chainScript, args);
  if (result.exitCode != 0) {
    fail(
      'chain.sh ${args.join(' ')} exited ${result.exitCode}: ${result.stderr}',
    );
  }
  return (result.stdout as String).trim();
}

/// Calls [check] every [every] until it returns true, failing after [limit].
Future<void> waitFor(
  String what,
  Future<bool> Function() check, {
  Duration limit = const Duration(minutes: 5),
  Duration every = const Duration(seconds: 3),
}) async {
  final deadline = DateTime.now().add(limit);
  while (!await check()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('timed out after ${limit.inSeconds}s waiting for $what');
    }
    await Future<void>.delayed(every);
  }
}

/// A refreshed summary, or null when the refresh hit a block mined between the node calls it
/// makes (claim V-09, `## Found`); polling just asks again.
Future<WalletSummary?> refreshed(EpicWallet wallet) async {
  try {
    return await wallet.summary(refresh: true);
  } on WalletError catch (error) {
    if (error.kind != WalletErrorKind.other) rethrow;
    printOnFailure('refresh retried: ${error.message}');
    return null;
  }
}

Future<void> fundOverEpicboxAndSendBackByFile() async {
  final stack = Map.fromEntries(
    (await chain(['env'])).split('\n').map((line) {
      final at = line.indexOf('=');
      return MapEntry(line.substring(0, at), line.substring(at + 1));
    }),
  );
  final exchange = stack['LEPIC_INTEROP_EXCHANGE_DIR']!;
  final dir = Directory.systemTemp.createTempSync('lepic-interop-test-');
  addTearDown(() => dir.deleteSync(recursive: true));

  // The local chain is usernet, where epic-wallet derives mainnet Epicbox addresses.
  final runtime = LepicRuntime(logLevel: LogLevel.info);
  final wallet = await EpicWallet.create(
    runtime: runtime,
    config: WalletConfig(
      dataDir: dir.path,
      chain: Chain.mainnet,
      nodeUrl: stack['LEPIC_INTEROP_NODE_URL']!,
      nodeApiSecret: File(stack['LEPIC_INTEROP_NODE_API_SECRET_FILE']!)
          .readAsStringSync()
          .trim(),
      epicboxDomain: stack['LEPIC_INTEROP_EPICBOX_DOMAIN']!,
      epicboxPort: int.parse(stack['LEPIC_INTEROP_EPICBOX_PORT']!),
    ),
    store: lepicSecretStore(MemoryStore()),
    password: password,
  );
  addTearDown(wallet.dispose);
  expect((await wallet.summary(refresh: true)).total, BigInt.zero);

  // The funder sends 10 EPIC to the wallet's address; a drain answers the S1, and the
  // funder's listener finalizes and posts.
  final address = await wallet.epicboxAddress();
  expect(
    validateEpicboxAddress(address: address, chain: Chain.mainnet),
    isTrue,
  );
  await chain(['fund', address, '10']);
  var received = 0;
  await waitFor('the funder S1 on the relay', () async {
    received += (await wallet.drainEpicbox()).received;
    return received > 0;
  }, limit: const Duration(minutes: 2));
  expect(received, 1);

  final funded = BigInt.from(10 * epic);
  await waitFor('10 EPIC spendable', () async {
    return (await refreshed(wallet))?.spendable == funded;
  });

  // 2 EPIC back to the funder through a slate file in the exchange directory.
  final file =
      '$exchange/lepic-flutter-${DateTime.now().microsecondsSinceEpoch}.slate';
  final sent = await wallet.sendFile(
    amount: BigInt.from(2 * epic),
    minimumConfirmations: BigInt.one,
    path: file,
  );
  await chain(['receive', file]);
  final posted = await wallet.finalizeFile(path: '$file.response');
  expect(posted.txId, sent.txId);
  expect(posted.slateId, sent.slateId);

  // The change becomes spendable only once the node mined the transaction.
  final change = funded - BigInt.from(2 * epic) - sent.fee;
  await waitFor('the change spendable', () async {
    final summary = await refreshed(wallet);
    return summary?.spendable == change && summary?.total == change;
  });
}

void main() {
  test(
    'a wallet funded by epic-wallet over epicbox sends back by file',
    () async {
      await RustLib.init(externalLibrary: ExternalLibrary.open(libraryPath()));
      try {
        await fundOverEpicboxAndSendBackByFile();
      } on WalletError catch (error) {
        fail('${error.kind} (${error.code}): ${error.message}');
      }
    },
    skip: enabled ? false : 'set LEPIC_INTEROP=1 with interop/acceptance/run.sh --stack-only running',
    timeout: const Timeout(Duration(minutes: 15)),
  );
}
