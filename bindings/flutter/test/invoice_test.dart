// Invoices over Epicbox between two wallets on the mock chain and the mock relay. Runs as
// wallet_test.dart does; from the repository root:
//   cargo xtask mobile --host-test

import 'dart:async';
import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lepic/lepic.dart';

import 'wallet_test.dart'
    show
        MemoryStore,
        bobPhrase,
        epic,
        libraryPath,
        password,
        scanToEnd,
        throwsWalletError;

const day = Duration(hours: 24);

/// Waits until [events] holds an event that [matches], and returns it.
Future<WalletEvent> eventWhere(
  List<WalletEvent> events,
  bool Function(WalletEvent) matches,
) async {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  while (DateTime.now().isBefore(deadline)) {
    for (final event in events) {
      if (matches(event)) return event;
    }
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  throw TimeoutException('no matching event in $events');
}

typedef Parties = ({
  EpicWallet payer,
  EpicWallet issuer,
  String issuerAddress,
  String invoiceAddress,
  List<WalletEvent> payerEvents,
  List<WalletEvent> issuerEvents,
});

void main() {
  late Directory root;
  late MockChain chain;
  late MockRelay relay;
  late LepicRuntime runtime;
  final subscriptions = <StreamSubscription<WalletEvent>>[];

  setUpAll(() async {
    await RustLib.init(externalLibrary: ExternalLibrary.open(libraryPath()));
  });

  setUp(() {
    root = Directory.systemTemp.createTempSync('lepic-invoice-test-');
    chain = MockChain(height: BigInt.one);
    relay = MockRelay(chain: Chain.floonet);
    runtime = chain.runtimeWithRelay(logLevel: LogLevel.info, relay: relay);
  });

  tearDown(() async {
    // A wallet's event stream ends only when the wallet is dropped, so cancelling waits for
    // that; the cancels finish once the test's wallets are gone.
    for (final subscription in subscriptions) {
      unawaited(subscription.cancel());
    }
    subscriptions.clear();
    root.deleteSync(recursive: true);
  });

  WalletConfig relayConfig(String name, {String domain = 'epicbox.example'}) =>
      WalletConfig(
        dataDir: (Directory('${root.path}/$name')..createSync()).path,
        chain: Chain.floonet,
        nodeUrl: 'http://127.0.0.1:1',
        epicboxDomain: domain,
        epicboxPort: 443,
      );

  List<WalletEvent> record(EpicWallet wallet) {
    final events = <WalletEvent>[];
    subscriptions.add(wallet.events().listen(events.add));
    return events;
  }

  /// A payer with 10 EPIC that allows invoices from the issuer, and the issuer.
  Future<Parties> parties(String name) async {
    final payer = await EpicWallet.create(
      runtime: runtime,
      config: relayConfig('$name-payer'),
      store: lepicSecretStore(MemoryStore()),
      password: password,
    );
    chain.fund(
      mnemonic: await payer.mnemonic(password: password),
      chain: Chain.floonet,
      amount: BigInt.from(10 * epic),
      child: 0,
    );
    chain.setHeight(height: BigInt.from(20));
    await scanToEnd(payer);
    final issuer = await EpicWallet.create(
      runtime: runtime,
      config: relayConfig('$name-issuer'),
      store: lepicSecretStore(MemoryStore()),
      mnemonic: bobPhrase,
      password: password,
    );
    await scanToEnd(issuer);
    final issuerAddress = await issuer.epicboxAddress();
    await payer.allowInvoiceSender(address: issuerAddress, label: 'shop');
    return (
      payer: payer,
      issuer: issuer,
      issuerAddress: issuerAddress,
      invoiceAddress: await payer.invoiceAddress(),
      payerEvents: record(payer),
      issuerEvents: record(issuer),
    );
  }

  /// The issuer invoices 3 EPIC and the payer's drain parks it.
  Future<(IssuedInvoice, IncomingInvoice)> parked(Parties p) async {
    final issued = await p.issuer.issueInvoiceEpicbox(
      amount: BigInt.from(3 * epic),
      address: p.invoiceAddress,
      message: 'order 42',
    );
    expect(relay.pending(address: p.invoiceAddress), 1);
    final report = await p.payer.drainInvoices();
    expect(report.parked, 1);
    expect(relay.pending(address: p.invoiceAddress), 0);
    final waiting = await p.payer.pendingInvoices();
    expect(waiting, hasLength(1));
    return (issued, waiting.single);
  }

  test(
    'the invoice address starts at index 1, rotates and is set back',
    () async {
      final wallet = await EpicWallet.create(
        runtime: runtime,
        config: relayConfig('address'),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      final payments = await wallet.epicboxAddress();
      final first = await wallet.invoiceAddress();
      expect(await wallet.invoiceAddressIndex(), 1);
      expect(first, isNot(payments));
      expect(first, endsWith('@epicbox.example'));
      expect(
        validateEpicboxAddress(address: first, chain: Chain.floonet),
        isTrue,
      );

      final second = await wallet.rotateInvoiceAddress();
      expect(second, isNot(first));
      expect(await wallet.invoiceAddressIndex(), 2);
      expect(await wallet.invoiceAddress(), second);

      await wallet.setInvoiceAddressIndex(index: 1);
      expect(await wallet.invoiceAddress(), first);
      await expectLater(
        wallet.setInvoiceAddressIndex(index: 0),
        throwsWalletError(WalletErrorKind.invalidArgument),
      );
      expect(await wallet.invoiceAddressIndex(), 1);

      final offline = await EpicWallet.create(
        runtime: runtime,
        config: relayConfig('address-no-relay', domain: ''),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      await expectLater(
        offline.invoiceAddress(),
        throwsWalletError(WalletErrorKind.unsupported),
      );
      await expectLater(
        offline.drainInvoices(),
        throwsWalletError(WalletErrorKind.unsupported),
      );
    },
  );

  test(
    'the allowlist keeps full addresses and refuses anything else',
    () async {
      final wallet = await EpicWallet.create(
        runtime: runtime,
        config: relayConfig('allowlist'),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      final shop = await EpicWallet.create(
        runtime: runtime,
        config: relayConfig('allowlist-shop'),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      final address = await shop.epicboxAddress();
      final key = address.split('@').first;

      // The default port is left out, as in every address LEPIC shows.
      final added = await wallet.allowInvoiceSender(
        address: '$address:443',
        label: 'shop',
      );
      expect(added.address, address);
      expect(added.label, 'shop');
      expect(added.addedAtMs, greaterThan(0));
      expect(await wallet.invoiceSenders(), [added]);

      for (final invalid in [key, '$key@', 'not an address']) {
        await expectLater(
          wallet.allowInvoiceSender(address: invalid, label: 'x'),
          throwsWalletError(WalletErrorKind.invalidArgument),
        );
      }
      await expectLater(
        wallet.allowInvoiceSender(address: address, label: 'bad\nlabel'),
        throwsWalletError(WalletErrorKind.invalidArgument),
      );
      await expectLater(
        wallet.allowInvoiceSender(address: address, label: 'x' * 65),
        throwsWalletError(WalletErrorKind.invalidArgument),
      );

      // The key decides; the relay part of the address it is removed under does not.
      expect(
        await wallet.removeInvoiceSender(address: '$key@other.example'),
        isTrue,
      );
      expect(await wallet.invoiceSenders(), isEmpty);
      expect(await wallet.removeInvoiceSender(address: address), isFalse);
    },
  );

  test(
    'an invoice is received, paid with the typed amount and finalized',
    () async {
      final p = await parties('paid');
      final (issued, invoice) = await parked(p);
      expect(issued.amount, BigInt.from(3 * epic));
      final waiting = await p.issuer.transaction(txId: issued.txId);
      expect(waiting.direction, TxDirection.incoming);
      expect(waiting.flow, TxFlow.invoice);
      expect(invoice.slateId, issued.slateId);
      expect(invoice.senderAddress, p.issuerAddress);
      expect(invoice.amount, BigInt.from(3 * epic));
      expect(invoice.message, 'order 42');
      expect(invoice.expiresAtMs - invoice.receivedAtMs, day.inMilliseconds);
      final received = await eventWhere(
        p.payerEvents,
        (e) => e.kind == WalletEventKind.invoiceReceived,
      );
      expect(received.slateId, issued.slateId);
      expect(received.amount, BigInt.from(3 * epic));
      final hour = await p.payer.pendingInvoices(expirySecs: BigInt.from(3600));
      expect(hour.single.expiresAtMs - hour.single.receivedAtMs, 3600 * 1000);

      await expectLater(
        p.payer.payInvoice(
          slateId: issued.slateId,
          amount: BigInt.from(2 * epic),
          minimumConfirmations: BigInt.one,
        ),
        throwsWalletError(WalletErrorKind.amountMismatch),
      );
      final paid = await p.payer.payInvoice(
        slateId: issued.slateId,
        amount: BigInt.from(3 * epic),
        minimumConfirmations: BigInt.one,
      );
      expect(paid.slateId, issued.slateId);
      expect(paid.amount, BigInt.from(3 * epic));
      expect(paid.fee, greaterThan(BigInt.zero));
      final payment = await p.payer.transaction(txId: paid.txId);
      expect(payment.direction, TxDirection.outgoing);
      expect(payment.flow, TxFlow.invoice);
      expect(await p.payer.pendingInvoices(), isEmpty);
      await expectLater(
        p.payer.payInvoice(
          slateId: issued.slateId,
          amount: BigInt.from(3 * epic),
          minimumConfirmations: BigInt.one,
        ),
        throwsWalletError(WalletErrorKind.invoiceNotFound),
      );
      expect(relay.pending(address: p.issuerAddress), 1);

      final report = await p.issuer.drainEpicbox();
      expect(report.finalized, 1);
      expect(chain.pushedCount(), 1);
      final finalized = await eventWhere(
        p.issuerEvents,
        (e) => e.kind == WalletEventKind.invoiceFinalized,
      );
      expect(finalized.txId, issued.txId);
      expect(finalized.slateId, issued.slateId);
      final posted = await p.issuer.transaction(txId: issued.txId);
      expect(posted.status, TxStatus.posted);

      // The issuer's receipt waits on the payer's invoice address.
      expect(relay.pending(address: p.invoiceAddress), 1);
      final receipt = await p.payer.drainInvoices();
      expect(receipt.notices, 1);
      final notice = await eventWhere(
        p.payerEvents,
        (e) => e.kind == WalletEventKind.invoicePosted,
      );
      expect(notice.txId, paid.txId);
      expect(notice.slateId, issued.slateId);
      expect(notice.kernelExcess, isNotNull);
      expect(notice.kernelExcess, posted.kernelExcess);
    },
  );

  test(
    'an invoice from a sender that is not allowed is dropped unopened',
    () async {
      final p = await parties('stranger');
      final stranger = await EpicWallet.create(
        runtime: runtime,
        config: relayConfig('stranger-wallet'),
        store: lepicSecretStore(MemoryStore()),
        password: password,
      );
      await stranger.epicboxAddress();
      await stranger.issueInvoiceEpicbox(
        amount: BigInt.from(epic),
        address: p.invoiceAddress,
      );
      expect(relay.pending(address: p.invoiceAddress), 1);

      final report = await p.payer.drainInvoices();
      expect(report.dropped, 1);
      expect(report.parked, 0);
      expect(relay.pending(address: p.invoiceAddress), 0);
      expect(await p.payer.pendingInvoices(), isEmpty);
      expect(
        p.payerEvents.where((e) => e.kind == WalletEventKind.invoiceReceived),
        isEmpty,
      );
    },
  );

  test('an invoice a stock wallet sends back is counted and named as bounced', () async {
    final p = await parties('bounced');
    final stock = MockStockPeer(relay: relay, seed: List.filled(32, 7));
    final issued = await p.issuer.issueInvoiceEpicbox(
      amount: BigInt.from(epic),
      address: stock.address(),
    );
    expect(await stock.returnMessages(runtime: runtime), 1);
    expect(relay.pending(address: p.issuerAddress), 1);

    final report = await p.issuer.drainEpicbox();
    expect(report.bounced, 1);
    expect(report.finalized, 0);
    expect(report.dropped, 0);
    expect(relay.pending(address: p.issuerAddress), 0);
    await eventWhere(
      p.issuerEvents,
      (e) => e.kind == WalletEventKind.invoiceBounced,
    );
    final bounced = p.issuerEvents
        .where((e) => e.kind == WalletEventKind.invoiceBounced)
        .toList();
    expect(bounced, hasLength(1));
    expect(bounced.single.txId, issued.txId);
    expect(bounced.single.slateId, issued.slateId);
    expect(
      (await p.issuer.transaction(txId: issued.txId)).status,
      TxStatus.received,
    );

    // A wallet that does not pay invoices is never sent a notice: the cancel posts nothing.
    await p.issuer.cancelTransaction(txId: issued.txId);
    expect(relay.pending(address: stock.address()), 0);
  });

  test('the listener names an invoice a stock wallet sends back', () async {
    final p = await parties('bounced-listener');
    final stock = MockStockPeer(relay: relay, seed: List.filled(32, 7));
    final issued = await p.issuer.issueInvoiceEpicbox(
      amount: BigInt.from(epic),
      address: stock.address(),
    );
    expect(await stock.returnMessages(runtime: runtime), 1);

    final heard = <ListenerEvent>[];
    final stopped = Completer<void>();
    final listening = p.issuer.startListener().listen((event) {
      heard.add(event);
      if (event.kind == ListenerEventKind.stopped) stopped.complete();
    });
    final deadline = DateTime.now().add(const Duration(seconds: 10));
    while (!heard.any((e) => e.kind == ListenerEventKind.invoiceBounced) &&
        DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    p.issuer.stopListener();
    await stopped.future.timeout(const Duration(seconds: 10));
    await listening.cancel();

    final bounced = heard
        .where((e) => e.kind == ListenerEventKind.invoiceBounced)
        .toList();
    expect(bounced, hasLength(1), reason: '$heard');
    expect(bounced.single.txId, issued.txId);
    expect(bounced.single.slateId, issued.slateId);
    final events = p.issuerEvents
        .where((e) => e.kind == WalletEventKind.invoiceBounced)
        .toList();
    expect(events, hasLength(1));
    expect(events.single.txId, issued.txId);
    expect(events.single.slateId, issued.slateId);
  });

  test('a notice from a key that is not the other party is dropped', () async {
    final p = await parties('foreign-notice');
    final stranger = MockStockPeer(relay: relay, seed: List.filled(32, 9));
    final (issued, _) = await parked(p);
    for (final text in [
      '{"lepic":1,"type":"declined","slate_id":"${issued.slateId}"}',
      '{"lepic":1,"type":"surprise","slate_id":"${issued.slateId}"}',
    ]) {
      await stranger.send(runtime: runtime, to: p.issuerAddress, text: text);
    }

    final report = await p.issuer.drainEpicbox();
    expect(report.dropped, 2);
    expect(report.notices, 0);
    expect(relay.pending(address: p.issuerAddress), 0);
    expect(
      p.issuerEvents.where((e) => e.kind == WalletEventKind.invoiceDeclined),
      isEmpty,
    );
  });

  test('a declined invoice is never paid', () async {
    final p = await parties('declined');
    final (issued, _) = await parked(p);

    await p.payer.declineInvoice(slateId: issued.slateId);
    expect(await p.payer.pendingInvoices(), isEmpty);
    await expectLater(
      p.payer.payInvoice(
        slateId: issued.slateId,
        amount: BigInt.from(3 * epic),
        minimumConfirmations: BigInt.one,
      ),
      throwsWalletError(WalletErrorKind.invoiceNotFound),
    );
    await expectLater(
      p.payer.declineInvoice(slateId: issued.slateId),
      throwsWalletError(WalletErrorKind.invoiceNotFound),
    );
    await expectLater(
      p.payer.declineInvoice(slateId: 'not-a-slate-id'),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
    // The parked invoice proved the issuer runs LEPIC, so it hears of the decline.
    expect(relay.pending(address: p.issuerAddress), 1);
    final report = await p.issuer.drainEpicbox();
    expect(report.notices, 1);
    final declined = await eventWhere(
      p.issuerEvents,
      (e) => e.kind == WalletEventKind.invoiceDeclined,
    );
    expect(declined.txId, issued.txId);
    expect(declined.slateId, issued.slateId);
    expect(
      (await p.issuer.transaction(txId: issued.txId)).status,
      TxStatus.received,
    );
  });

  test('a withdrawn invoice reaches the payer only once it proved LEPIC', () async {
    final p = await parties('withdrawn');

    // Nothing proves yet that the payer runs LEPIC: the cancel sends no notice.
    final (unproven, _) = await parked(p);
    await p.issuer.cancelTransaction(txId: unproven.txId);
    expect(relay.pending(address: p.invoiceAddress), 0);
    await p.payer.declineInvoice(slateId: unproven.slateId);
    await p.issuer.drainEpicbox();

    // A paid and finalized invoice proves it.
    final (first, _) = await parked(p);
    await p.payer.payInvoice(
      slateId: first.slateId,
      amount: BigInt.from(3 * epic),
      minimumConfirmations: BigInt.one,
    );
    expect((await p.issuer.drainEpicbox()).finalized, 1);
    expect((await p.payer.drainInvoices()).notices, 1);

    final (unpaid, _) = await parked(p);
    await p.issuer.cancelTransaction(txId: unpaid.txId);
    expect(relay.pending(address: p.invoiceAddress), 1);
    expect((await p.payer.drainInvoices()).notices, 1);
    final gone = await eventWhere(
      p.payerEvents,
      (e) =>
          e.kind == WalletEventKind.invoiceWithdrawn &&
          e.slateId == unpaid.slateId,
    );
    expect(gone.txId, isNull);
    expect(await p.payer.pendingInvoices(), isEmpty);

    // Withdrawn after the payer paid: the payment is named for a cancel, nothing moves. The
    // first payment's change is mined first, so there is something to pay with.
    chain.minePushed();
    chain.setHeight(height: BigInt.from(30));
    await p.payer.summary(refresh: true);
    final (late, _) = await parked(p);
    final payment = await p.payer.payInvoice(
      slateId: late.slateId,
      amount: BigInt.from(3 * epic),
      minimumConfirmations: BigInt.one,
    );
    await p.issuer.cancelTransaction(txId: late.txId);
    expect((await p.payer.drainInvoices()).notices, 1);
    final offer = await eventWhere(
      p.payerEvents,
      (e) =>
          e.kind == WalletEventKind.invoiceWithdrawn &&
          e.slateId == late.slateId,
    );
    expect(offer.txId, payment.txId);
    expect(
      (await p.payer.transaction(txId: payment.txId)).status,
      TxStatus.sent,
    );
    final pushed = chain.pushedCount();
    expect((await p.issuer.drainEpicbox()).finalized, 0);
    expect(chain.pushedCount(), pushed);
    await p.payer.cancelTransaction(txId: payment.txId);
  });

  test('a payment the relay did not take is delivered again', () async {
    final p = await parties('resend');
    final (issued, _) = await parked(p);

    relay.setRefusing(refusing: true);
    await expectLater(
      p.payer.payInvoice(
        slateId: issued.slateId,
        amount: BigInt.from(3 * epic),
        minimumConfirmations: BigInt.one,
      ),
      throwsWalletError(WalletErrorKind.notDelivered),
    );
    final payment = (await p.payer.transactions()).singleWhere(
      (tx) => tx.slateId == issued.slateId,
    );
    expect(payment.status, TxStatus.sent);
    expect(payment.counterparty, p.issuerAddress);
    await expectLater(
      p.payer.resendInvoicePayment(txId: payment.txId),
      throwsWalletError(WalletErrorKind.transportFailed),
    );
    relay.setRefusing(refusing: false);

    await p.payer.resendInvoicePayment(txId: payment.txId);
    expect(relay.pending(address: p.issuerAddress), 1);
    expect((await p.issuer.drainEpicbox()).finalized, 1);
    expect(chain.pushedCount(), 1);
    await expectLater(
      p.payer.resendInvoicePayment(txId: 999),
      throwsWalletError(WalletErrorKind.invalidArgument),
    );
  });

  test('a sweep expires unpaid invoices on both sides', () async {
    final p = await parties('expiry');
    final (issued, _) = await parked(p);
    for (final invalid in [0, 48 * 3600 + 1]) {
      await expectLater(
        p.payer.sweepInvoices(expirySecs: BigInt.from(invalid)),
        throwsWalletError(WalletErrorKind.invalidArgument),
      );
    }
    final kept = await p.payer.sweepInvoices();
    expect(kept.deleted, isEmpty);
    expect(await p.payer.pendingInvoices(), hasLength(1));

    await Future<void>.delayed(const Duration(milliseconds: 1500));
    final payerSweep = await p.payer.sweepInvoices(expirySecs: BigInt.one);
    expect(payerSweep.deleted, [issued.slateId]);
    expect(await p.payer.pendingInvoices(), isEmpty);
    final deleted = await eventWhere(
      p.payerEvents,
      (e) => e.kind == WalletEventKind.invoiceExpired,
    );
    expect(deleted.slateId, issued.slateId);
    expect(deleted.txId, isNull);

    final issuerSweep = await p.issuer.sweepInvoices(expirySecs: BigInt.one);
    expect(issuerSweep.cancelled, [issued.txId]);
    expect(
      (await p.issuer.transaction(txId: issued.txId)).status,
      TxStatus.cancelled,
    );
    final cancelled = await eventWhere(
      p.issuerEvents,
      (e) => e.kind == WalletEventKind.invoiceExpired,
    );
    expect(cancelled.slateId, issued.slateId);
    expect(cancelled.txId, issued.txId);
  });

  test('a payment past its time to live is offered for cancel', () async {
    final p = await parties('cancellable');
    final (issued, _) = await parked(p);
    final paid = await p.payer.payInvoice(
      slateId: issued.slateId,
      amount: BigInt.from(3 * epic),
      minimumConfirmations: BigInt.one,
    );
    expect((await p.payer.sweepInvoices()).cancellable, isEmpty);

    // The issuer never posts it; the chain passes the payment's time to live, and two
    // refreshes confirm that tip.
    final ttl = (await p.payer.transaction(txId: paid.txId)).ttlCutoffHeight!;
    chain.setHeight(height: ttl);
    await p.payer.summary(refresh: true);
    await p.payer.summary(refresh: true);

    final sweep = await p.payer.sweepInvoices();
    expect(sweep.cancellable, [paid.txId]);
    expect((await p.payer.transaction(txId: paid.txId)).status, TxStatus.sent);
    await p.payer.cancelTransaction(txId: paid.txId);
    expect(
      (await p.payer.transaction(txId: paid.txId)).status,
      TxStatus.cancelled,
    );
  });

  test('errors of the invoice calls carry their stable codes', () async {
    final wallet = await EpicWallet.create(
      runtime: runtime,
      config: relayConfig('codes'),
      store: lepicSecretStore(MemoryStore()),
      password: password,
    );
    await expectLater(
      wallet.payInvoice(
        slateId: '0436430c-2b02-624c-2032-570501212b0e',
        amount: BigInt.from(epic),
        minimumConfirmations: BigInt.one,
      ),
      throwsWalletError(WalletErrorKind.invoiceNotFound),
    );
    wallet.lock();
    await expectLater(
      wallet.pendingInvoices(),
      throwsWalletError(WalletErrorKind.locked),
    );
  });
}
