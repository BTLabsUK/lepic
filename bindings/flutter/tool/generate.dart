// Regenerates the bindings: runs `flutter_rust_bridge_codegen generate`, then makes every stream
// decode its errors as `WalletError`.
//
// flutter_rust_bridge 2.13.0 always decodes a `StreamSink` error as `AnyhowException`. Every
// stream call of `crates/lepic-ffi` ends its stream with a `WalletError` instead, the type every
// other call throws, so the decoder of each stream sink is replaced here.
//
// Run from `bindings/flutter`: dart run tool/generate.dart

import 'dart:io';

const generated = 'lib/src/rust/frb_generated.dart';
const anyhowDecoder = 'decodeErrorData: sse_decode_AnyhowException,';
const walletErrorDecoder = 'decodeErrorData: sse_decode_wallet_error,';

/// The body of every generated `sse_encode_StreamSink_*` function, which builds the codec of
/// one stream.
final streamSinkEncoder = RegExp(
  r'void sse_encode_StreamSink_\w+\([^)]*\)\s*\{.*?\n  \}',
  dotAll: true,
);

Future<void> main() async {
  final codegen = await Process.start('flutter_rust_bridge_codegen', [
    'generate',
  ], mode: ProcessStartMode.inheritStdio);
  final exitCode = await codegen.exitCode;
  if (exitCode != 0) {
    stderr.writeln(
      'flutter_rust_bridge_codegen failed with exit code $exitCode',
    );
    exit(exitCode);
  }

  final file = File(generated);
  final source = await file.readAsString();
  var sinks = 0;
  var replaced = 0;
  final patched = source.replaceAllMapped(streamSinkEncoder, (match) {
    sinks++;
    final encoder = match[0]!;
    if (encoder.contains(anyhowDecoder)) replaced++;
    return encoder.replaceAll(anyhowDecoder, walletErrorDecoder);
  });
  if (sinks == 0 || replaced != sinks) {
    stderr.writeln(
      'expected every stream sink in $generated to decode AnyhowException errors; '
      'found $sinks sinks, $replaced of them with that decoder. '
      'The codegen output changed: check tool/generate.dart against it.',
    );
    exit(1);
  }
  await file.writeAsString(patched);
  stdout.writeln('$replaced stream sinks decode WalletError');
}
