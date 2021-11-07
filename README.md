# flutterconsoleempty

dart is in /Users/michaelfehr/flutter/bin/cache/dart-sdk

https://pub.dev/packages/webcrypto

https://github.com/google/webcrypto.dart

webcrypto: ^0.5.2

ACHTUNG: error in impl_ffi.utils.dart bei aktuellem Dart (2.5+)

Zeile 28ff

void _attachFinalizerEVP_PKEY(ffi.Pointer<EVP_PKEY> key) {
final ret = dl.webcrypto_dart_dl_attach_finalizer(
key,
key.cast(),
ssl.addresses.EVP_PKEY_free.cast(),
// We don't really have an estimate of how much space the EVP_PKEY structure
// takes up, but if we make it some non-trivial size then hopefully the GC
// will prioritize freeing them.
4096,
);
if (ret != 1) {
throw AssertionError('package:webcrypto failed to attached finalizer');
}
}

geändert in void _attachFinalizerEVP_PKEY(ffi.Pointer<EVP_PKEY> key) {
final ret = dl.webcrypto_dart_dl_attach_finalizer(
key,
key.cast(),
ssl.addresses.EVP_PKEY_free.cast(),
// We don't really have an estimate of how much space the EVP_PKEY structure
// takes up, but if we make it some non-trivial size then hopefully the GC
// will prioritize freeing them.
4096,
);
if (ret != 1) {
print('error in impl_ffi.utils.dart: package:webcrypto failed to attached finalizer');
//throw AssertionError('package:webcrypto failed to attached finalizer');
}
}

Das Programm funktioniert dann, aber der Schlüssel wird nicht mehr schnell aus dem Speicher gelöscht

siehe: https://github.com/google/webcrypto.dart/issues/10



A new Flutter project.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://flutter.dev/docs/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://flutter.dev/docs/cookbook)

For help getting started with Flutter, view our
[online documentation](https://flutter.dev/docs), which offers tutorials,
samples, guidance on mobile development, and a full API reference.
