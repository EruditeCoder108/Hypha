import 'package:flutter/material.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

class RelayPlatformProvider extends InheritedWidget {
  const RelayPlatformProvider({
    super.key,
    required this.platform,
    required super.child,
  });

  final RelayPlatformApi platform;

  static RelayPlatformApi of(BuildContext context) {
    final provider = context
        .dependOnInheritedWidgetOfExactType<RelayPlatformProvider>();
    assert(provider != null, 'No RelayPlatformProvider found in context');
    return provider!.platform;
  }

  static RelayPlatformApi? maybeOf(BuildContext context) {
    final provider = context
        .dependOnInheritedWidgetOfExactType<RelayPlatformProvider>();
    return provider?.platform;
  }

  @override
  bool updateShouldNotify(RelayPlatformProvider oldWidget) {
    return platform != oldWidget.platform;
  }
}
