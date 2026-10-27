import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:relay_mobile/src/features/messenger/controllers/messenger_controller.dart';
import 'package:relay_mobile/src/features/messenger/screens/chats_home_screen.dart';
import 'package:relay_mobile/src/features/messenger/screens/conversation_screen.dart';
import 'package:relay_mobile/src/features/messenger/screens/nearby_people_screen.dart';
import 'package:relay_mobile/src/features/messenger/screens/settings_screen.dart';
import 'package:relay_mobile/src/features/messenger/widgets/hypha_brand.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';
import 'package:relay_mobile/src/platform/relay_platform_provider.dart';

class RelayApp extends StatefulWidget {
  const RelayApp({super.key, this.platform = const RelayPlatform()});

  final RelayPlatformApi platform;

  static const green = Color(0xFF12643F);
  static const darkBackground = Color(0xFF080808);
  static const darkSurface = Color(0xFF111111);
  static const lightBackground = Color(0xFFFCFCFB);

  @override
  State<RelayApp> createState() => _RelayAppState();
}

class _RelayAppState extends State<RelayApp> with WidgetsBindingObserver {
  late MessengerController _controller;
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();
  bool _controllerActionScheduled = false;
  bool _profileDialogVisible = false;
  bool _conversationNavigationRunning = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _controller = MessengerController(platform: widget.platform);
    _controller.addListener(_scheduleControllerAction);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) return;
    unawaited(_controller.loadContacts());
    unawaited(_controller.loadStoredMessages());
    unawaited(_controller.loadBackgroundSettings());
    unawaited(_controller.loadPendingConversationOpen());
    unawaited(_controller.startDiscoveryIfNeeded());
  }

  @override
  void didUpdateWidget(RelayApp oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.platform != oldWidget.platform) {
      _controller.removeListener(_scheduleControllerAction);
      _controller.dispose();
      _controller = MessengerController(platform: widget.platform);
      _controller.addListener(_scheduleControllerAction);
      _scheduleControllerAction();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _controller.removeListener(_scheduleControllerAction);
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return RelayPlatformProvider(
      platform: widget.platform,
      child: MaterialApp(
        navigatorKey: _navigatorKey,
        title: 'Hypha',
        debugShowCheckedModeBanner: false,
        themeMode: ThemeMode.system,
        theme: _theme(Brightness.light),
        darkTheme: _theme(Brightness.dark),
        home: MainNavigationShell(controller: _controller),
      ),
    );
  }

  void _scheduleControllerAction() {
    if (_controllerActionScheduled || !mounted) return;
    _controllerActionScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _controllerActionScheduled = false;
      if (mounted) unawaited(_handleControllerAction());
    });
  }

  Future<void> _handleControllerAction() async {
    final context = _navigatorKey.currentContext;
    if (context == null) return;
    if (_controller.needsProfileSetup) {
      if (_profileDialogVisible) return;
      _profileDialogVisible = true;
      await showDialog<void>(
        context: context,
        barrierDismissible: false,
        builder: (_) => _FirstRunProfileDialog(controller: _controller),
      );
      _profileDialogVisible = false;
      _scheduleControllerAction();
      return;
    }
    if (!_controller.profileSetupComplete ||
        _conversationNavigationRunning ||
        _controller.pendingConversationOpen == null) {
      return;
    }
    final fingerprint = _controller.takePendingConversationOpen();
    if (fingerprint == null || fingerprint.isEmpty) return;
    _conversationNavigationRunning = true;
    try {
      await _navigatorKey.currentState?.push<void>(
        MaterialPageRoute<void>(
          builder: (_) => ConversationScreen(
            controller: _controller,
            peerFingerprint: fingerprint,
          ),
        ),
      );
    } finally {
      _conversationNavigationRunning = false;
    }
  }

  ThemeData _theme(Brightness brightness) {
    final isDark = brightness == Brightness.dark;
    final scheme = ColorScheme.fromSeed(
      seedColor: Colors.black,
      brightness: brightness,
      primary: isDark ? const Color(0xFFF7F7F5) : const Color(0xFF050505),
      onPrimary: isDark ? const Color(0xFF080808) : Colors.white,
      primaryContainer: isDark
          ? const Color(0xFF292929)
          : const Color(0xFFEDEDEC),
      onPrimaryContainer: isDark
          ? const Color(0xFFF7F7F5)
          : const Color(0xFF101010),
      secondary: isDark ? const Color(0xFF72C49F) : RelayApp.green,
      onSecondary: isDark ? const Color(0xFF043823) : Colors.white,
      secondaryContainer: isDark
          ? const Color(0xFF123B2C)
          : const Color(0xFFDFF5EB),
      onSecondaryContainer: isDark
          ? const Color(0xFFB9F2D6)
          : const Color(0xFF073D28),
      tertiary: isDark ? const Color(0xFFBDBDBD) : const Color(0xFF4B4B4B),
      onTertiary: isDark ? const Color(0xFF171717) : Colors.white,
      tertiaryContainer: isDark
          ? const Color(0xFF303030)
          : const Color(0xFFE9E9E8),
      onTertiaryContainer: isDark
          ? const Color(0xFFF0F0EE)
          : const Color(0xFF202020),
      surface: isDark ? RelayApp.darkSurface : Colors.white,
      onSurface: isDark ? const Color(0xFFF5F5F3) : const Color(0xFF0A0A0A),
      onSurfaceVariant: isDark
          ? const Color(0xFFAEAEAA)
          : const Color(0xFF595957),
      surfaceContainerLowest: isDark
          ? const Color(0xFF050505)
          : const Color(0xFFFFFFFF),
      surfaceContainerLow: isDark
          ? const Color(0xFF141414)
          : const Color(0xFFF8F8F7),
      surfaceContainer: isDark
          ? const Color(0xFF1C1C1C)
          : const Color(0xFFF1F1F0),
      surfaceContainerHigh: isDark
          ? const Color(0xFF252525)
          : const Color(0xFFE9E9E8),
      surfaceContainerHighest: isDark
          ? const Color(0xFF303030)
          : const Color(0xFFDEDEDC),
      outline: isDark ? const Color(0xFF777773) : const Color(0xFF9B9B97),
      outlineVariant: isDark
          ? const Color(0xFF383838)
          : const Color(0xFFDEDEDC),
      error: isDark ? const Color(0xFFFFB4AB) : const Color(0xFFB42318),
      onError: isDark ? const Color(0xFF690005) : Colors.white,
      errorContainer: isDark
          ? const Color(0xFF93000A)
          : const Color(0xFFFEE4E2),
      onErrorContainer: isDark
          ? const Color(0xFFFFDAD6)
          : const Color(0xFF7A0006),
    );
    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: scheme,
      scaffoldBackgroundColor: isDark
          ? RelayApp.darkBackground
          : RelayApp.lightBackground,
      splashFactory: InkSparkle.splashFactory,
      appBarTheme: AppBarTheme(
        backgroundColor: isDark
            ? RelayApp.darkBackground
            : RelayApp.lightBackground,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        iconTheme: IconThemeData(color: scheme.onSurface, size: 24),
        actionsIconTheme: IconThemeData(color: scheme.onSurface, size: 24),
        titleTextStyle: TextStyle(
          color: scheme.onSurface,
          fontSize: 22,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.6,
        ),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        margin: EdgeInsets.zero,
        color: scheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(18),
          side: BorderSide(color: scheme.outlineVariant),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(48, 48),
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(15),
          ),
          textStyle: const TextStyle(
            fontSize: 15,
            fontWeight: FontWeight.w600,
            letterSpacing: -0.1,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size(48, 48),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          side: BorderSide(color: scheme.outline),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(15),
          ),
          textStyle: const TextStyle(
            fontSize: 15,
            fontWeight: FontWeight.w600,
            letterSpacing: -0.1,
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          minimumSize: const Size(48, 48),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(15),
          ),
          textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
      ),
      iconButtonTheme: IconButtonThemeData(
        style: IconButton.styleFrom(minimumSize: const Size(48, 48)),
      ),
      chipTheme: ChipThemeData(
        side: BorderSide.none,
        backgroundColor: scheme.primaryContainer.withValues(alpha: 0.65),
        shape: const StadiumBorder(),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: scheme.surface,
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 18,
          vertical: 16,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: BorderSide(color: scheme.outlineVariant),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: BorderSide(color: scheme.primary, width: 1.5),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: BorderSide(color: scheme.error),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: BorderSide(color: scheme.error, width: 1.5),
        ),
      ),
      dividerTheme: DividerThemeData(
        color: scheme.outlineVariant,
        space: 1,
        thickness: 1,
      ),
      navigationBarTheme: NavigationBarThemeData(
        elevation: 0,
        backgroundColor: isDark
            ? RelayApp.darkBackground
            : RelayApp.lightBackground,
        surfaceTintColor: Colors.transparent,
        indicatorColor: scheme.primaryContainer,
        height: 76,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          final isSelected = states.contains(WidgetState.selected);
          return TextStyle(
            fontSize: 12,
            fontWeight: isSelected ? FontWeight.bold : FontWeight.w500,
            color: isSelected ? scheme.onSurface : scheme.onSurfaceVariant,
          );
        }),
      ),
    );
  }
}

class MainNavigationShell extends StatefulWidget {
  const MainNavigationShell({
    super.key,
    required this.controller,
    this.initialIndex = 0,
  });

  final MessengerController controller;
  final int initialIndex;

  @override
  State<MainNavigationShell> createState() => MainNavigationShellState();
}

class MainNavigationShellState extends State<MainNavigationShell> {
  late int _currentIndex = widget.initialIndex;

  void selectTab(int index) {
    if (index >= 0 && index < 3 && _currentIndex != index) {
      setState(() => _currentIndex = index);
    }
  }

  @override
  Widget build(BuildContext context) {
    final wide = MediaQuery.sizeOf(context).width >= 640;

    final screens = [
      ChatsHomeScreen(
        controller: widget.controller,
        onNavigateToPeople: () => selectTab(1),
      ),
      NearbyPeopleScreen(controller: widget.controller),
      SettingsScreen(controller: widget.controller),
    ];

    if (wide) {
      return Scaffold(
        body: Row(
          children: [
            NavigationRail(
              selectedIndex: _currentIndex,
              onDestinationSelected: (index) =>
                  setState(() => _currentIndex = index),
              labelType: NavigationRailLabelType.all,
              destinations: const [
                NavigationRailDestination(
                  icon: Icon(Icons.chat_bubble_outline_rounded),
                  selectedIcon: Icon(Icons.chat_bubble_rounded),
                  label: Text('Chats'),
                ),
                NavigationRailDestination(
                  icon: Icon(Icons.people_outline_rounded),
                  selectedIcon: Icon(Icons.people_rounded),
                  label: Text('People'),
                ),
                NavigationRailDestination(
                  icon: Icon(Icons.settings_outlined),
                  selectedIcon: Icon(Icons.settings_rounded),
                  label: Text('Settings'),
                ),
              ],
            ),
            const VerticalDivider(width: 1, thickness: 1),
            Expanded(
              child: IndexedStack(index: _currentIndex, children: screens),
            ),
          ],
        ),
      );
    }

    return Scaffold(
      body: IndexedStack(index: _currentIndex, children: screens),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _currentIndex,
        onDestinationSelected: (index) => setState(() => _currentIndex = index),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.chat_bubble_outline_rounded),
            selectedIcon: Icon(Icons.chat_bubble_rounded),
            label: 'Chats',
          ),
          NavigationDestination(
            icon: Icon(Icons.people_outline_rounded),
            selectedIcon: Icon(Icons.people_rounded),
            label: 'People',
          ),
          NavigationDestination(
            icon: Icon(Icons.settings_outlined),
            selectedIcon: Icon(Icons.settings_rounded),
            label: 'Settings',
          ),
        ],
      ),
    );
  }
}

class _FirstRunProfileDialog extends StatefulWidget {
  const _FirstRunProfileDialog({required this.controller});

  final MessengerController controller;

  @override
  State<_FirstRunProfileDialog> createState() => _FirstRunProfileDialogState();
}

class _FirstRunProfileDialogState extends State<_FirstRunProfileDialog> {
  final TextEditingController _nameController = TextEditingController();
  String? _errorText;
  bool _saving = false;
  int _step = 0;

  @override
  void dispose() {
    _nameController.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (_saving) return;
    final normalized = _nameController.text.trim().replaceAll(
      RegExp(r'\s+'),
      ' ',
    );
    final byteLength = utf8.encode(normalized).length;
    final validationError = switch ((normalized, byteLength)) {
      ('', _) => 'Enter the name people should see.',
      (_, > 64) => 'Use a shorter name (maximum 64 UTF-8 bytes).',
      _ => null,
    };
    if (validationError != null) {
      setState(() => _errorText = validationError);
      return;
    }
    setState(() {
      _saving = true;
      _errorText = null;
    });
    final saved = await widget.controller.updateDisplayName(normalized);
    if (!mounted) return;
    if (saved) {
      Navigator.of(context).pop();
      return;
    }
    setState(() {
      _saving = false;
      _errorText =
          widget.controller.statusError ?? 'Your name could not be saved.';
    });
  }

  void _showLearnMore() {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (sheetContext) {
        final theme = Theme.of(sheetContext);
        final scheme = theme.colorScheme;
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(24, 4, 24, 28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Messaging that meets people where they are',
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w800,
                    letterSpacing: -0.6,
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  'Hypha discovers nearby phones with Bluetooth. Text messages are encrypted and can wait safely until Hypha encounters the recipient again. A direct Wi-Fi link may be used for larger attachments.',
                  style: theme.textTheme.bodyLarge?.copyWith(
                    color: scheme.onSurfaceVariant,
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 20),
                FilledButton(
                  onPressed: () => Navigator.of(sheetContext).pop(),
                  child: const Text('Got it'),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return PopScope(
      canPop: false,
      child: Dialog.fullscreen(
        backgroundColor: theme.scaffoldBackgroundColor,
        child: AnimatedSwitcher(
          duration: const Duration(milliseconds: 260),
          child: _step == 0
              ? _OnboardingIntro(
                  key: const ValueKey('first_run_intro'),
                  onContinue: () => setState(() => _step = 1),
                  onLearnMore: _showLearnMore,
                )
              : Scaffold(
                  key: const ValueKey('first_run_profile_setup'),
                  backgroundColor: theme.scaffoldBackgroundColor,
                  body: SafeArea(
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.fromLTRB(24, 28, 24, 24),
                      child: Center(
                        child: ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 560),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              const HyphaWordmark(),
                              const SizedBox(height: 54),
                              Text(
                                'Set up Hypha',
                                style: theme.textTheme.displaySmall?.copyWith(
                                  fontWeight: FontWeight.w800,
                                  letterSpacing: -1.4,
                                ),
                              ),
                              const SizedBox(height: 34),
                              Row(
                                children: [
                                  _OnboardingIcon(
                                    icon: Icons.person_outline_rounded,
                                    color: scheme.primary,
                                  ),
                                  const SizedBox(width: 14),
                                  Expanded(
                                    child: Text(
                                      'What should people call you?',
                                      style: theme.textTheme.titleMedium
                                          ?.copyWith(
                                            fontWeight: FontWeight.w700,
                                          ),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 16),
                              TextField(
                                key: const ValueKey('first_run_display_name'),
                                controller: _nameController,
                                autofocus: true,
                                enabled: !_saving,
                                maxLength: 64,
                                textCapitalization: TextCapitalization.words,
                                textInputAction: TextInputAction.done,
                                autofillHints: const [AutofillHints.name],
                                decoration: InputDecoration(
                                  hintText: 'Your name',
                                  helperText:
                                      'Shown only after a secure connection.',
                                  errorText: _errorText,
                                ),
                                onChanged: (_) {
                                  if (_errorText != null) {
                                    setState(() => _errorText = null);
                                  }
                                },
                                onSubmitted: (_) => _save(),
                              ),
                              const SizedBox(height: 18),
                              Card(
                                clipBehavior: Clip.antiAlias,
                                child: Padding(
                                  padding: const EdgeInsets.fromLTRB(
                                    18,
                                    18,
                                    18,
                                    8,
                                  ),
                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.stretch,
                                    children: [
                                      Text(
                                        'Before you start',
                                        style: theme.textTheme.titleMedium
                                            ?.copyWith(
                                              fontWeight: FontWeight.w800,
                                            ),
                                      ),
                                      const SizedBox(height: 10),
                                      _PermissionSummaryRow(
                                        icon: Icons.bluetooth_rounded,
                                        title: 'Nearby devices',
                                        body:
                                            'Hypha will ask to discover phones when setup is complete.',
                                      ),
                                      const Divider(height: 1),
                                      _PermissionSummaryRow(
                                        icon: Icons.lock_outline_rounded,
                                        title: 'Private by design',
                                        body:
                                            'Messages and attachments stay encrypted in transit.',
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                              const SizedBox(height: 18),
                              Row(
                                children: [
                                  _OnboardingIcon(
                                    icon: Icons.shield_outlined,
                                    color: scheme.primary,
                                    size: 42,
                                  ),
                                  const SizedBox(width: 12),
                                  Expanded(
                                    child: Text(
                                      'You can review delivery, notification, and attachment permissions later in Settings.',
                                      style: theme.textTheme.bodyMedium
                                          ?.copyWith(
                                            color: scheme.onSurfaceVariant,
                                            height: 1.4,
                                          ),
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 24),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                  bottomNavigationBar: SafeArea(
                    child: Padding(
                      padding: const EdgeInsets.fromLTRB(24, 10, 24, 18),
                      child: Center(
                        heightFactor: 1,
                        child: ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 560),
                          child: FilledButton(
                            onPressed: _saving ? null : _save,
                            style: FilledButton.styleFrom(
                              minimumSize: const Size.fromHeight(56),
                            ),
                            child: _saving
                                ? const SizedBox.square(
                                    dimension: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  )
                                : const Text('Finish setup'),
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
        ),
      ),
    );
  }
}

class _OnboardingIntro extends StatelessWidget {
  const _OnboardingIntro({
    super.key,
    required this.onContinue,
    required this.onLearnMore,
  });

  final VoidCallback onContinue;
  final VoidCallback onLearnMore;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    const foreground = Color(0xFF050505);
    const supporting = Color(0xFF4F4F4D);
    return Scaffold(
      backgroundColor: const Color(0xFFFCFCFB),
      body: Stack(
        fit: StackFit.expand,
        children: [
          Image.asset(
            'assets/branding/hypha-onboarding-network-v2.png',
            key: const ValueKey('onboarding_network_background'),
            fit: BoxFit.cover,
            alignment: Alignment.topCenter,
            filterQuality: FilterQuality.high,
            semanticLabel:
                'A network whose prominent nodes form the Hypha symbol',
          ),
          SafeArea(
            child: LayoutBuilder(
              builder: (context, constraints) => SingleChildScrollView(
                child: Center(
                  child: ConstrainedBox(
                    constraints: BoxConstraints(
                      maxWidth: 580,
                      minHeight: constraints.maxHeight,
                    ),
                    child: Padding(
                      padding: EdgeInsets.fromLTRB(
                        28,
                        constraints.maxHeight < 700 ? 30 : 70,
                        28,
                        16,
                      ),
                      child: IntrinsicHeight(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            const Align(
                              alignment: Alignment.center,
                              child: HyphaWordmark(
                                markSize: 43,
                                textSize: 46,
                                color: foreground,
                              ),
                            ),
                            SizedBox(
                              height: constraints.maxHeight < 700
                                  ? 150
                                  : constraints.maxHeight * 0.42,
                            ),
                            Text(
                              'Talk without\nthe internet.',
                              textAlign: TextAlign.center,
                              style: theme.textTheme.displaySmall?.copyWith(
                                color: foreground,
                                fontSize: 40,
                                fontWeight: FontWeight.w900,
                                letterSpacing: -1.9,
                                height: 1.04,
                              ),
                            ),
                            const SizedBox(height: 18),
                            Text(
                              'Hypha connects nearby devices directly and can carry messages through other Hypha devices.',
                              textAlign: TextAlign.center,
                              style: theme.textTheme.bodyLarge?.copyWith(
                                color: supporting,
                                fontSize: 17,
                                fontWeight: FontWeight.w400,
                                height: 1.5,
                                letterSpacing: -0.15,
                              ),
                            ),
                            const Spacer(),
                            FilledButton(
                              onPressed: onContinue,
                              style: FilledButton.styleFrom(
                                backgroundColor: foreground,
                                foregroundColor: Colors.white,
                                minimumSize: const Size.fromHeight(58),
                                textStyle: const TextStyle(
                                  fontSize: 17,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                              child: const Text('Continue'),
                            ),
                            const SizedBox(height: 8),
                            TextButton(
                              onPressed: onLearnMore,
                              style: TextButton.styleFrom(
                                foregroundColor: foreground,
                                textStyle: const TextStyle(
                                  fontSize: 16,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                              child: const Text('Learn more'),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _OnboardingIcon extends StatelessWidget {
  const _OnboardingIcon({
    required this.icon,
    required this.color,
    this.size = 48,
  });

  final IconData icon;
  final Color color;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        shape: BoxShape.circle,
      ),
      alignment: Alignment.center,
      child: Icon(icon, color: color, size: size * 0.5),
    );
  }
}

class _PermissionSummaryRow extends StatelessWidget {
  const _PermissionSummaryRow({
    required this.icon,
    required this.title,
    required this.body,
  });

  final IconData icon;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _OnboardingIcon(icon: icon, color: scheme.primary, size: 46),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 3),
                Text(
                  body,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: scheme.onSurfaceVariant,
                    height: 1.35,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
