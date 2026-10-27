import 'dart:async';

import 'package:flutter/material.dart';
import 'package:relay_mobile/src/features/messenger/controllers/messenger_controller.dart';
import 'package:relay_mobile/src/features/messenger/screens/conversation_screen.dart';
import 'package:relay_mobile/src/features/messenger/screens/nearby_people_screen.dart';
import 'package:relay_mobile/src/features/messenger/widgets/conversation_tile.dart';
import 'package:relay_mobile/src/features/messenger/widgets/hypha_brand.dart';

class ChatsHomeScreen extends StatefulWidget {
  const ChatsHomeScreen({
    super.key,
    required this.controller,
    this.onNavigateToPeople,
  });

  final MessengerController controller;
  final VoidCallback? onNavigateToPeople;

  @override
  State<ChatsHomeScreen> createState() => _ChatsHomeScreenState();
}

class _ChatsHomeScreenState extends State<ChatsHomeScreen> {
  bool _isSearching = false;
  String _searchQuery = '';
  final TextEditingController _searchController = TextEditingController();

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _triggerFindNearby() {
    if (widget.onNavigateToPeople != null) {
      widget.onNavigateToPeople!();
    } else {
      Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (_) => NearbyPeopleScreen(controller: widget.controller),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final controller = widget.controller;

    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final allSummaries = controller.conversationSummaries;
        final filteredSummaries = _searchQuery.trim().isEmpty
            ? allSummaries
            : allSummaries
                  .where((s) {
                    final query = _searchQuery.toLowerCase();
                    return s.displayLabel.toLowerCase().contains(query) ||
                        s.lastMessage.text.toLowerCase().contains(query);
                  })
                  .toList(growable: false);
        final error = controller.statusError;
        final discoveryLabel = switch ((
          controller.radioCapabilities?.bluetoothEnabled,
          controller.isDiscovering,
        )) {
          (false, _) => 'Bluetooth is off',
          (_, true) => 'Nearby discovery on',
          _ => 'Nearby discovery paused',
        };

        return Scaffold(
          appBar: AppBar(
            title: _isSearching
                ? TextField(
                    controller: _searchController,
                    autofocus: true,
                    decoration: const InputDecoration(
                      hintText: 'Search chats...',
                      border: InputBorder.none,
                    ),
                    onChanged: (val) => setState(() => _searchQuery = val),
                  )
                : Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [const HyphaBrandMark(size: 42)],
                  ),
            actions: [
              IconButton(
                icon: Icon(
                  _isSearching ? Icons.close_rounded : Icons.search_rounded,
                ),
                tooltip: _isSearching ? 'Close search' : 'Search chats',
                onPressed: () {
                  setState(() {
                    if (_isSearching) {
                      _isSearching = false;
                      _searchQuery = '';
                      _searchController.clear();
                    } else {
                      _isSearching = true;
                    }
                  });
                },
              ),
              if (_isSearching)
                const SizedBox(width: 4),
            ],
          ),
          body: Column(
            children: [
              if (error != null)
                MaterialBanner(
                  content: Text(
                    error,
                    style: TextStyle(color: scheme.onErrorContainer),
                  ),
                  backgroundColor: scheme.errorContainer,
                  actions: [
                    TextButton(
                      onPressed: controller.clearError,
                      child: Text(
                        'Dismiss',
                        style: TextStyle(color: scheme.onErrorContainer),
                      ),
                    ),
                  ],
                ),
              if (controller.showNotificationOnboarding)
                _NotificationOnboardingCard(controller: controller),
              if (!_isSearching)
                Align(
                  alignment: Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(18, 4, 18, 12),
                    child: Semantics(
                      label: discoveryLabel,
                      child: Container(
                        constraints: const BoxConstraints(maxWidth: 280),
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 7,
                        ),
                        decoration: BoxDecoration(
                          color: scheme.primaryContainer.withValues(
                            alpha: 0.72,
                          ),
                          borderRadius: BorderRadius.circular(999),
                        ),
                        child: Row(
                          children: [
                            Container(
                              width: 8,
                              height: 8,
                              decoration: BoxDecoration(
                                color: controller.isDiscovering
                                    ? scheme.secondary
                                    : scheme.onSurfaceVariant,
                                shape: BoxShape.circle,
                              ),
                            ),
                            const SizedBox(width: 9),
                            Expanded(
                              child: Text(
                                discoveryLabel,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.labelLarge?.copyWith(
                                  color: scheme.onPrimaryContainer,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              Expanded(
                child: allSummaries.isEmpty
                    ? _EmptyState(onFindNearby: _triggerFindNearby)
                    : filteredSummaries.isEmpty
                    ? Center(
                        child: Text(
                          'No matching chats found.',
                          style: theme.textTheme.bodyLarge?.copyWith(
                            color: scheme.onSurfaceVariant,
                          ),
                        ),
                      )
                    : RefreshIndicator(
                        onRefresh: controller.loadStoredMessages,
                        child: ListView.builder(
                          physics: const AlwaysScrollableScrollPhysics(),
                          itemCount: filteredSummaries.length,
                          itemBuilder: (context, index) {
                            final summary = filteredSummaries[index];
                            return ConversationTile(
                              summary: summary,
                              onTap: () {
                                Navigator.of(context).push(
                                  MaterialPageRoute<void>(
                                    builder: (_) => ConversationScreen(
                                      controller: controller,
                                      peerFingerprint: summary.peerFingerprint,
                                    ),
                                  ),
                                );
                              },
                            );
                          },
                        ),
                      ),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _NotificationOnboardingCard extends StatelessWidget {
  const _NotificationOnboardingCard({required this.controller});

  final MessengerController controller;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Card(
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 8),
      color: scheme.surfaceContainerLow,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(18),
        side: BorderSide(color: scheme.outlineVariant),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: scheme.primaryContainer,
                shape: BoxShape.circle,
              ),
              child: Icon(
                Icons.notifications_none_rounded,
                color: scheme.onPrimaryContainer,
                size: 22,
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Know when an offline message arrives',
                    style: theme.textTheme.titleSmall?.copyWith(
                      color: scheme.onSurface,
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Alerts hide message text. You can say no; messaging keeps working.',
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: scheme.onSurfaceVariant,
                      height: 1.35,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      TextButton(
                        onPressed: () => unawaited(
                          controller.dismissNotificationOnboarding(),
                        ),
                        child: const Text('Not now'),
                      ),
                      FilledButton(
                        onPressed: controller.isChangingBackgroundSettings
                            ? null
                            : () => unawaited(
                                controller.requestNotificationPermission(),
                              ),
                        child: const Text('Allow alerts'),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.onFindNearby});

  final VoidCallback onFindNearby;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final isDark = theme.brightness == Brightness.dark;

    return Stack(
      fit: StackFit.expand,
      children: [
        Positioned.fill(
          child: IgnorePointer(
            child: ExcludeSemantics(
              child: Opacity(
                opacity: isDark ? 0.10 : 0.14,
                child: Image.asset(
                  isDark
                      ? 'assets/branding/hypha-network-background-transparent.png'
                      : 'assets/branding/hypha-onboarding-network-v2.png',
                  key: const ValueKey('chats_empty_background'),
                  fit: BoxFit.cover,
                  alignment: Alignment.center,
                  color: isDark ? scheme.onSurface : null,
                  colorBlendMode: isDark ? BlendMode.srcIn : null,
                  filterQuality: FilterQuality.medium,
                ),
              ),
            ),
          ),
        ),
        Align(
          alignment: Alignment.bottomCenter,
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(32, 24, 32, 36),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  Text(
                    'No conversations yet',
                    style: theme.textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.w800,
                      letterSpacing: -0.7,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Find someone nearby to start a private offline chat.',
                    style: theme.textTheme.bodyLarge?.copyWith(
                      color: scheme.onSurfaceVariant,
                      fontSize: 16,
                      height: 1.4,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 24),
                  FilledButton.icon(
                    onPressed: onFindNearby,
                    icon: const Icon(Icons.radar_rounded),
                    label: const Text('Find nearby people'),
                    style: FilledButton.styleFrom(
                      minimumSize: const Size(220, 52),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}
