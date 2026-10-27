import 'dart:async';

import 'package:flutter/material.dart';
import 'package:relay_mobile/src/features/messenger/controllers/messenger_controller.dart';
import 'package:relay_mobile/src/features/messenger/models/safety_code.dart';
import 'package:relay_mobile/src/features/messenger/screens/conversation_screen.dart';
import 'package:relay_mobile/src/features/messenger/widgets/hypha_brand.dart';

class NearbyPeopleScreen extends StatefulWidget {
  const NearbyPeopleScreen({super.key, required this.controller});

  final MessengerController controller;

  @override
  State<NearbyPeopleScreen> createState() => _NearbyPeopleScreenState();
}

class _NearbyPeopleScreenState extends State<NearbyPeopleScreen> {
  bool _showContacts = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) unawaited(widget.controller.startDiscoveryIfNeeded());
    });
  }

  Future<void> _showVerificationSheet(
    BuildContext context,
    String token,
    String fingerprint,
  ) async {
    final matches = await Navigator.of(context).push<bool>(
      MaterialPageRoute<bool>(
        builder: (_) => _VerifyContactScreen(
          displayName: widget.controller.contactLabel(fingerprint),
          fingerprint: fingerprint,
        ),
      ),
    );
    if (matches == true) {
      await widget.controller.markPeerVerified(token);
    }
  }

  void _openConversation(String fingerprint, String token) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => ConversationScreen(
          controller: widget.controller,
          peerFingerprint: fingerprint,
          explicitPeerToken: token,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.controller,
      builder: (context, _) {
        final controller = widget.controller;
        final theme = Theme.of(context);
        final scheme = theme.colorScheme;
        final peers = controller.nearbyPeers;
        final fingerprints = controller.fingerprintByToken;
        final trust = controller.trustStateByToken;

        final verified = peers.entries
            .where(
              (entry) =>
                  fingerprints[entry.key] != null &&
                  trust[entry.key] == 'verified',
            )
            .toList(growable: false);
        final identified = peers.entries
            .where(
              (entry) =>
                  fingerprints[entry.key] != null &&
                  trust[entry.key] != 'verified',
            )
            .toList(growable: false);
        final unidentified = peers.entries
            .where((entry) => fingerprints[entry.key] == null)
            .toList(growable: false);
        final nearbyFingerprints = fingerprints.values.toSet();
        final waitingContacts = controller.contacts
            .where(
              (contact) =>
                  contact.verified &&
                  !nearbyFingerprints.contains(contact.fingerprint),
            )
            .toList(growable: false);
        final waitingLegacy = controller.conversationSummaries
            .where(
              (conversation) =>
                  !nearbyFingerprints.contains(conversation.peerFingerprint) &&
                  !controller.contacts.any(
                    (contact) =>
                        contact.fingerprint == conversation.peerFingerprint,
                  ),
            )
            .toList(growable: false);

        return Scaffold(
          appBar: AppBar(
            title: const Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                HyphaBrandMark(size: 28),
                SizedBox(width: 10),
                Text('People'),
              ],
            ),
            actions: [
              Padding(
                padding: const EdgeInsets.only(right: 10),
                child: IconButton.filledTonal(
                  onPressed: () {
                    setState(() => _showContacts = false);
                    if (!controller.isDiscovering) {
                      unawaited(controller.toggleDiscovery());
                    }
                  },
                  tooltip: 'Find nearby people',
                  icon: const Icon(Icons.person_search_rounded),
                ),
              ),
            ],
          ),
          body: SafeArea(
            child: Column(
              children: [
                if (controller.statusError != null)
                  MaterialBanner(
                    content: Text(controller.statusError!),
                    backgroundColor: scheme.errorContainer,
                    actions: [
                      TextButton(
                        onPressed: controller.clearError,
                        child: const Text('Dismiss'),
                      ),
                    ],
                  ),
                Expanded(
                  child: ListView(
                    padding: const EdgeInsets.fromLTRB(12, 8, 12, 32),
                    children: [
                      _PeopleTabs(
                        showContacts: _showContacts,
                        onChanged: (showContacts) =>
                            setState(() => _showContacts = showContacts),
                      ),
                      const SizedBox(height: 20),
                      if (_showContacts) ...[
                        _SectionHeading(
                          title: 'Verified contacts',
                          count: controller.contacts.length,
                        ),
                        const SizedBox(height: 8),
                        if (controller.contacts.isEmpty &&
                            waitingLegacy.isEmpty)
                          const _SectionEmpty(
                            text:
                                'Verified people and saved conversations will appear here.',
                          )
                        else ...[
                          for (final contact in controller.contacts)
                            _ContactRow(
                              title: contact.displayName,
                              subtitle:
                                  nearbyFingerprints.contains(
                                    contact.fingerprint,
                                  )
                                  ? 'Verified • Directly nearby'
                                  : 'Verified • Not nearby',
                              nearby: nearbyFingerprints.contains(
                                contact.fingerprint,
                              ),
                              onTap: () => Navigator.of(context).push(
                                MaterialPageRoute<void>(
                                  builder: (_) => ConversationScreen(
                                    controller: controller,
                                    peerFingerprint: contact.fingerprint,
                                  ),
                                ),
                              ),
                            ),
                          for (final summary in waitingLegacy)
                            _ContactRow(
                              title: summary.displayLabel,
                              subtitle: 'Saved conversation • Not nearby',
                              nearby: false,
                              onTap: () => Navigator.of(context).push(
                                MaterialPageRoute<void>(
                                  builder: (_) => ConversationScreen(
                                    controller: controller,
                                    peerFingerprint: summary.peerFingerprint,
                                  ),
                                ),
                              ),
                            ),
                        ],
                      ] else ...[
                        _DiscoveryCard(controller: controller),
                        const SizedBox(height: 20),
                        _SectionHeading(
                          title: 'Nearby and verified',
                          count: verified.length,
                        ),
                        const SizedBox(height: 8),
                        if (verified.isEmpty)
                          const _SectionEmpty(
                            text: 'Verified contacts nearby will appear here.',
                          )
                        else
                          for (final entry in verified)
                            _PeerCard(
                              leading: Icons.verified_user_rounded,
                              leadingColor: scheme.primary,
                              title: controller.contactLabel(
                                fingerprints[entry.key]!,
                              ),
                              subtitle: 'Directly nearby • Verified',
                              status: controller.statusByToken[entry.key],
                              busy: controller.busyToken == entry.key,
                              actionLabel: 'Open chat',
                              actionIcon: Icons.chat_bubble_rounded,
                              onAction: () => _openConversation(
                                fingerprints[entry.key]!,
                                entry.key,
                              ),
                            ),
                        const SizedBox(height: 20),
                        _SectionHeading(
                          title: 'Ready to verify',
                          count: identified.length,
                        ),
                        const SizedBox(height: 8),
                        if (identified.isEmpty)
                          const _SectionEmpty(
                            text:
                                'Securely identified phones will wait here for a code comparison.',
                          )
                        else
                          for (final entry in identified)
                            _PeerCard(
                              leading: Icons.shield_outlined,
                              leadingColor: scheme.tertiary,
                              title: controller.contactLabel(
                                fingerprints[entry.key]!,
                              ),
                              subtitle:
                                  'Safety code ready • ${controller.protectionByToken[entry.key] ?? 'protected key'}',
                              status: controller.statusByToken[entry.key],
                              busy: controller.busyToken == entry.key,
                              actionLabel: 'Compare & verify',
                              actionIcon: Icons.fact_check_outlined,
                              onAction: () => _showVerificationSheet(
                                context,
                                entry.key,
                                fingerprints[entry.key]!,
                              ),
                            ),
                        const SizedBox(height: 20),
                        _SectionHeading(
                          title: 'New nearby phones',
                          count: unidentified.length,
                        ),
                        const SizedBox(height: 8),
                        if (unidentified.isEmpty)
                          const _SectionEmpty(
                            text: 'No unidentified Hypha phones are nearby.',
                          )
                        else
                          for (final entry in unidentified)
                            _PeerCard(
                              leading: Icons.phone_android_rounded,
                              leadingColor: scheme.primary,
                              title: 'Unidentified Hypha phone',
                              subtitle:
                                  'Directly nearby • Identity not yet verified',
                              status: controller.statusByToken[entry.key],
                              busy: controller.busyToken == entry.key,
                              actionLabel: 'Identify securely',
                              actionIcon: Icons.person_search_rounded,
                              onAction: () =>
                                  controller.identifyPeer(entry.key),
                            ),
                        const SizedBox(height: 20),
                        _SectionHeading(
                          title: 'Out of direct range',
                          count: waitingContacts.length + waitingLegacy.length,
                        ),
                        const SizedBox(height: 8),
                        if (waitingContacts.isEmpty && waitingLegacy.isEmpty)
                          const _SectionEmpty(
                            text:
                                'No saved conversations are waiting for a contact.',
                          )
                        else ...[
                          for (final contact in waitingContacts)
                            Card(
                              margin: const EdgeInsets.only(bottom: 8),
                              child: ListTile(
                                minVerticalPadding: 14,
                                leading: CircleAvatar(
                                  backgroundColor: scheme.surfaceContainerHigh,
                                  foregroundColor: scheme.onSurfaceVariant,
                                  child: const Icon(Icons.route_rounded),
                                ),
                                title: Text(
                                  contact.displayName,
                                  style: const TextStyle(
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                                subtitle: const Text(
                                  'Messages can travel through other Hypha phones.',
                                ),
                                trailing: const Icon(
                                  Icons.chevron_right_rounded,
                                ),
                                onTap: () => Navigator.of(context).push(
                                  MaterialPageRoute<void>(
                                    builder: (_) => ConversationScreen(
                                      controller: controller,
                                      peerFingerprint: contact.fingerprint,
                                    ),
                                  ),
                                ),
                              ),
                            ),
                          for (final summary in waitingLegacy)
                            Card(
                              margin: const EdgeInsets.only(bottom: 8),
                              child: ListTile(
                                minVerticalPadding: 14,
                                leading: CircleAvatar(
                                  backgroundColor: scheme.surfaceContainerHigh,
                                  foregroundColor: scheme.onSurfaceVariant,
                                  child: const Icon(
                                    Icons.portable_wifi_off_rounded,
                                  ),
                                ),
                                title: Text(
                                  summary.displayLabel,
                                  style: const TextStyle(
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                                subtitle: const Text(
                                  'Hypha will retry queued messages while nearby discovery is active.',
                                ),
                                trailing: const Icon(
                                  Icons.chevron_right_rounded,
                                ),
                                onTap: () => Navigator.of(context).push(
                                  MaterialPageRoute<void>(
                                    builder: (_) => ConversationScreen(
                                      controller: controller,
                                      peerFingerprint: summary.peerFingerprint,
                                    ),
                                  ),
                                ),
                              ),
                            ),
                        ],
                      ],
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}

class _VerifyContactScreen extends StatelessWidget {
  const _VerifyContactScreen({
    required this.displayName,
    required this.fingerprint,
  });

  final String displayName;
  final String fingerprint;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final compactCode = shortSafetyCode(fingerprint);
    final initial = displayName.trim().isEmpty
        ? 'H'
        : displayName.trim().substring(0, 1).toUpperCase();
    return Scaffold(
      appBar: AppBar(title: const Text('Verify contact')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const _VerificationConnectionArtwork(),
                  Card(
                    child: ListTile(
                      minTileHeight: 88,
                      leading: CircleAvatar(
                        radius: 28,
                        backgroundColor: scheme.primaryContainer,
                        foregroundColor: scheme.onPrimaryContainer,
                        child: Text(
                          initial,
                          style: const TextStyle(fontWeight: FontWeight.w800),
                        ),
                      ),
                      title: Text(
                        displayName,
                        style: const TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w800,
                          letterSpacing: -0.35,
                        ),
                      ),
                      subtitle: const Text('Hypha user'),
                    ),
                  ),
                  const SizedBox(height: 28),
                  Text(
                    'Someone nearby wants to connect',
                    textAlign: TextAlign.center,
                    style: theme.textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.w900,
                      letterSpacing: -0.9,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    'Make sure you\'re both looking at the same code.',
                    textAlign: TextAlign.center,
                    style: theme.textTheme.bodyLarge?.copyWith(
                      color: scheme.onSurfaceVariant,
                      height: 1.45,
                    ),
                  ),
                  const SizedBox(height: 18),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 18,
                      vertical: 24,
                    ),
                    decoration: BoxDecoration(
                      color: scheme.surface,
                      borderRadius: BorderRadius.circular(22),
                      border: Border.all(color: scheme.outline, width: 1.1),
                    ),
                    child: Semantics(
                      label: 'Safety code: ${compactCode.replaceAll(' ', '')}',
                      child: Text(
                        compactCode,
                        key: const ValueKey('short_safety_code'),
                        textAlign: TextAlign.center,
                        maxLines: 1,
                        style: theme.textTheme.displaySmall?.copyWith(
                          color: scheme.onSurface,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 4.5,
                          fontFeatures: const [FontFeature.tabularFigures()],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Theme(
                    data: theme.copyWith(dividerColor: Colors.transparent),
                    child: ExpansionTile(
                      tilePadding: const EdgeInsets.symmetric(horizontal: 4),
                      childrenPadding: const EdgeInsets.only(bottom: 12),
                      leading: Icon(
                        Icons.fingerprint_rounded,
                        color: scheme.onSurfaceVariant,
                      ),
                      title: const Text('View full safety fingerprint'),
                      subtitle: const Text('For higher-assurance comparison'),
                      children: [
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: scheme.surfaceContainerLow,
                            borderRadius: BorderRadius.circular(16),
                          ),
                          child: SelectableText(
                            fingerprint,
                            textAlign: TextAlign.center,
                            style: theme.textTheme.bodyMedium?.copyWith(
                              fontFamily: 'monospace',
                              fontWeight: FontWeight.w700,
                              letterSpacing: 1.1,
                              height: 1.5,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Icon(
                        Icons.shield_outlined,
                        color: scheme.onSurfaceVariant,
                        size: 20,
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'If even one digit differs, choose “Not this person”. Verification is stored only on this phone.',
                          style: theme.textTheme.bodyMedium?.copyWith(
                            color: scheme.onSurfaceVariant,
                            height: 1.4,
                          ),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 24),
                  FilledButton.icon(
                    onPressed: () => Navigator.of(context).pop(true),
                    icon: const Icon(Icons.verified_user_rounded),
                    label: const Text('Codes match'),
                    style: FilledButton.styleFrom(
                      minimumSize: const Size.fromHeight(56),
                    ),
                  ),
                  const SizedBox(height: 10),
                  OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(false),
                    style: OutlinedButton.styleFrom(
                      minimumSize: const Size.fromHeight(54),
                    ),
                    child: const Text('Not this person'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _VerificationConnectionArtwork extends StatelessWidget {
  const _VerificationConnectionArtwork();

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Semantics(
      image: true,
      label: 'Two nearby people connected through Hypha',
      child: ExcludeSemantics(
        child: RepaintBoundary(
          child: SizedBox(
            height: 228,
            child: Stack(
              alignment: Alignment.center,
              children: [
                Positioned.fill(
                  child: CustomPaint(
                    painter: _VerificationOrbitPainter(
                      lineColor: scheme.outlineVariant,
                      dotColor: scheme.onSurfaceVariant,
                    ),
                  ),
                ),
                HyphaBrandMark(size: 84, color: scheme.onSurface),
                const Positioned(
                  left: 8,
                  top: 102,
                  child: _ConnectionPersonNode(),
                ),
                const Positioned(
                  right: 8,
                  top: 118,
                  child: _ConnectionPersonNode(),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _ConnectionPersonNode extends StatelessWidget {
  const _ConnectionPersonNode();

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      width: 64,
      height: 64,
      decoration: BoxDecoration(
        color: scheme.surface,
        shape: BoxShape.circle,
        border: Border.all(color: scheme.outlineVariant, width: 1.2),
        boxShadow: [
          BoxShadow(
            color: scheme.shadow.withValues(alpha: 0.07),
            blurRadius: 16,
            offset: const Offset(0, 5),
          ),
        ],
      ),
      child: Icon(
        Icons.person_rounded,
        color: scheme.onSurfaceVariant.withValues(alpha: 0.72),
        size: 35,
      ),
    );
  }
}

class _VerificationOrbitPainter extends CustomPainter {
  const _VerificationOrbitPainter({
    required this.lineColor,
    required this.dotColor,
  });

  final Color lineColor;
  final Color dotColor;

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final orbitPaint = Paint()
      ..color = lineColor.withValues(alpha: 0.62)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;

    for (final scale in const [0.45, 0.68, 0.91]) {
      canvas.drawOval(
        Rect.fromCenter(
          center: center,
          width: size.width * scale,
          height: size.height * scale,
        ),
        orbitPaint,
      );
    }

    final left = Offset(68, size.height * 0.58);
    final right = Offset(size.width - 68, size.height * 0.65);
    _drawDottedCurve(
      canvas,
      left,
      Offset(size.width * 0.30, size.height * 0.34),
      center,
    );
    _drawDottedCurve(
      canvas,
      center,
      Offset(size.width * 0.72, size.height * 0.28),
      right,
    );

    const dots = [
      (0.16, 0.20, 3.5),
      (0.28, 0.80, 5.0),
      (0.76, 0.18, 3.0),
      (0.86, 0.40, 5.5),
      (0.70, 0.86, 3.5),
    ];
    final dotPaint = Paint()..color = dotColor.withValues(alpha: 0.42);
    for (final dot in dots) {
      canvas.drawCircle(
        Offset(size.width * dot.$1, size.height * dot.$2),
        dot.$3,
        dotPaint,
      );
    }
  }

  void _drawDottedCurve(
    Canvas canvas,
    Offset start,
    Offset control,
    Offset end,
  ) {
    final paint = Paint()..color = dotColor.withValues(alpha: 0.50);
    for (var index = 0; index <= 18; index++) {
      final t = index / 18;
      final inverse = 1 - t;
      final point = Offset(
        inverse * inverse * start.dx +
            2 * inverse * t * control.dx +
            t * t * end.dx,
        inverse * inverse * start.dy +
            2 * inverse * t * control.dy +
            t * t * end.dy,
      );
      canvas.drawCircle(point, 1.15, paint);
    }
  }

  @override
  bool shouldRepaint(covariant _VerificationOrbitPainter oldDelegate) {
    return lineColor != oldDelegate.lineColor ||
        dotColor != oldDelegate.dotColor;
  }
}

class _PeopleTabs extends StatelessWidget {
  const _PeopleTabs({required this.showContacts, required this.onChanged});

  final bool showContacts;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: double.infinity,
      child: SegmentedButton<bool>(
        showSelectedIcon: false,
        segments: const [
          ButtonSegment<bool>(
            value: false,
            icon: Icon(Icons.radar_rounded),
            label: Text('Nearby'),
          ),
          ButtonSegment<bool>(
            value: true,
            icon: Icon(Icons.contacts_outlined),
            label: Text('Contacts'),
          ),
        ],
        selected: {showContacts},
        onSelectionChanged: (selection) => onChanged(selection.single),
        style: ButtonStyle(
          minimumSize: WidgetStateProperty.all(const Size(0, 52)),
          visualDensity: VisualDensity.comfortable,
        ),
      ),
    );
  }
}

class _ContactRow extends StatelessWidget {
  const _ContactRow({
    required this.title,
    required this.subtitle,
    required this.nearby,
    required this.onTap,
  });

  final String title;
  final String subtitle;
  final bool nearby;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final initial = title.trim().isEmpty
        ? 'H'
        : title.trim().substring(0, 1).toUpperCase();
    return Container(
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: scheme.outlineVariant)),
      ),
      child: ListTile(
        minTileHeight: 82,
        contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        leading: CircleAvatar(
          radius: 27,
          backgroundColor: nearby
              ? scheme.primaryContainer
              : scheme.surfaceContainerHighest,
          foregroundColor: scheme.onSurface,
          child: Text(
            initial,
            style: const TextStyle(fontWeight: FontWeight.w800),
          ),
        ),
        title: Text(
          title,
          style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 16),
        ),
        subtitle: Text(subtitle),
        trailing: const Icon(Icons.chevron_right_rounded),
        onTap: onTap,
      ),
    );
  }
}

class _DiscoveryCard extends StatelessWidget {
  const _DiscoveryCard({required this.controller});

  final MessengerController controller;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final active = controller.isDiscovering;
    final recovering = controller.isRadioRecovering;
    return Container(
      decoration: BoxDecoration(
        color: active || recovering
            ? scheme.primaryContainer.withValues(alpha: 0.55)
            : scheme.surfaceContainerHigh,
        borderRadius: BorderRadius.circular(22),
      ),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 14, 12, 14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: active || recovering
                        ? scheme.primary
                        : scheme.surfaceContainerHighest,
                    shape: BoxShape.circle,
                  ),
                  child: Icon(
                    active
                        ? Icons.radar_rounded
                        : recovering
                        ? Icons.bluetooth_searching_rounded
                        : Icons.bluetooth_disabled_rounded,
                    size: 23,
                    color: active || recovering
                        ? scheme.onPrimary
                        : scheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        active
                            ? 'Looking for Hypha phones'
                            : recovering
                            ? 'Waiting for Bluetooth'
                            : 'Nearby discovery is off',
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        recovering
                            ? 'Turn Bluetooth on to continue'
                            : active
                            ? 'Scanning locally over Bluetooth'
                            : 'Start scanning when you want to connect',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: scheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                if (controller.isChangingDiscovery)
                  const Padding(
                    padding: EdgeInsets.all(12),
                    child: SizedBox.square(
                      dimension: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                  )
                else
                  IconButton.filledTonal(
                    onPressed: controller.toggleDiscovery,
                    tooltip: active || recovering
                        ? 'Stop nearby discovery'
                        : 'Start nearby discovery',
                    icon: Icon(
                      active || recovering
                          ? Icons.stop_rounded
                          : Icons.play_arrow_rounded,
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 10),
            Text(
              recovering
                  ? 'Hypha will reconnect and deliver waiting messages after Bluetooth is available.'
                  : 'Find, identify, and verify another Hypha phone nearby. No internet is needed.',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: scheme.onSurfaceVariant,
                height: 1.3,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _SectionHeading extends StatelessWidget {
  const _SectionHeading({required this.title, required this.count});

  final String title;
  final int count;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Row(
      children: [
        Expanded(
          child: Text(
            title,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.bold,
              letterSpacing: -0.2,
            ),
          ),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
          decoration: BoxDecoration(
            color: scheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Text(
            '$count',
            style: theme.textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.bold,
              color: scheme.onSurfaceVariant,
            ),
          ),
        ),
      ],
    );
  }
}

class _SectionEmpty extends StatelessWidget {
  const _SectionEmpty({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Text(
        text,
        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
}

class _PeerCard extends StatelessWidget {
  const _PeerCard({
    required this.leading,
    required this.leadingColor,
    required this.title,
    required this.subtitle,
    required this.busy,
    required this.actionLabel,
    required this.actionIcon,
    required this.onAction,
    this.status,
  });

  final IconData leading;
  final Color leadingColor;
  final String title;
  final String subtitle;
  final String? status;
  final bool busy;
  final String actionLabel;
  final IconData actionIcon;
  final VoidCallback onAction;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card(
      margin: const EdgeInsets.only(bottom: 6),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 10, 10, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 44,
                  height: 44,
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: leadingColor.withValues(alpha: 0.12),
                    shape: BoxShape.circle,
                  ),
                  child: Icon(leading, color: leadingColor, size: 22),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: theme.textTheme.bodyLarge?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        subtitle,
                        style: theme.textTheme.bodyMedium?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                          height: 1.3,
                        ),
                      ),
                      if (status != null && status!.isNotEmpty) ...[
                        const SizedBox(height: 3),
                        Text(
                          status!,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton.icon(
                onPressed: busy ? null : onAction,
                icon: busy
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : Icon(actionIcon, size: 19),
                label: Text(busy ? 'Working…' : actionLabel),
                style: TextButton.styleFrom(
                  minimumSize: const Size(48, 48),
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
