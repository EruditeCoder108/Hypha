import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:relay_mobile/src/features/messenger/controllers/messenger_controller.dart';
import 'package:relay_mobile/src/features/messenger/widgets/hypha_brand.dart';
import 'package:relay_mobile/src/features/protocol_lab/protocol_lab_screen.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key, required this.controller});

  final MessengerController controller;

  Future<void> _editDisplayName(BuildContext context) async {
    final value = await showDialog<String>(
      context: context,
      builder: (_) => _DisplayNameDialog(initialName: controller.displayName),
    );
    if (value == null || !context.mounted) return;

    final saved = await controller.updateDisplayName(value);
    if (!context.mounted) return;
    final messenger = ScaffoldMessenger.of(context);
    messenger.hideCurrentSnackBar();
    messenger.showSnackBar(
      SnackBar(
        content: Text(
          saved
              ? 'Name saved as ${controller.displayName}.'
              : controller.statusError ?? 'The name could not be saved.',
        ),
      ),
    );
  }

  Future<void> _importVenueInventory(BuildContext context) async {
    final current = controller.venueTrustStatus;
    if (!current.isManaged) {
      final approved = await showDialog<bool>(
        context: context,
        builder: (dialogContext) => AlertDialog(
          title: const Text('Enter Managed Venue mode?'),
          content: const Text(
            'After setup, Hypha will use only ESP nodes approved by this venueâ€™s signed list. '
            'Your current demo mode keeps accepting any ESP that proves its identity.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext, false),
              child: const Text('Keep demo mode'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(dialogContext, true),
              child: const Text('Choose signed list'),
            ),
          ],
        ),
      );
      if (approved != true || !context.mounted) return;
    }
    final result = await controller.pickVenueInventory();
    if (!context.mounted || result == null) return;
    final message = result.installed
        ? 'Managed Venue list installed (version ${result.status.version}).'
        : result.reason ?? 'The signed venue list was rejected.';
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _resetVenueTrust(BuildContext context) async {
    final approved = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Return to demo mode?'),
        content: const Text(
          'This removes the phoneâ€™s venue approval list. ESP records and identities are not cleared.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext, false),
            child: const Text('Cancel'),
          ),
          FilledButton.tonal(
            onPressed: () => Navigator.pop(dialogContext, true),
            child: const Text('Return to demo mode'),
          ),
        ],
      ),
    );
    if (approved != true || !context.mounted) return;
    final reset = await controller.resetVenueTrustToLab();
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          reset ? 'Demo mode restored.' : 'Venue mode was not reset.',
        ),
      ),
    );
  }

  void _showHowHyphaConnects(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (sheetContext) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 4, 20, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'How Hypha connects',
                style: theme.textTheme.headlineSmall?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                'Hypha works without internet and chooses the connection automatically.',
                style: theme.textTheme.bodyLarge?.copyWith(
                  color: scheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 16),
              const _ConnectionExplanation(
                icon: Icons.bluetooth_rounded,
                title: 'Nearby discovery and text',
                body:
                    'Bluetooth finds phones, verifies contacts, and carries text messages.',
              ),
              const _ConnectionExplanation(
                icon: Icons.route_rounded,
                title: 'Messages waiting for someone',
                body:
                    'Encrypted messages can be carried by other Hypha phones until they meet the recipient.',
              ),
              const _ConnectionExplanation(
                icon: Icons.wifi_tethering_rounded,
                title: 'Photos and files',
                body:
                    'A direct Wi-Fi link may be used between nearby phones for faster encrypted transfers.',
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _batteryGuidance(BackgroundRelaySettings settings) {
    final maker = settings.manufacturer.toLowerCase();
    if (maker.contains('samsung')) {
      return 'On Samsung: Settings > Apps > Hypha > Battery > Unrestricted. '
          'If delays continue, also check Battery > Background usage limits.';
    }
    if (maker.contains('xiaomi') ||
        maker.contains('redmi') ||
        maker.contains('poco')) {
      return 'On Xiaomi/Redmi: Settings > Apps > Manage apps > Hypha > '
          'Battery saver > No restrictions. Menu names can vary.';
    }
    return 'Open Hypha in Android app settings, then allow background battery '
        'use only if screen-off delivery is unreliable.';
  }

  Widget _backgroundSection(BuildContext context) {
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final settings = controller.backgroundSettings;
        final changing = controller.isChangingBackgroundSettings;
        final deliveryStatus = switch (controller.offlineDeliveryState) {
          OfflineDeliveryState.checking => 'Checking this phone…',
          OfflineDeliveryState.profileRequired =>
            'Finish setting your display name first',
          OfflineDeliveryState.off =>
            'Off — nearby messaging works while Hypha is open',
          OfflineDeliveryState.permissionRequired =>
            'Nearby devices permission is required',
          OfflineDeliveryState.bluetoothOff =>
            'Bluetooth is off — Hypha will resume when it is available',
          OfflineDeliveryState.active =>
            'Ready to carry and receive messages in the background',
          OfflineDeliveryState.activeButBatteryLimited =>
            'Ready — Android may delay some screen-off encounters',
        };
        final notificationStatus =
            switch (controller.privateNotificationState) {
              PrivateNotificationState.enabled =>
                'On — alerts never include message text',
              PrivateNotificationState.permissionRequired =>
                'Permission needed — messaging still works',
              PrivateNotificationState.disabledInSystem =>
                'Off in Android settings — messaging still works',
            };
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _SectionLabel('Privacy & delivery'),
            const SizedBox(height: 8),
            Card(
              clipBehavior: Clip.antiAlias,
              child: Column(
                children: [
                  SwitchListTile(
                    secondary: const _SettingsIcon(
                      icon: Icons.cloud_done_outlined,
                    ),
                    title: const Text(
                      'Offline delivery',
                      style: TextStyle(fontWeight: FontWeight.w600),
                    ),
                    subtitle: Text(deliveryStatus),
                    value: settings.backgroundRelayEnabled,
                    onChanged: changing
                        ? null
                        : (value) => unawaited(
                            controller.setBackgroundRelayEnabled(value),
                          ),
                  ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 4, 12, 4),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        ListTile(
                          contentPadding: EdgeInsets.zero,
                          leading: const _SettingsIcon(
                            icon: Icons.notifications_off_outlined,
                          ),
                          title: const Text(
                            'Private notifications',
                            style: TextStyle(fontWeight: FontWeight.w600),
                          ),
                          subtitle: Text(notificationStatus),
                        ),
                        if (controller.privateNotificationState ==
                            PrivateNotificationState.permissionRequired)
                          FilledButton.tonalIcon(
                            onPressed: changing
                                ? null
                                : () => unawaited(
                                    controller.requestNotificationPermission(),
                                  ),
                            icon: const Icon(
                              Icons.notifications_active_outlined,
                            ),
                            label: const Text('Allow notifications'),
                          ),
                        if (controller.privateNotificationState ==
                            PrivateNotificationState.disabledInSystem) ...[
                          OutlinedButton.icon(
                            onPressed: controller.openNotificationSettings,
                            icon: const Icon(Icons.settings_outlined),
                            label: const Text('Open notification settings'),
                          ),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _attachmentSection(BuildContext context) {
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final state = controller.fastAttachmentState;
        final ready = state == FastAttachmentState.ready;
        final status = switch (state) {
          FastAttachmentState.checking => 'Checking this phone…',
          FastAttachmentState.unsupported =>
            'Direct Wi-Fi is not supported on this phone',
          FastAttachmentState.permissionRequired =>
            'Nearby Wi-Fi permission is needed',
          FastAttachmentState.wifiOff =>
            'Wi-Fi is off — internet is not required',
          FastAttachmentState.locationOff =>
            'Location is off (required by this Android version)',
          FastAttachmentState.ready =>
            'Ready for encrypted resumable transfers',
        };
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _SectionLabel('Connections'),
            const SizedBox(height: 8),
            Card(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(12, 4, 12, 10),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: _SettingsIcon(
                        icon: ready
                            ? Icons.wifi_tethering_rounded
                            : Icons.wifi_tethering_off_rounded,
                      ),
                      title: const Text(
                        'Fast attachments',
                        style: TextStyle(fontWeight: FontWeight.w600),
                      ),
                      subtitle: Text(status),
                    ),
                    FilledButton.tonalIcon(
                      onPressed:
                          controller.isChangingAttachmentSettings ||
                              state == FastAttachmentState.checking ||
                              state == FastAttachmentState.unsupported
                          ? null
                          : () => unawaited(controller.enableFastAttachments()),
                      icon: controller.isChangingAttachmentSettings
                          ? const SizedBox.square(
                              dimension: 18,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : Icon(
                              ready
                                  ? Icons.refresh_rounded
                                  : Icons.wifi_rounded,
                            ),
                      label: Text(ready ? 'Check again' : 'Set up'),
                    ),
                  ],
                ),
              ),
            ),
          ],
        );
      },
    );
  }

  Widget _advancedSection(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final settings = controller.backgroundSettings;
        final changing = controller.isChangingBackgroundSettings;
        final venue = controller.venueTrustStatus;
        final venueStatus = switch ((venue.mode, venue.policyState)) {
          ('lab', _) => 'Demo mode â€” authenticated ESP nodes can connect',
          ('managed', 'ready') =>
            'Managed â€” signed list version ${venue.version ?? '?'} is active',
          _ => 'Managed â€” signed list is unavailable; ESP relay is blocked',
        };
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _SectionLabel('Advanced'),
            const SizedBox(height: 8),
            Card(
              clipBehavior: Clip.antiAlias,
              child: ExpansionTile(
                leading: const Icon(Icons.tune_rounded),
                title: const Text(
                  'Advanced settings',
                  style: TextStyle(fontWeight: FontWeight.w600),
                ),
                subtitle: const Text(
                  'Android background behavior and diagnostics',
                ),
                children: [
                  const Divider(height: 1),
                  SwitchListTile(
                    secondary: const Icon(Icons.restart_alt_rounded),
                    title: const Text('Restart after reboot'),
                    subtitle: const Text(
                      'Resume offline delivery after the phone starts.',
                    ),
                    value: settings.restartAfterReboot,
                    onChanged: changing || !settings.backgroundRelayEnabled
                        ? null
                        : (value) => unawaited(
                            controller.setRestartAfterReboot(value),
                          ),
                  ),
                  const Divider(height: 1),
                  ExpansionTile(
                    leading: const Icon(Icons.admin_panel_settings_outlined),
                    title: const Text('Venue ESP approval'),
                    subtitle: Text(venueStatus),
                    children: [
                      ListTile(
                        contentPadding: const EdgeInsets.only(
                          left: 32,
                          right: 16,
                        ),
                        leading: controller.isChangingVenueTrust
                            ? const SizedBox.square(
                                dimension: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : const Icon(Icons.upload_file_outlined),
                        title: Text(
                          venue.isManaged
                              ? 'Update signed list'
                              : 'Set up managed venue',
                        ),
                        subtitle: const Text(
                          'Choose an operator-signed HVI1 file from this phone.',
                        ),
                        onTap: controller.isChangingVenueTrust
                            ? null
                            : () => unawaited(_importVenueInventory(context)),
                      ),
                      if (venue.isManaged)
                        ListTile(
                          contentPadding: const EdgeInsets.only(
                            left: 32,
                            right: 16,
                          ),
                          leading: const Icon(Icons.science_outlined),
                          title: const Text('Return to demo mode'),
                          subtitle: const Text(
                            'Requires a separate confirmation.',
                          ),
                          onTap: controller.isChangingVenueTrust
                              ? null
                              : () => unawaited(_resetVenueTrust(context)),
                        ),
                    ],
                  ),
                  const Divider(height: 1),
                  ListTile(
                    leading: const Icon(Icons.battery_saver_outlined),
                    title: const Text('Screen-off reliability'),
                    subtitle: Text(
                      settings.batteryOptimizationExempt
                          ? 'Android reports unrestricted battery use'
                          : 'Android may delay background encounters',
                    ),
                    trailing: const Icon(Icons.open_in_new_rounded),
                    onTap: controller.openBatterySettings,
                  ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                    child: Text(
                      '${_batteryGuidance(settings)} Changing this may use more battery and cannot guarantee delivery.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: scheme.onSurfaceVariant,
                        height: 1.35,
                      ),
                    ),
                  ),
                  const Divider(height: 1),
                  ExpansionTile(
                    leading: const Icon(Icons.monitor_heart_outlined),
                    title: const Text('Diagnostics'),
                    subtitle: const Text('Engineering tools'),
                    children: [
                      ListTile(
                        contentPadding: const EdgeInsets.only(
                          left: 32,
                          right: 16,
                        ),
                        leading: const Icon(Icons.science_outlined),
                        title: const Text('Protocol Lab'),
                        subtitle: const Text(
                          'Radio probes, discovery events, and protocol tests',
                        ),
                        trailing: const Icon(Icons.chevron_right_rounded),
                        onTap: () {
                          Navigator.of(context).push(
                            MaterialPageRoute<void>(
                              builder: (_) => ProtocolLabScreen(
                                platform: controller.platform,
                              ),
                            ),
                          );
                        },
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        actions: [
          Padding(
            padding: EdgeInsets.only(right: 10),
            child: HyphaBrandMark(size: 30),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 32),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 720),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                ListenableBuilder(
                  listenable: controller,
                  builder: (context, _) => Card(
                    child: ListTile(
                      minTileHeight: 78,
                      leading: CircleAvatar(
                        backgroundColor: scheme.primaryContainer,
                        foregroundColor: scheme.onPrimaryContainer,
                        child: Text(
                          controller.displayName.isEmpty
                              ? 'H'
                              : controller.displayName
                                    .substring(0, 1)
                                    .toUpperCase(),
                          style: const TextStyle(fontWeight: FontWeight.w700),
                        ),
                      ),
                      title: Text(
                        controller.displayName,
                        style: const TextStyle(
                          fontWeight: FontWeight.w700,
                          fontSize: 17,
                        ),
                      ),
                      subtitle: const Text('Edit profile'),
                      trailing: const Icon(Icons.chevron_right_rounded),
                      onTap: () => _editDisplayName(context),
                    ),
                  ),
                ),
                const SizedBox(height: 20),

                _backgroundSection(context),

                const SizedBox(height: 20),

                _attachmentSection(context),

                const SizedBox(height: 20),

                const _SectionLabel('Help'),
                const SizedBox(height: 8),
                Card(
                  child: ListTile(
                    minTileHeight: 64,
                    leading: Icon(
                      Icons.offline_bolt_outlined,
                      color: scheme.primary,
                    ),
                    title: const Text(
                      'How Hypha works',
                      style: TextStyle(fontWeight: FontWeight.w600),
                    ),
                    subtitle: const Text('Nearby connections and delivery'),
                    trailing: const Icon(Icons.chevron_right_rounded),
                    onTap: () => _showHowHyphaConnects(context),
                  ),
                ),

                const SizedBox(height: 20),

                _advancedSection(context),

                const SizedBox(height: 20),

                const _SectionLabel('About'),
                const SizedBox(height: 8),

                Card(
                  child: ListTile(
                    minTileHeight: 64,
                    leading: const HyphaBrandMark(size: 30),
                    title: const Text(
                      'Hypha',
                      style: TextStyle(fontWeight: FontWeight.w600),
                    ),
                    subtitle: const Text('Private offline messenger'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _SettingsIcon extends StatelessWidget {
  const _SettingsIcon({required this.icon});

  final IconData icon;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      width: 44,
      height: 44,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: scheme.primaryContainer.withValues(alpha: 0.72),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Icon(icon, size: 22, color: scheme.onPrimaryContainer),
    );
  }
}

class _SectionLabel extends StatelessWidget {
  const _SectionLabel(this.label);

  final String label;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.only(left: 4),
      child: Text(
        label,
        style: theme.textTheme.labelLarge?.copyWith(
          color: theme.colorScheme.primary,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.2,
        ),
      ),
    );
  }
}

class _ConnectionExplanation extends StatelessWidget {
  const _ConnectionExplanation({
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
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 42,
            height: 42,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: theme.colorScheme.primaryContainer,
              shape: BoxShape.circle,
            ),
            child: Icon(
              icon,
              size: 21,
              color: theme.colorScheme.onPrimaryContainer,
            ),
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
                  body,
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                    height: 1.3,
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

class _DisplayNameDialog extends StatefulWidget {
  const _DisplayNameDialog({required this.initialName});

  final String initialName;

  @override
  State<_DisplayNameDialog> createState() => _DisplayNameDialogState();
}

class _DisplayNameDialogState extends State<_DisplayNameDialog> {
  late String _draft = widget.initialName;
  String? _errorText;

  void _submit() {
    final normalized = _draft.trim().replaceAll(RegExp(r'\s+'), ' ');
    final bytes = utf8.encode(normalized).length;
    final error = switch ((normalized, bytes)) {
      ('', _) => 'Enter a name.',
      (_, > 64) => 'Use a shorter name (maximum 64 UTF-8 bytes).',
      _ => null,
    };
    if (error != null) {
      setState(() => _errorText = error);
      return;
    }
    Navigator.of(context).pop(normalized);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Your Hypha name'),
      content: TextFormField(
        key: const ValueKey('display_name_field'),
        initialValue: widget.initialName,
        autofocus: true,
        maxLength: 64,
        textCapitalization: TextCapitalization.words,
        textInputAction: TextInputAction.done,
        autofillHints: const [AutofillHints.name],
        decoration: InputDecoration(
          labelText: 'Display name',
          helperText: 'Shown to people after a secure contact exchange.',
          errorText: _errorText,
        ),
        onChanged: (value) {
          _draft = value;
          if (_errorText != null) setState(() => _errorText = null);
        },
        onFieldSubmitted: (_) => _submit(),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(onPressed: _submit, child: const Text('Save')),
      ],
    );
  }
}
