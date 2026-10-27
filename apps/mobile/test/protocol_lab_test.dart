import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:relay_mobile/src/app/relay_app.dart';
import 'package:relay_mobile/src/features/protocol_lab/protocol_lab_screen.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

class _FakePlatform implements RelayPlatformApi {
  _FakePlatform({this.contacts = const []});

  final List<RelayContact> contacts;
  String? lastCopyFingerprint;
  String? lastCopyText;

  @override
  Stream<BleDiscoveryEvent> get bleDiscoveryEvents => const Stream.empty();

  @override
  Future<RadioCapabilities> probeRadioCapabilities() async {
    return const RadioCapabilities(
      sdkInt: 36,
      bluetoothPresent: true,
      bluetoothEnabled: true,
      multipleAdvertisementSupported: true,
      le2MPhySupported: true,
      leCodedPhySupported: false,
      extendedAdvertisingSupported: true,
      wifiAwareSupported: true,
      wifiDirectSupported: true,
      wifiEnabled: true,
      wifiDirectPermissionRequired: false,
      locationServicesEnabled: true,
      rangingApiAvailable: true,
      secureCoreReady: true,
      permissionRequired: false,
    );
  }

  @override
  Future<VenueTrustStatus> getVenueTrustStatus() async =>
      const VenueTrustStatus.lab();

  @override
  Future<VenueInventoryInstallResult?> pickVenueInventory({
    required bool allowAuthorityBootstrap,
  }) async => null;

  @override
  Future<bool> resetVenueTrust(String confirmation) async => false;

  @override
  Future<bool> requestRadioPermissions() async => true;

  @override
  Future<bool> requestWifiDirectPermissions() async => true;

  @override
  Future<BackgroundRelaySettings> getBackgroundSettings() async =>
      const BackgroundRelaySettings.defaults();

  @override
  Future<BackgroundRelaySettings> setBackgroundRelayEnabled(
    bool enabled,
  ) async => const BackgroundRelaySettings.defaults();

  @override
  Future<BackgroundRelaySettings> setRestartAfterReboot(bool enabled) async =>
      const BackgroundRelaySettings.defaults();

  @override
  Future<bool> requestNotificationPermission() async => true;

  @override
  Future<BackgroundRelaySettings> dismissNotificationOnboarding() async =>
      const BackgroundRelaySettings.defaults();

  @override
  Future<void> openNotificationSettings() async {}

  @override
  Future<void> openBatterySettings() async {}

  @override
  Future<StoredAttachment?> pickAttachment(
    String peerFingerprint,
    String kind,
  ) async => null;

  @override
  Future<void> sendAttachment(String blePeerToken, String attachmentId) async {}

  @override
  Future<void> prepareCourierAttachment(String attachmentId) async {}

  @override
  Future<void> pauseAttachment(String attachmentId) async {}

  @override
  Future<void> cancelAttachment(String attachmentId) async {}

  @override
  Future<List<StoredAttachment>> getStoredAttachments() async => const [];

  @override
  Future<Uint8List?> loadAttachmentPreview(String attachmentId) async => null;

  @override
  Future<void> openAttachment(String attachmentId) async {}

  @override
  Future<String> startBleDiscovery() async => '0011223344556677';

  @override
  Future<void> stopBleDiscovery() async {}

  @override
  Future<void> sendEngineeringTransfer(String peerToken) async {}

  @override
  Future<void> sendTamperedEngineeringTransfer(String peerToken) async {}

  @override
  Future<void> identifyPeer(String peerToken) async {}

  @override
  Future<void> markPeerVerified(String peerToken) async {}

  @override
  Future<StoredTextMessage> sendTextMessage(
    String peerToken,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  }) async => StoredTextMessage(
    messageId: 'protocol-message',
    peerFingerprint: 'protocol-peer',
    direction: 'outgoing',
    text: text,
    status: 'queued',
    transport: 'direct',
    replyToMessageId: replyToMessageId,
    replyPreview: replyPreview,
    createdAtMs: 1,
    attemptCount: 0,
  );

  @override
  Future<void> retryTextMessage(String peerToken, String messageId) async {}

  @override
  Future<MeshQueueResult> queueMeshText(
    String peerFingerprint,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  }) async => MeshQueueResult(
    messageId: 'mesh-id',
    fingerprint: peerFingerprint,
    replyToMessageId: replyToMessageId,
    replyPreview: replyPreview,
  );

  @override
  Future<MeshQueueResult> queueLastCopyDiagnosticText(
    String peerFingerprint,
    String text,
  ) async {
    lastCopyFingerprint = peerFingerprint;
    lastCopyText = text;
    return MeshQueueResult(
      messageId: 'last-copy-mesh-id',
      fingerprint: peerFingerprint,
    );
  }

  @override
  Future<void> syncMesh(String peerToken) async {}

  @override
  Future<List<RelayContact>> getRelayContacts() async => contacts;

  @override
  Future<String> getLocalDisplayName() async => 'Relay user';

  @override
  Future<LocalProfile> getLocalProfile() async =>
      const LocalProfile(displayName: 'Relay user', setupComplete: true);

  @override
  Future<String> updateDisplayName(String displayName) async => displayName;

  @override
  Future<void> sendWifiTextMessage(
    String blePeerToken,
    String wifiPeerToken,
    String text,
  ) async {}

  @override
  Future<List<StoredTextMessage>> getStoredMessages() async => const [];

  @override
  Future<StoredMessagePage> getStoredMessagePage(
    String peerFingerprint, {
    int? beforeCreatedAtMs,
    String? beforeMessageId,
    int limit = 40,
  }) async => const StoredMessagePage(messages: [], hasMore: false);

  @override
  Future<List<StoredConversationSummary>> getConversationSummaries() async =>
      const [];

  @override
  Future<int> markConversationRead(String peerFingerprint) async => 0;

  @override
  Future<String?> consumePendingConversationOpen() async => null;

  @override
  Future<String> startWifiDirect() async => '8899aabbccddeeff';

  @override
  Future<void> stopWifiDirect() async {}

  @override
  Future<void> runWifiDirectSpeedTest(String peerToken) async {}

  @override
  Future<void> authorizeWifiUpgrade(
    String blePeerToken,
    String wifiPeerToken,
  ) async {}
}

void main() {
  testWidgets(
    'navigates from Settings -> Advanced -> Diagnostics -> Protocol Lab',
    (tester) async {
      await tester.pumpWidget(RelayApp(platform: _FakePlatform()));
      await tester.pumpAndSettle();

      // Verify Hypha home screen.
      expect(find.text('Hypha'), findsNothing);
      expect(find.bySemanticsLabel('Hypha logo'), findsOneWidget);
      expect(find.text('No conversations yet'), findsOneWidget);

      // Navigate to Settings
      final settingsButton = find.text('Settings');
      expect(settingsButton, findsOneWidget);
      await tester.tap(settingsButton);
      await tester.pumpAndSettle();

      expect(find.text('Settings'), findsWidgets);
      expect(find.text('How Hypha works'), findsOneWidget);
      expect(find.text('Nearby connections and delivery'), findsOneWidget);

      final advancedTile = find.text('Advanced settings');
      await tester.ensureVisible(advancedTile);
      await tester.tap(advancedTile);
      await tester.pumpAndSettle();

      expect(find.text('Venue ESP approval'), findsOneWidget);

      final diagnosticsTile = find.text('Diagnostics');
      await tester.ensureVisible(diagnosticsTile);
      await tester.tap(diagnosticsTile);
      await tester.pumpAndSettle();

      // Navigate to Protocol Lab under Advanced > Diagnostics.
      final protocolLabTile = find.text('Protocol Lab');
      expect(protocolLabTile, findsOneWidget);
      await tester.ensureVisible(protocolLabTile);
      await tester.pumpAndSettle();
      await tester.tap(protocolLabTile);
      await tester.pumpAndSettle();

      // Protocol Lab screen verified
      expect(find.text('Hypha Protocol Lab'), findsOneWidget);
      expect(find.text('The internet is optional.'), findsOneWidget);
      expect(find.text('Run device probe'), findsOneWidget);
      expect(find.textContaining('Not measured yet'), findsOneWidget);
    },
  );

  testWidgets('renders capability results with text and icons', (tester) async {
    await tester.pumpWidget(
      MaterialApp(home: ProtocolLabScreen(platform: _FakePlatform())),
    );

    final probeButton = find.text('Run device probe');
    await tester.ensureVisible(probeButton);
    await tester.tap(probeButton);
    await tester.pumpAndSettle();

    expect(find.text('Android API 36'), findsOneWidget);
    expect(find.text('Wi-Fi Aware'), findsOneWidget);
    expect(find.text('BLE Coded PHY'), findsOneWidget);
  });

  testWidgets('queues a private last-copy probe for the selected contact', (
    tester,
  ) async {
    const fingerprint = '1234567890ABCDEF';
    final platform = _FakePlatform(
      contacts: const [
        RelayContact(
          fingerprint: fingerprint,
          displayName: 'Samsung',
          verified: true,
          ready: true,
        ),
      ],
    );
    await tester.pumpWidget(
      MaterialApp(home: ProtocolLabScreen(platform: platform)),
    );
    await tester.pumpAndSettle();

    final button = find.byKey(const ValueKey('last_copy_$fingerprint'));
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pumpAndSettle();

    expect(platform.lastCopyFingerprint, fingerprint);
    expect(platform.lastCopyText, startsWith('LAST-COPY-PROBE-'));
    expect(find.textContaining('Queued LAST-COPY-PROBE-'), findsOneWidget);
  });
}
