import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:relay_mobile/src/app/relay_app.dart';
import 'package:relay_mobile/src/features/messenger/controllers/messenger_controller.dart';
import 'package:relay_mobile/src/features/messenger/models/safety_code.dart';
import 'package:relay_mobile/src/features/messenger/screens/conversation_screen.dart';
import 'package:relay_mobile/src/features/messenger/screens/nearby_people_screen.dart';
import 'package:relay_mobile/src/features/messenger/screens/settings_screen.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

class _TestPlatform implements RelayPlatformApi {
  _TestPlatform({
    this.messages = const [],
    this.attachments = const [],
    this.contacts = const [],
    this.summaryLoader,
    this.textSender,
    this.attachmentPreviews = const {},
    LocalProfile? localProfile,
    RadioCapabilities? radioCapabilities,
    BackgroundRelaySettings? backgroundSettings,
    Stream<BleDiscoveryEvent>? discoveryStream,
  }) : profile =
           localProfile ??
           const LocalProfile(displayName: 'Relay user', setupComplete: true),
       _radioCapabilities =
           radioCapabilities ??
           const RadioCapabilities(
             sdkInt: 34,
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
           ),
       _backgroundSettings =
           backgroundSettings ?? const BackgroundRelaySettings.defaults(),
       _discoveryStream = discoveryStream ?? const Stream.empty();

  final List<StoredTextMessage> messages;
  final List<StoredAttachment> attachments;
  final List<RelayContact> contacts;
  final Future<List<StoredConversationSummary>> Function()? summaryLoader;
  final Future<StoredTextMessage> Function(String, String)? textSender;
  final Map<String, Uint8List> attachmentPreviews;
  final Stream<BleDiscoveryEvent> _discoveryStream;
  final RadioCapabilities _radioCapabilities;
  final BackgroundRelaySettings _backgroundSettings;
  LocalProfile profile;
  String? _pendingConversationOpen;
  int messageLoadCalls = 0;
  int messagePageLoadCalls = 0;
  int summaryLoadCalls = 0;
  int discoveryStartCalls = 0;
  String? identifiedToken;
  String? verifiedToken;
  final List<(String, String)> sentMessages = [];
  final List<({String text, String? replyToMessageId, String? replyPreview})>
  sentTextRequests = [];
  final List<(String, String)> sentAttachments = [];
  final List<String> pausedAttachments = [];
  final List<String> cancelledAttachments = [];
  final List<String> updatedDisplayNames = [];
  final List<String> markedReadFingerprints = [];

  @override
  Stream<BleDiscoveryEvent> get bleDiscoveryEvents => _discoveryStream;

  @override
  Future<RadioCapabilities> probeRadioCapabilities() async =>
      _radioCapabilities;

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
      _backgroundSettings;

  @override
  Future<BackgroundRelaySettings> setBackgroundRelayEnabled(
    bool enabled,
  ) async => _backgroundSettings;

  @override
  Future<BackgroundRelaySettings> setRestartAfterReboot(bool enabled) async =>
      _backgroundSettings;

  @override
  Future<bool> requestNotificationPermission() async => true;

  @override
  Future<BackgroundRelaySettings> dismissNotificationOnboarding() async =>
      _backgroundSettings;

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
  Future<void> sendAttachment(String blePeerToken, String attachmentId) async {
    sentAttachments.add((blePeerToken, attachmentId));
  }

  @override
  Future<void> prepareCourierAttachment(String attachmentId) async {}

  @override
  Future<void> pauseAttachment(String attachmentId) async {
    pausedAttachments.add(attachmentId);
  }

  @override
  Future<void> cancelAttachment(String attachmentId) async {
    cancelledAttachments.add(attachmentId);
  }

  @override
  Future<List<StoredAttachment>> getStoredAttachments() async => attachments;

  @override
  Future<Uint8List?> loadAttachmentPreview(String attachmentId) async =>
      attachmentPreviews[attachmentId];

  @override
  Future<void> openAttachment(String attachmentId) async {}

  @override
  Future<String> startBleDiscovery() async {
    discoveryStartCalls += 1;
    return 'test_token_1234';
  }

  @override
  Future<void> stopBleDiscovery() async {}

  @override
  Future<void> sendEngineeringTransfer(String peerToken) async {}

  @override
  Future<void> sendTamperedEngineeringTransfer(String peerToken) async {}

  @override
  Future<void> identifyPeer(String peerToken) async {
    identifiedToken = peerToken;
  }

  @override
  Future<void> markPeerVerified(String peerToken) async {
    verifiedToken = peerToken;
  }

  @override
  Future<StoredTextMessage> sendTextMessage(
    String peerToken,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  }) async {
    sentMessages.add((peerToken, text));
    sentTextRequests.add((
      text: text,
      replyToMessageId: replyToMessageId,
      replyPreview: replyPreview,
    ));
    final customSender = textSender;
    if (customSender != null) return customSender(peerToken, text);
    return StoredTextMessage(
      messageId: 'direct-${sentMessages.length}',
      peerFingerprint: contacts.isNotEmpty
          ? contacts.first.fingerprint
          : 'PAIR-FINGERPRINT-9999',
      direction: 'outgoing',
      text: text,
      status: 'queued',
      transport: 'direct',
      replyToMessageId: replyToMessageId,
      replyPreview: replyPreview,
      createdAtMs: sentMessages.length,
      attemptCount: 0,
    );
  }

  @override
  Future<void> retryTextMessage(String peerToken, String messageId) async {}

  @override
  Future<MeshQueueResult> queueMeshText(
    String peerFingerprint,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  }) async {
    sentTextRequests.add((
      text: text,
      replyToMessageId: replyToMessageId,
      replyPreview: replyPreview,
    ));
    return MeshQueueResult(
      messageId: 'mesh-id',
      fingerprint: peerFingerprint,
      replyToMessageId: replyToMessageId,
      replyPreview: replyPreview,
    );
  }

  @override
  Future<MeshQueueResult> queueLastCopyDiagnosticText(
    String peerFingerprint,
    String text,
  ) async => MeshQueueResult(
    messageId: 'last-copy-mesh-id',
    fingerprint: peerFingerprint,
  );

  @override
  Future<void> syncMesh(String peerToken) async {}

  @override
  Future<List<RelayContact>> getRelayContacts() async => contacts;

  @override
  Future<String> getLocalDisplayName() async => profile.displayName;

  @override
  Future<LocalProfile> getLocalProfile() async => profile;

  @override
  Future<String> updateDisplayName(String displayName) async {
    updatedDisplayNames.add(displayName);
    profile = LocalProfile(displayName: displayName, setupComplete: true);
    return displayName;
  }

  @override
  Future<void> sendWifiTextMessage(
    String blePeerToken,
    String wifiPeerToken,
    String text,
  ) async {}

  @override
  Future<List<StoredTextMessage>> getStoredMessages() async {
    messageLoadCalls += 1;
    return messages;
  }

  @override
  Future<StoredMessagePage> getStoredMessagePage(
    String peerFingerprint, {
    int? beforeCreatedAtMs,
    String? beforeMessageId,
    int limit = 40,
  }) async {
    messagePageLoadCalls += 1;
    final newestFirst =
        messages
            .where((message) => message.peerFingerprint == peerFingerprint)
            .where(
              (message) =>
                  beforeCreatedAtMs == null ||
                  message.createdAtMs < beforeCreatedAtMs ||
                  (message.createdAtMs == beforeCreatedAtMs &&
                      message.messageId.compareTo(beforeMessageId!) < 0),
            )
            .toList(growable: false)
          ..sort((left, right) {
            final time = right.createdAtMs.compareTo(left.createdAtMs);
            return time != 0 ? time : right.messageId.compareTo(left.messageId);
          });
    final hasMore = newestFirst.length > limit;
    final pageNewestFirst = newestFirst.take(limit).toList(growable: false);
    final oldest = pageNewestFirst.isEmpty ? null : pageNewestFirst.last;
    return StoredMessagePage(
      messages: pageNewestFirst.reversed.toList(growable: false),
      hasMore: hasMore,
      nextBeforeCreatedAtMs: hasMore ? oldest?.createdAtMs : null,
      nextBeforeMessageId: hasMore ? oldest?.messageId : null,
    );
  }

  @override
  Future<List<StoredConversationSummary>> getConversationSummaries() async {
    summaryLoadCalls += 1;
    final customLoader = summaryLoader;
    if (customLoader != null) return customLoader();
    final byPeer = <String, List<StoredTextMessage>>{};
    for (final message in messages) {
      byPeer.putIfAbsent(message.peerFingerprint, () => []).add(message);
    }
    final summaries =
        byPeer.entries
            .map((entry) {
              final ordered = entry.value.toList(growable: false)
                ..sort((left, right) {
                  final time = left.createdAtMs.compareTo(right.createdAtMs);
                  return time != 0
                      ? time
                      : left.messageId.compareTo(right.messageId);
                });
              return StoredConversationSummary(
                peerFingerprint: entry.key,
                lastMessage: ordered.last,
                messageCount: ordered.length,
                unreadCount: ordered
                    .where(
                      (message) =>
                          message.direction == 'incoming' && !message.isRead,
                    )
                    .length,
              );
            })
            .toList(growable: false)
          ..sort(
            (left, right) => right.lastMessage.createdAtMs.compareTo(
              left.lastMessage.createdAtMs,
            ),
          );
    return summaries;
  }

  @override
  Future<int> markConversationRead(String peerFingerprint) async {
    markedReadFingerprints.add(peerFingerprint);
    return messages
        .where(
          (message) =>
              message.peerFingerprint == peerFingerprint &&
              message.direction == 'incoming' &&
              !message.isRead,
        )
        .length;
  }

  @override
  Future<String?> consumePendingConversationOpen() async {
    final target = _pendingConversationOpen;
    _pendingConversationOpen = null;
    return target;
  }

  @override
  Future<String> startWifiDirect() async => 'wifi_token_5678';

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

class _KeyboardInsetHarness extends StatelessWidget {
  const _KeyboardInsetHarness({
    required this.controller,
    required this.bottomInset,
  });

  final MessengerController controller;
  final ValueNotifier<double> bottomInset;

  @override
  Widget build(BuildContext context) {
    final baseMediaQuery = MediaQuery.of(context);
    return ValueListenableBuilder<double>(
      valueListenable: bottomInset,
      child: MainNavigationShell(controller: controller),
      builder: (context, inset, child) => MediaQuery(
        data: baseMediaQuery.copyWith(
          viewInsets: EdgeInsets.only(bottom: inset),
        ),
        child: child!,
      ),
    );
  }
}

void main() {
  test('short safety code is stable, normalized, and six digits', () {
    const fingerprint =
        'AA-BB-CC-DD-EE-FF-00-11-22-33-44-55-66-77-88-99-00-11-22-33-44-55-66-77-88-99-AA-BB-CC-DD-EE-FF';
    final code = shortSafetyCode(fingerprint);

    expect(code, matches(RegExp(r'^\d{2} \d{2} \d{2}$')));
    expect(
      shortSafetyCode(fingerprint.toLowerCase().replaceAll('-', '')),
      code,
    );
  });

  testWidgets(
    'first install requires a saved display name before discovery starts',
    (tester) async {
      final platform = _TestPlatform(
        localProfile: const LocalProfile(
          displayName: 'Hypha user',
          setupComplete: false,
        ),
      );

      await tester.pumpWidget(RelayApp(platform: platform));
      await tester.pumpAndSettle();

      expect(find.text('Talk without\nthe internet.'), findsOneWidget);
      expect(
        find.byKey(const ValueKey('onboarding_network_background')),
        findsOneWidget,
      );
      expect(platform.discoveryStartCalls, 0);

      await tester.tap(find.text('Continue'));
      await tester.pumpAndSettle();

      expect(find.text('What should people call you?'), findsOneWidget);

      await tester.enterText(
        find.byKey(const ValueKey('first_run_display_name')),
        'Maya Singh',
      );
      await tester.tap(find.text('Finish setup'));
      await tester.pumpAndSettle();

      expect(find.text('What should people call you?'), findsNothing);
      expect(platform.updatedDisplayNames, ['Maya Singh']);
      expect(platform.profile.setupComplete, isTrue);
      expect(platform.discoveryStartCalls, 1);
    },
  );

  testWidgets('keyboard inset does not rebuild the hidden navigation screens', (
    tester,
  ) async {
    final platform = _TestPlatform();
    final controller = MessengerController(platform: platform);
    final bottomInset = ValueNotifier<double>(0);

    await tester.pumpWidget(
      MaterialApp(
        home: _KeyboardInsetHarness(
          controller: controller,
          bottomInset: bottomInset,
        ),
      ),
    );
    await tester.pumpAndSettle();

    final settingsBefore = tester.widget<SettingsScreen>(
      find.byType(SettingsScreen, skipOffstage: false),
    );
    bottomInset.value = 320;
    await tester.pump();
    final settingsAfter = tester.widget<SettingsScreen>(
      find.byType(SettingsScreen, skipOffstage: false),
    );

    expect(identical(settingsAfter, settingsBefore), isTrue);

    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
    bottomInset.dispose();
  });

  testWidgets('opening a conversation durably clears its unread badge', (
    tester,
  ) async {
    final platform = _TestPlatform(
      messages: const [
        StoredTextMessage(
          messageId: 'unread-1',
          peerFingerprint: 'UNREAD-PEER',
          direction: 'incoming',
          text: 'A new offline message',
          status: 'received',
          createdAtMs: 1,
          attemptCount: 0,
          isRead: false,
        ),
      ],
    );

    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();

    expect(find.byType(Badge), findsOneWidget);
    expect(find.bySemanticsLabel(RegExp('1 unread message')), findsOneWidget);

    await tester.tap(find.text('A new offline message'));
    await tester.pumpAndSettle();

    expect(platform.markedReadFingerprints, contains('UNREAD-PEER'));
    expect(find.byType(Badge), findsNothing);
  });

  test('coalesces overlapping encrypted-history reload requests', () async {
    final firstRead = Completer<List<StoredConversationSummary>>();
    final followUpRead = Completer<List<StoredConversationSummary>>();
    var readIndex = 0;
    final platform = _TestPlatform(
      summaryLoader: () {
        readIndex += 1;
        return readIndex == 1 ? firstRead.future : followUpRead.future;
      },
    );
    final controller = MessengerController(platform: platform);

    await Future<void>.delayed(Duration.zero);
    expect(platform.summaryLoadCalls, 1);

    final reloadOne = controller.loadStoredMessages();
    final reloadTwo = controller.loadStoredMessages();
    expect(platform.summaryLoadCalls, 1);

    firstRead.complete(const []);
    await Future<void>.delayed(Duration.zero);
    expect(platform.summaryLoadCalls, 2);

    followUpRead.complete(const [
      StoredConversationSummary(
        peerFingerprint: 'FP-1',
        messageCount: 1,
        lastMessage: StoredTextMessage(
          messageId: 'latest',
          peerFingerprint: 'FP-1',
          direction: 'incoming',
          text: 'new state',
          status: 'received',
          createdAtMs: 1,
          attemptCount: 0,
        ),
      ),
    ]);
    await Future.wait([reloadOne, reloadTwo]);

    expect(platform.summaryLoadCalls, 2);
    expect(
      controller.conversationSummaries.single.lastMessage.messageId,
      'latest',
    );
    controller.dispose();
  });

  test(
    'direct durable events patch the timeline without a history reload',
    () async {
      final events = StreamController<BleDiscoveryEvent>.broadcast();
      final platform = _TestPlatform(
        discoveryStream: events.stream,
        messages: const [
          StoredTextMessage(
            messageId: 'outgoing-1',
            peerFingerprint: 'DIRECT-PEER',
            direction: 'outgoing',
            text: 'already durable',
            status: 'queued',
            transport: 'direct',
            createdAtMs: 1,
            attemptCount: 1,
          ),
        ],
      );
      final controller = MessengerController(platform: platform);
      await Future<void>.delayed(Duration.zero);
      await controller.loadInitialConversationHistory('DIRECT-PEER');
      expect(platform.summaryLoadCalls, 1);
      expect(platform.messagePageLoadCalls, 1);

      events.add(
        const BleDiscoveryEvent(
          type: 'text_message_delivered',
          messageId: 'outgoing-1',
        ),
      );
      await Future<void>.delayed(Duration.zero);
      expect(controller.storedMessages.single.status, 'delivered');
      expect(platform.messagePageLoadCalls, 1);

      events.add(
        const BleDiscoveryEvent(
          type: 'text_message_received',
          messageId: 'incoming-1',
          fingerprint: 'DIRECT-PEER',
          text: 'received after durable commit',
        ),
      );
      await Future<void>.delayed(Duration.zero);
      expect(controller.storedMessages, hasLength(2));
      expect(controller.storedMessages.last.messageId, 'incoming-1');
      expect(controller.storedMessages.last.status, 'received');
      expect(platform.messagePageLoadCalls, 1);

      events.add(
        const BleDiscoveryEvent(
          type: 'text_message_duplicate',
          messageId: 'incoming-1',
          fingerprint: 'DIRECT-PEER',
          text: 'received after durable commit',
        ),
      );
      await Future<void>.delayed(Duration.zero);
      expect(controller.storedMessages, hasLength(2));
      expect(platform.messagePageLoadCalls, 1);

      await events.close();
      controller.dispose();
    },
  );

  test('conversation history loads newest messages then older pages', () async {
    final messages = List<StoredTextMessage>.generate(
      85,
      (index) => StoredTextMessage(
        messageId: 'message-${index.toString().padLeft(3, '0')}',
        peerFingerprint: 'PAGED-PEER',
        direction: index.isEven ? 'incoming' : 'outgoing',
        text: 'message $index',
        status: index.isEven ? 'received' : 'delivered',
        createdAtMs: index,
        attemptCount: 0,
      ),
    );
    final platform = _TestPlatform(messages: messages);
    final controller = MessengerController(platform: platform);
    await Future<void>.delayed(Duration.zero);

    await controller.loadInitialConversationHistory('PAGED-PEER');
    expect(platform.messagePageLoadCalls, 1);
    expect(controller.storedMessages, hasLength(40));
    expect(controller.storedMessages.first.messageId, 'message-045');
    expect(controller.storedMessages.last.messageId, 'message-084');
    expect(controller.hasOlderMessages('PAGED-PEER'), isTrue);

    await controller.loadOlderMessages('PAGED-PEER');
    expect(controller.storedMessages, hasLength(80));
    expect(controller.storedMessages.first.messageId, 'message-005');

    await controller.loadOlderMessages('PAGED-PEER');
    expect(controller.storedMessages, hasLength(85));
    expect(controller.storedMessages.first.messageId, 'message-000');
    expect(controller.hasOlderMessages('PAGED-PEER'), isFalse);

    controller.dispose();
  });

  testWidgets('chats home shows empty state when no stored messages exist', (
    tester,
  ) async {
    final platform = _TestPlatform(messages: const []);

    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();

    expect(find.text('Hypha'), findsNothing);
    expect(find.bySemanticsLabel('Hypha logo'), findsOneWidget);
    expect(find.byKey(const ValueKey('new_conversation')), findsNothing);
    expect(find.text('No conversations yet'), findsOneWidget);
    expect(
      find.text('Find someone nearby to start a private offline chat.'),
      findsOneWidget,
    );
    expect(
      find.byKey(const ValueKey('chats_empty_background')),
      findsOneWidget,
    );
    expect(find.text('Find nearby people'), findsWidgets);
  });

  testWidgets(
    'settings saves a display name without a dialog lifecycle crash',
    (tester) async {
      final platform = _TestPlatform();
      final controller = MessengerController(platform: platform);

      await tester.pumpWidget(
        MaterialApp(home: SettingsScreen(controller: controller)),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Relay user'));
      await tester.pumpAndSettle();

      await tester.enterText(
        find.byKey(const ValueKey('display_name_field')),
        '  Alice   Example  ',
      );
      await tester.tap(find.widgetWithText(FilledButton, 'Save'));
      await tester.pumpAndSettle();

      expect(tester.takeException(), isNull);
      expect(platform.updatedDisplayNames, ['Alice Example']);
      expect(find.text('Alice Example'), findsOneWidget);
      expect(find.text('Name saved as Alice Example.'), findsOneWidget);

      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    },
  );

  testWidgets('settings renders typed delivery and attachment states', (
    tester,
  ) async {
    final platform = _TestPlatform(
      backgroundSettings: const BackgroundRelaySettings(
        backgroundRelayEnabled: true,
        restartAfterReboot: false,
        notificationPermissionRequired: true,
        notificationsEnabled: false,
        notificationOnboardingDismissed: true,
        batteryOptimizationExempt: false,
        manufacturer: 'Test',
        model: 'Phone',
        sdkInt: 34,
      ),
      radioCapabilities: const RadioCapabilities(
        sdkInt: 34,
        bluetoothPresent: true,
        bluetoothEnabled: false,
        multipleAdvertisementSupported: true,
        le2MPhySupported: true,
        leCodedPhySupported: false,
        extendedAdvertisingSupported: true,
        wifiAwareSupported: false,
        wifiDirectSupported: true,
        wifiEnabled: true,
        wifiDirectPermissionRequired: true,
        locationServicesEnabled: true,
        rangingApiAvailable: false,
        secureCoreReady: true,
        permissionRequired: false,
      ),
    );

    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Settings'));
    await tester.pumpAndSettle();

    expect(
      find.text('Bluetooth is off — Hypha will resume when it is available'),
      findsOneWidget,
    );
    expect(
      find.text('Permission needed — messaging still works'),
      findsOneWidget,
    );
    expect(find.text('Nearby Wi-Fi permission is needed'), findsOneWidget);
    expect(find.text('Protocol Lab'), findsNothing);
  });

  testWidgets('groups real StoredTextMessage records by peerFingerprint', (
    tester,
  ) async {
    final platform = _TestPlatform(
      messages: const [
        StoredTextMessage(
          messageId: 'msg1',
          peerFingerprint: 'AA-BB-CC-1234',
          direction: 'outgoing',
          text: 'Hello from device 1',
          status: 'delivered',
          createdAtMs: 1000,
          attemptCount: 1,
        ),
        StoredTextMessage(
          messageId: 'msg2',
          peerFingerprint: 'AA-BB-CC-1234',
          direction: 'incoming',
          text: 'Reply from device 1',
          status: 'received',
          createdAtMs: 2000,
          attemptCount: 1,
        ),
        StoredTextMessage(
          messageId: 'msg3',
          peerFingerprint: 'XX-YY-ZZ-5678',
          direction: 'outgoing',
          text: 'Queued message to device 2',
          status: 'queued',
          createdAtMs: 1500,
          attemptCount: 2,
        ),
      ],
    );

    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();

    // Verify formatted labels using last 4 chars of fingerprint
    expect(find.text('Hypha device • 1234'), findsOneWidget);
    expect(find.text('Hypha device • 5678'), findsOneWidget);

    // Verify last messages shown
    expect(find.text('Reply from device 1'), findsOneWidget);
    expect(find.text('Queued message to device 2'), findsOneWidget);
  });

  testWidgets(
    'displays compact waiting, carried, delivered, and expired status icons',
    (tester) async {
      final platform = _TestPlatform(
        messages: const [
          StoredTextMessage(
            messageId: 'msg1',
            peerFingerprint: 'FP1234',
            direction: 'outgoing',
            text: 'Message delivered',
            status: 'delivered',
            createdAtMs: 1000,
            attemptCount: 1,
          ),
          StoredTextMessage(
            messageId: 'msg3',
            peerFingerprint: 'FP9012',
            direction: 'outgoing',
            text: 'Message expired',
            status: 'expired',
            createdAtMs: 3000,
            attemptCount: 1,
          ),
          StoredTextMessage(
            messageId: 'msg2',
            peerFingerprint: 'FP5678',
            direction: 'outgoing',
            text: 'Message queued',
            status: 'queued',
            createdAtMs: 2000,
            attemptCount: 1,
          ),
          StoredTextMessage(
            messageId: 'msg4',
            peerFingerprint: 'FP3456',
            direction: 'outgoing',
            text: 'Message carried by mesh',
            status: 'relayed',
            createdAtMs: 4000,
            attemptCount: 1,
          ),
        ],
      );

      await tester.pumpWidget(RelayApp(platform: platform));
      await tester.pumpAndSettle();

      expect(find.byIcon(Icons.done_all_rounded), findsOneWidget);
      expect(find.byIcon(Icons.schedule_rounded), findsOneWidget);
      expect(find.byIcon(Icons.hub_outlined), findsOneWidget);
      expect(find.byIcon(Icons.timer_off_outlined), findsOneWidget);
    },
  );

  testWidgets(
    'opens a conversation, displays filtered messages, and shows valid composer',
    (tester) async {
      final platform = _TestPlatform(
        messages: const [
          StoredTextMessage(
            messageId: 'msg1',
            peerFingerprint: 'FP-9999',
            direction: 'incoming',
            text: 'Hey there offline!',
            status: 'received',
            createdAtMs: 1000,
            attemptCount: 1,
          ),
          StoredTextMessage(
            messageId: 'msg2',
            peerFingerprint: 'FP-9999',
            direction: 'outgoing',
            text: 'Hi! Relay works offline.',
            status: 'queued',
            createdAtMs: 2000,
            attemptCount: 1,
          ),
        ],
      );

      await tester.pumpWidget(RelayApp(platform: platform));
      await tester.pumpAndSettle();

      // Tap on conversation tile
      await tester.tap(find.text('Hypha device • 9999'));
      await tester.pumpAndSettle();

      // Check conversation screen elements
      expect(find.text('Hypha device • 9999'), findsOneWidget);
      expect(find.text('Hey there offline!'), findsOneWidget);
      expect(find.text('Hi! Relay works offline.'), findsOneWidget);
      expect(find.byIcon(Icons.schedule_rounded), findsOneWidget);
      expect(find.text('Retry now'), findsNothing);

      // Composer check
      expect(find.text('Message'), findsOneWidget);

      // Send button semantics and touch target check
      final sendButtonFinder = find.bySemanticsLabel('Send message');
      expect(sendButtonFinder, findsOneWidget);
      final size = tester.getSize(sendButtonFinder);
      expect(size.width, greaterThanOrEqualTo(48.0));
      expect(size.height, greaterThanOrEqualTo(48.0));
    },
  );

  testWidgets('long press selects whole messages and opens the action bar', (
    tester,
  ) async {
    final platform = _TestPlatform(
      contacts: const [
        RelayContact(
          fingerprint: 'ACTION-PEER',
          displayName: 'Action peer',
          verified: true,
          ready: true,
        ),
      ],
      messages: const [
        StoredTextMessage(
          messageId: 'action-message',
          peerFingerprint: 'ACTION-PEER',
          direction: 'incoming',
          text: 'Copy this safely',
          status: 'received',
          transport: 'mesh',
          createdAtMs: 1000,
          attemptCount: 0,
        ),
        StoredTextMessage(
          messageId: 'second-action-message',
          peerFingerprint: 'ACTION-PEER',
          direction: 'outgoing',
          text: 'Forward this too',
          status: 'delivered',
          transport: 'mesh',
          createdAtMs: 2000,
          attemptCount: 0,
        ),
      ],
    );

    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Forward this too'));
    await tester.pumpAndSettle();
    final firstMessage = find.byKey(const ValueKey('message_action-message'));
    final secondMessage = find.byKey(
      const ValueKey('message_second-action-message'),
    );
    await tester.longPress(firstMessage);
    await tester.pumpAndSettle();

    expect(find.byType(SelectableText), findsNothing);
    expect(find.byTooltip('Cancel selection'), findsOneWidget);
    expect(find.byTooltip('Reply'), findsOneWidget);
    expect(find.byTooltip('Copy message'), findsOneWidget);
    expect(find.byTooltip('Forward message'), findsOneWidget);
    expect(find.byTooltip('Message info'), findsOneWidget);
    expect(find.byIcon(Icons.check_circle_rounded), findsOneWidget);
    expect(find.byIcon(Icons.radio_button_unchecked_rounded), findsOneWidget);

    await tester.tap(secondMessage);
    await tester.pumpAndSettle();
    expect(find.byIcon(Icons.check_circle_rounded), findsNWidgets(2));
    expect(find.byTooltip('Copy messages'), findsOneWidget);
    expect(find.byTooltip('Forward messages'), findsOneWidget);
    expect(find.byTooltip('Reply'), findsNothing);
    expect(find.byTooltip('Message info'), findsNothing);

    await tester.tap(secondMessage);
    await tester.pumpAndSettle();

    await tester.tap(find.byTooltip('Reply'));
    await tester.pumpAndSettle();
    expect(find.text('Replying to'), findsOneWidget);
    expect(find.byTooltip('Cancel reply'), findsOneWidget);

    await tester.enterText(find.byType(TextField), 'This is a real reply');
    await tester.tap(find.bySemanticsLabel('Send message'));
    await tester.pumpAndSettle();
    expect(platform.sentTextRequests, hasLength(1));
    expect(platform.sentTextRequests.single.text, 'This is a real reply');
    expect(platform.sentTextRequests.single.replyToMessageId, 'action-message');
    expect(platform.sentTextRequests.single.replyPreview, 'Copy this safely');
    expect(platform.sentTextRequests.single.text, isNot(startsWith('> ')));
    expect(find.text('This is a real reply'), findsOneWidget);

    await tester.longPress(firstMessage);
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Forward message'));
    await tester.pumpAndSettle();
    expect(find.text('Forward to…'), findsOneWidget);
    Navigator.of(tester.element(find.text('Forward to…'))).pop();
    await tester.pumpAndSettle();

    await tester.longPress(firstMessage);
    await tester.pumpAndSettle();
    await tester.tap(find.byTooltip('Cancel selection'));
    await tester.pumpAndSettle();
    expect(find.byTooltip('Cancel selection'), findsNothing);
    expect(
      find.descendant(
        of: firstMessage,
        matching: find.text('Copy this safely'),
      ),
      findsOneWidget,
    );
  });

  testWidgets('renders both light and dark themes without exceptions', (
    tester,
  ) async {
    final platform = _TestPlatform();
    addTearDown(
      tester.binding.platformDispatcher.clearPlatformBrightnessTestValue,
    );

    tester.binding.platformDispatcher.platformBrightnessTestValue =
        Brightness.light;
    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();
    expect(
      Theme.of(tester.element(find.byType(Scaffold).first)).brightness,
      Brightness.light,
    );

    tester.binding.platformDispatcher.platformBrightnessTestValue =
        Brightness.dark;
    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();
    expect(
      Theme.of(tester.element(find.byType(Scaffold).first)).brightness,
      Brightness.dark,
    );
  });

  testWidgets('identifies a rotating token before allowing verification', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    final platform = _TestPlatform(discoveryStream: events.stream);

    await tester.pumpWidget(RelayApp(platform: platform));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Find nearby people'));
    await tester.pumpAndSettle();

    const token = '0011223344556677';
    const fingerprint = 'AA-BB-CC-DD-EE-FF-00-11-22-33-FP-8899';
    events.add(
      const BleDiscoveryEvent(
        type: 'peer_seen',
        token: token,
        rssi: -54,
        primaryPhy: '1M',
      ),
    );
    await tester.pump();

    await tester.scrollUntilVisible(
      find.text('Identify securely'),
      250,
      scrollable: find.byType(Scrollable).last,
    );
    expect(find.text('Unidentified Hypha phone'), findsOneWidget);
    expect(find.text('Identify securely'), findsOneWidget);
    await tester.tap(find.text('Identify securely'));
    await tester.pump();
    expect(platform.identifiedToken, token);

    events
      ..add(
        const BleDiscoveryEvent(
          type: 'identity_proof_verified',
          token: token,
          fingerprint: fingerprint,
          protection: 'TEE',
          trustState: 'observed',
        ),
      )
      ..add(const BleDiscoveryEvent(type: 'peer_identity_ready', token: token));
    await tester.pump();

    await tester.scrollUntilVisible(
      find.text('Compare & verify'),
      -200,
      scrollable: find.byType(Scrollable).last,
    );
    expect(find.text('Hypha device • 8899'), findsOneWidget);
    expect(find.text('Compare & verify'), findsOneWidget);
    await tester.tap(find.text('Compare & verify'));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('short_safety_code')), findsOneWidget);
    expect(find.text(shortSafetyCode(fingerprint)), findsOneWidget);
    expect(find.text(fingerprint), findsNothing);
    await tester.ensureVisible(find.text('View full safety fingerprint'));
    await tester.tap(find.text('View full safety fingerprint'));
    await tester.pumpAndSettle();
    expect(find.text(fingerprint), findsOneWidget);
    await tester.ensureVisible(find.text('Codes match'));
    await tester.tap(find.text('Codes match'));
    await tester.pump();
    expect(platform.verifiedToken, token);

    events.add(
      const BleDiscoveryEvent(
        type: 'peer_trust_updated',
        token: token,
        fingerprint: fingerprint,
        trustState: 'verified',
      ),
    );
    await tester.pump();
    await tester.scrollUntilVisible(
      find.text('Open chat'),
      -200,
      scrollable: find.byType(Scrollable).last,
    );
    expect(find.text('Open chat'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
    await events.close();
  });

  testWidgets(
    'automatic recognition exposes verified contacts but keeps unknown phones private',
    (tester) async {
      final events = StreamController<BleDiscoveryEvent>.broadcast();
      final platform = _TestPlatform(discoveryStream: events.stream);
      final controller = MessengerController(platform: platform);
      const token = '0011223344556677';

      events.add(const BleDiscoveryEvent(type: 'peer_seen', token: token));
      events.add(
        const BleDiscoveryEvent(
          type: 'identity_proof_verified',
          token: token,
          fingerprint: 'UNKNOWN-9999',
          trustState: 'observed',
          automatic: true,
        ),
      );
      await tester.pump();

      expect(controller.fingerprintByToken[token], isNull);
      expect(controller.trustStateByToken[token], isNull);

      events.add(
        const BleDiscoveryEvent(
          type: 'identity_proof_verified',
          token: token,
          fingerprint: 'VERIFIED-1234',
          trustState: 'verified',
          automatic: true,
        ),
      );
      await tester.pump();

      expect(controller.fingerprintByToken[token], 'VERIFIED-1234');
      expect(controller.trustStateByToken[token], 'verified');

      controller.dispose();
      await events.close();
    },
  );

  testWidgets('clears the composer as soon as native queueing is durable', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    final platform = _TestPlatform(discoveryStream: events.stream);
    final controller = MessengerController(platform: platform);
    const token = '0011223344556677';
    const fingerprint = 'PAIR-FINGERPRINT-9999';

    await tester.pumpWidget(
      MaterialApp(
        home: ConversationScreen(
          controller: controller,
          peerFingerprint: fingerprint,
          explicitPeerToken: token,
        ),
      ),
    );
    events
      ..add(
        const BleDiscoveryEvent(
          type: 'peer_seen',
          token: token,
          rssi: -48,
          primaryPhy: '1M',
        ),
      )
      ..add(
        const BleDiscoveryEvent(
          type: 'identity_proof_verified',
          token: token,
          fingerprint: fingerprint,
          trustState: 'verified',
        ),
      );
    await tester.pump();

    await tester.enterText(find.byType(TextField), 'keep this draft');
    await tester.tap(find.bySemanticsLabel('Send message'));
    await tester.pumpAndSettle();
    expect(platform.sentMessages, [(token, 'keep this draft')]);
    expect(find.text('keep this draft'), findsOneWidget);
    expect(
      tester.widget<TextField>(find.byType(TextField).last).controller?.text,
      isEmpty,
    );
    expect(
      tester.widget<TextField>(find.byType(TextField).last).enabled,
      isNot(false),
    );
    expect(
      tester
          .widget<EditableText>(find.byType(EditableText).last)
          .focusNode
          .hasFocus,
      isTrue,
    );

    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
    await events.close();
  });

  testWidgets('restores the draft when native durable queueing fails', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    final platform = _TestPlatform(
      discoveryStream: events.stream,
      textSender: (_, _) async => throw StateError('queue rejected'),
    );
    final controller = MessengerController(platform: platform);
    const token = '0011223344556677';
    const fingerprint = 'PAIR-FINGERPRINT-9999';

    await tester.pumpWidget(
      MaterialApp(
        home: ConversationScreen(
          controller: controller,
          peerFingerprint: fingerprint,
          explicitPeerToken: token,
        ),
      ),
    );
    events
      ..add(const BleDiscoveryEvent(type: 'peer_seen', token: token))
      ..add(
        const BleDiscoveryEvent(
          type: 'identity_proof_verified',
          token: token,
          fingerprint: fingerprint,
          trustState: 'verified',
        ),
      );
    await tester.pump();

    await tester.enterText(find.byType(TextField), 'restore this draft');
    await tester.tap(find.bySemanticsLabel('Send message'));
    await tester.pumpAndSettle();

    expect(
      tester.widget<TextField>(find.byType(TextField).last).controller?.text,
      'restore this draft',
    );
    expect(find.textContaining('could not complete'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
    await events.close();
  });

  testWidgets('verified nearby contacts use direct BLE before mesh', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    const token = '0011223344556677';
    const fingerprint = 'DIRECT-PEER-9999';
    final platform = _TestPlatform(
      contacts: const [
        RelayContact(
          fingerprint: fingerprint,
          displayName: 'Direct peer',
          verified: true,
          ready: true,
        ),
      ],
      discoveryStream: events.stream,
    );
    final controller = MessengerController(platform: platform);

    await tester.pump();
    events
      ..add(const BleDiscoveryEvent(type: 'peer_seen', token: token))
      ..add(
        const BleDiscoveryEvent(
          type: 'identity_proof_verified',
          token: token,
          fingerprint: fingerprint,
          trustState: 'verified',
        ),
      );
    await tester.pump();

    final sent = await controller.sendMessage(
      peerFingerprint: fingerprint,
      text: 'direct first',
    );
    expect(platform.sentMessages, [(token, 'direct first')]);
    expect(sent, MessageSendOutcome.queued);
    expect(controller.storedMessages.single.text, 'direct first');

    final second = await controller.sendMessage(
      peerFingerprint: fingerprint,
      text: 'direct second',
    );
    expect(second, MessageSendOutcome.queued);
    expect(platform.sentMessages, [
      (token, 'direct first'),
      (token, 'direct second'),
    ]);
    expect(controller.storedMessages.map((message) => message.text), [
      'direct first',
      'direct second',
    ]);

    controller.dispose();
    await events.close();
  });

  testWidgets(
    'shows Bluetooth recovery and accepts an automatic discovery restart',
    (tester) async {
      final events = StreamController<BleDiscoveryEvent>.broadcast();
      final platform = _TestPlatform(discoveryStream: events.stream);
      final controller = MessengerController(platform: platform);

      await tester.pumpWidget(
        MaterialApp(home: NearbyPeopleScreen(controller: controller)),
      );
      await tester.pumpAndSettle();
      expect(controller.isDiscovering, isTrue);

      events.add(
        const BleDiscoveryEvent(
          type: 'discovery_suspended',
          code: 'bluetooth_off',
          automatic: true,
        ),
      );
      await tester.pumpAndSettle();
      expect(controller.isDiscovering, isFalse);
      expect(controller.isRadioRecovering, isTrue);
      expect(find.text('Waiting for Bluetooth'), findsOneWidget);

      events.add(
        const BleDiscoveryEvent(
          type: 'discovery_started',
          token: 'new_session_token',
          automatic: true,
        ),
      );
      await tester.pumpAndSettle();
      expect(controller.isDiscovering, isTrue);
      expect(controller.isRadioRecovering, isFalse);
      expect(controller.localToken, 'new_session_token');
      expect(find.text('Looking for Hypha phones'), findsOneWidget);

      events.add(
        const BleDiscoveryEvent(
          type: 'link_error',
          token: 'peer_token',
          code: 'secure_response_read_failed',
          message: 'transient automatic sync error',
          automatic: true,
        ),
      );
      await tester.pump();
      expect(controller.statusError, isNull);

      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
      await events.close();
    },
  );

  testWidgets('shows durable attachment state in the conversation timeline', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    const fingerprint = 'ATTACHMENT-PEER-7788';
    final previewBytes = base64Decode(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    );
    final platform = _TestPlatform(
      attachmentPreviews: {
        '00112233445566778899aabbccddeeff': previewBytes,
        'abcdefabcdefabcdefabcdefabcdefab': previewBytes,
      },
      attachments: const [
        StoredAttachment(
          attachmentId: '00112233445566778899aabbccddeeff',
          peerFingerprint: fingerprint,
          direction: 'incoming',
          status: 'ready',
          kind: 'image',
          fileName: 'received-photo.jpg',
          mimeType: 'image/jpeg',
          bytes: 1048576,
          chunkCount: 6,
          createdAtMs: 2000,
          attemptCount: 1,
        ),
        StoredAttachment(
          attachmentId: 'abcdefabcdefabcdefabcdefabcdefab',
          peerFingerprint: fingerprint,
          direction: 'incoming',
          status: 'ready',
          kind: 'file',
          fileName: 'trail-video.mp4',
          mimeType: 'video/mp4',
          bytes: 2097152,
          chunkCount: 11,
          createdAtMs: 2500,
          attemptCount: 1,
        ),
        StoredAttachment(
          attachmentId: 'ffeeddccbbaa99887766554433221100',
          peerFingerprint: fingerprint,
          direction: 'outgoing',
          status: 'queued',
          kind: 'file',
          fileName: 'resume-me.pdf',
          mimeType: 'application/pdf',
          bytes: 2097152,
          chunkCount: 11,
          createdAtMs: 3000,
          attemptCount: 1,
        ),
        StoredAttachment(
          attachmentId: '11112222333344445555666677778888',
          peerFingerprint: fingerprint,
          direction: 'outgoing',
          status: 'queued',
          kind: 'file',
          fileName: 'cancelled.zip',
          mimeType: 'application/zip',
          bytes: 1024,
          chunkCount: 1,
          createdAtMs: 4000,
          attemptCount: 1,
          nextAttemptAtMs: 9223372036854775807,
          lastErrorCode: 'user_cancelled',
        ),
      ],
    );
    final controller = MessengerController(platform: platform);

    await tester.pumpWidget(
      MaterialApp(
        home: ConversationScreen(
          controller: controller,
          peerFingerprint: fingerprint,
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('received-photo.jpg'), findsOneWidget);
    expect(
      find.byKey(
        const ValueKey('attachment_preview_00112233445566778899aabbccddeeff'),
      ),
      findsOneWidget,
    );
    expect(find.text('trail-video.mp4'), findsOneWidget);
    expect(
      find.byKey(
        const ValueKey('attachment_preview_abcdefabcdefabcdefabcdefabcdefab'),
      ),
      findsOneWidget,
    );
    expect(
      find.descendant(
        of: find.byKey(
          const ValueKey('attachment_preview_abcdefabcdefabcdefabcdefabcdefab'),
        ),
        matching: find.byIcon(Icons.play_arrow_rounded),
      ),
      findsOneWidget,
    );
    expect(find.text('1.0 MB • Ready'), findsOneWidget);
    expect(find.text('resume-me.pdf'), findsOneWidget);
    expect(find.text('cancelled.zip'), findsOneWidget);
    expect(find.textContaining('Cancelled'), findsOneWidget);
    expect(
      find.text('2.0 MB • Waiting - retrying automatically'),
      findsOneWidget,
    );
    expect(find.byTooltip('Cancel attachment'), findsOneWidget);
    await tester.tap(find.byTooltip('Cancel attachment'));
    await tester.pump();
    expect(platform.cancelledAttachments, ['ffeeddccbbaa99887766554433221100']);

    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  testWidgets('shows actionable Wi-Fi and hotspot attachment states', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    const fingerprint = 'RADIO-ISSUE-PEER';
    const attachmentId = '99990000111122223333444455556666';
    final controller = MessengerController(
      platform: _TestPlatform(
        attachments: const [
          StoredAttachment(
            attachmentId: attachmentId,
            peerFingerprint: fingerprint,
            direction: 'outgoing',
            status: 'queued',
            kind: 'file',
            fileName: 'waiting.bin',
            mimeType: 'application/octet-stream',
            bytes: 1024,
            chunkCount: 1,
            createdAtMs: 1000,
            attemptCount: 1,
          ),
        ],
        discoveryStream: events.stream,
      ),
    );

    await tester.pumpWidget(
      MaterialApp(
        home: ConversationScreen(
          controller: controller,
          peerFingerprint: fingerprint,
        ),
      ),
    );
    await tester.pumpAndSettle();

    events.add(
      const BleDiscoveryEvent(type: 'wifi_direct_state', enabled: false),
    );
    await tester.pumpAndSettle();
    expect(
      controller.attachmentStatusText(controller.storedAttachments.single),
      contains('Wi-Fi Direct unavailable'),
    );
    expect(find.textContaining('Wi-Fi Direct unavailable'), findsOneWidget);
    expect(find.textContaining('â'), findsNothing);

    events
      ..add(const BleDiscoveryEvent(type: 'wifi_direct_state', enabled: true))
      ..add(
        const BleDiscoveryEvent(
          type: 'attachment_dispatch_error',
          attachmentId: attachmentId,
          code: 'wifi_direct_radio_busy',
        ),
      );
    await tester.pumpAndSettle();
    expect(
      controller.attachmentStatusText(controller.storedAttachments.single),
      contains('turn hotspot off'),
    );
    expect(find.textContaining('turn hotspot off'), findsOneWidget);
    expect(controller.statusError, isNull);

    events.add(
      const BleDiscoveryEvent(
        type: 'attachment_sending',
        attachmentId: attachmentId,
        transferredBytes: 512,
        totalBytes: 1024,
        resumedBytes: 0,
        throughputBps: 2048,
      ),
    );
    await tester.pumpAndSettle();
    expect(find.textContaining('Sending 50% - 2 KB/s'), findsOneWidget);
    expect(
      tester
          .widget<LinearProgressIndicator>(find.byType(LinearProgressIndicator))
          .value,
      0.5,
    );

    events.add(
      const BleDiscoveryEvent(
        type: 'attachment_queued',
        attachmentId: attachmentId,
        code: 'wifi_direct_connection_timeout',
      ),
    );
    await tester.pumpAndSettle();
    expect(find.textContaining('at 50%'), findsOneWidget);

    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
    await events.close();
  });

  testWidgets('relay delivery metadata cannot impersonate direct presence', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    final controller = MessengerController(
      platform: _TestPlatform(discoveryStream: events.stream),
    );
    const relayToken = 'relay-token';
    const relayFingerprint = 'RELAY-FINGERPRINT';
    const distantFingerprint = 'DISTANT-RECIPIENT';

    await tester.pump();
    events
      ..add(const BleDiscoveryEvent(type: 'peer_seen', token: relayToken))
      ..add(
        const BleDiscoveryEvent(
          type: 'text_message_delivered',
          token: relayToken,
          fingerprint: distantFingerprint,
          trustState: 'verified',
        ),
      );
    await tester.pump();

    expect(controller.findTokenForFingerprint(distantFingerprint), isNull);

    events.add(
      const BleDiscoveryEvent(
        type: 'identity_proof_verified',
        token: relayToken,
        fingerprint: relayFingerprint,
        trustState: 'verified',
      ),
    );
    await tester.pump();
    expect(controller.findTokenForFingerprint(relayFingerprint), relayToken);

    controller.dispose();
    await events.close();
  });

  testWidgets('foreground queue resumes automatically when Wi-Fi is ready', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    const token = 'nearby-recipient';
    const fingerprint = 'AUTO-RESUME-PEER';
    const attachmentId = '0123456789abcdef0123456789abcdef';
    final platform = _TestPlatform(
      contacts: const [
        RelayContact(
          fingerprint: fingerprint,
          displayName: 'Recipient',
          verified: true,
          ready: true,
        ),
      ],
      attachments: const [
        StoredAttachment(
          attachmentId: attachmentId,
          peerFingerprint: fingerprint,
          direction: 'outgoing',
          status: 'queued',
          kind: 'file',
          fileName: 'resume.bin',
          mimeType: 'application/octet-stream',
          bytes: 1048576,
          chunkCount: 6,
          createdAtMs: 1000,
          attemptCount: 1,
          nextAttemptAtMs: 0,
        ),
      ],
      discoveryStream: events.stream,
    );
    final controller = MessengerController(platform: platform);

    await tester.pump();
    events
      ..add(const BleDiscoveryEvent(type: 'peer_seen', token: token))
      ..add(
        const BleDiscoveryEvent(
          type: 'identity_proof_verified',
          token: token,
          fingerprint: fingerprint,
          trustState: 'verified',
        ),
      );
    await tester.pump();
    await tester.pump();

    expect(platform.sentAttachments, [(token, attachmentId)]);

    controller.dispose();
    await events.close();
  });

  testWidgets('conversation keeps relayed messages in sender sequence', (
    tester,
  ) async {
    const fingerprint = 'ORDERED-PEER';
    final controller = MessengerController(
      platform: _TestPlatform(
        messages: const [
          StoredTextMessage(
            messageId: 'second',
            peerFingerprint: fingerprint,
            direction: 'incoming',
            text: 'Second sent',
            status: 'received',
            transport: 'mesh',
            createdAtMs: 1000,
            attemptCount: 0,
            conversationSequence: 2,
          ),
          StoredTextMessage(
            messageId: 'first',
            peerFingerprint: fingerprint,
            direction: 'incoming',
            text: 'First sent',
            status: 'received',
            transport: 'mesh',
            createdAtMs: 2000,
            attemptCount: 0,
            conversationSequence: 1,
          ),
        ],
      ),
    );

    await tester.pumpWidget(
      MaterialApp(
        home: ConversationScreen(
          controller: controller,
          peerFingerprint: fingerprint,
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      tester.getTopLeft(find.text('First sent')).dy,
      lessThan(tester.getTopLeft(find.text('Second sent')).dy),
    );

    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  testWidgets('temporary attachment radio contention stays quiet', (
    tester,
  ) async {
    final events = StreamController<BleDiscoveryEvent>.broadcast();
    final controller = MessengerController(
      platform: _TestPlatform(
        attachments: const [
          StoredAttachment(
            attachmentId: '00112233445566778899aabbccddeeff',
            peerFingerprint: 'BUSY-PEER',
            direction: 'outgoing',
            status: 'queued',
            kind: 'file',
            fileName: 'queued.bin',
            mimeType: 'application/octet-stream',
            bytes: 1024,
            chunkCount: 1,
            createdAtMs: 1000,
            attemptCount: 1,
          ),
        ],
        discoveryStream: events.stream,
      ),
    );

    await tester.pump();
    events.add(
      const BleDiscoveryEvent(
        type: 'wifi_direct_error',
        code: 'wifi_direct_busy',
        message: 'Another transfer is already running.',
      ),
    );
    await tester.pump();

    expect(controller.statusError, isNull);

    controller.dispose();
    await events.close();
  });

  testWidgets(
    'renders Nearby People cards with human descriptions excluding RSSI, PHY, and token suffixes',
    (tester) async {
      final events = StreamController<BleDiscoveryEvent>.broadcast();
      final platform = _TestPlatform(discoveryStream: events.stream);
      final controller = MessengerController(platform: platform);

      await tester.pumpWidget(
        MaterialApp(home: NearbyPeopleScreen(controller: controller)),
      );
      await tester.pumpAndSettle();

      const token = '0011223344556677';
      events.add(
        const BleDiscoveryEvent(
          type: 'peer_seen',
          token: token,
          rssi: -62,
          primaryPhy: '2M',
        ),
      );
      await tester.pump();

      await tester.scrollUntilVisible(
        find.text('Identify securely'),
        250,
        scrollable: find.byType(Scrollable).last,
      );

      expect(find.text('Unidentified Hypha phone'), findsOneWidget);
      expect(
        find.text('Directly nearby • Identity not yet verified'),
        findsOneWidget,
      );
      expect(find.textContaining('dBm'), findsNothing);
      expect(find.textContaining('PHY'), findsNothing);

      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
      await events.close();
    },
  );

  testWidgets(
    'enforces accessibility semantics and 48dp minimum touch targets on primary actions',
    (tester) async {
      tester.view.physicalSize = const Size(390, 844);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final platform = _TestPlatform(
        messages: const [
          StoredTextMessage(
            messageId: 'msg1',
            peerFingerprint: 'ACC-PEER-1000',
            direction: 'incoming',
            text: 'Test message',
            status: 'received',
            createdAtMs: 1000,
            attemptCount: 0,
          ),
        ],
      );

      await tester.pumpWidget(RelayApp(platform: platform));
      await tester.pumpAndSettle();

      final searchButton = find.byTooltip('Search chats');
      expect(searchButton, findsOneWidget);
      final searchSize = tester.getSize(searchButton);
      expect(searchSize.width, greaterThanOrEqualTo(48.0));
      expect(searchSize.height, greaterThanOrEqualTo(48.0));

      final navigationBar = find.byType(NavigationBar);
      expect(navigationBar, findsOneWidget);
      expect(tester.getSize(navigationBar).height, greaterThanOrEqualTo(48.0));
    },
  );
}
