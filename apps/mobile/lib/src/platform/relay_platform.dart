import 'package:flutter/services.dart';

class BleDiscoveryEvent {
  const BleDiscoveryEvent({
    required this.type,
    this.token,
    this.rssi,
    this.primaryPhy,
    this.code,
    this.message,
    this.elapsedMs,
    this.bytes,
    this.chunks,
    this.mtu,
    this.throughputBps,
    this.fingerprint,
    this.protection,
    this.trustState,
    this.messageId,
    this.attachmentId,
    this.text,
    this.replyToMessageId,
    this.replyPreview,
    this.enabled,
    this.role,
    this.setupMs,
    this.secure,
    this.discovery,
    this.limited,
    this.previousToken,
    this.queued,
    this.automatic,
    this.attemptCount,
    this.retryAtMs,
    this.transferredBytes,
    this.totalBytes,
    this.resumedBytes,
    this.meshChanged,
  });

  factory BleDiscoveryEvent.fromMap(Map<Object?, Object?> map) {
    return BleDiscoveryEvent(
      type: map['type'] as String? ?? 'unknown',
      token: map['token'] as String?,
      rssi: map['rssi'] as int?,
      primaryPhy: map['primaryPhy'] as String?,
      code: map['code'] as String?,
      message: map['message'] as String?,
      elapsedMs: map['elapsedMs'] as int?,
      bytes: map['bytes'] as int?,
      chunks: map['chunks'] as int?,
      mtu: map['mtu'] as int?,
      throughputBps: map['throughputBps'] as int?,
      fingerprint: map['fingerprint'] as String?,
      protection: map['protection'] as String?,
      trustState: map['trustState'] as String?,
      messageId: map['messageId'] as String?,
      attachmentId: map['attachmentId'] as String?,
      text: map['text'] as String?,
      replyToMessageId: map['replyToMessageId'] as String?,
      replyPreview: map['replyPreview'] as String?,
      enabled: map['enabled'] as bool?,
      role: map['role'] as String?,
      setupMs: map['setupMs'] as int?,
      secure: map['secure'] as bool?,
      discovery: map['discovery'] as String?,
      limited: map['limited'] as bool?,
      previousToken: map['previousToken'] as String?,
      queued: map['queued'] as bool?,
      automatic: map['automatic'] as bool?,
      attemptCount: map['attemptCount'] as int?,
      retryAtMs: map['retryAtMs'] as int?,
      transferredBytes: map['transferredBytes'] as int?,
      totalBytes: map['totalBytes'] as int?,
      resumedBytes: map['resumedBytes'] as int?,
      meshChanged: map['meshChanged'] as bool?,
    );
  }

  final String type;
  final String? token;
  final int? rssi;
  final String? primaryPhy;
  final String? code;
  final String? message;
  final int? elapsedMs;
  final int? bytes;
  final int? chunks;
  final int? mtu;
  final int? throughputBps;
  final String? fingerprint;
  final String? protection;
  final String? trustState;
  final String? messageId;
  final String? attachmentId;
  final String? text;
  final String? replyToMessageId;
  final String? replyPreview;
  final bool? enabled;
  final String? role;
  final int? setupMs;
  final bool? secure;
  final String? discovery;
  final bool? limited;
  final String? previousToken;
  final bool? queued;
  final bool? automatic;
  final int? attemptCount;
  final int? retryAtMs;
  final int? transferredBytes;
  final int? totalBytes;
  final int? resumedBytes;
  final bool? meshChanged;
}

class StoredTextMessage {
  const StoredTextMessage({
    required this.messageId,
    required this.peerFingerprint,
    required this.direction,
    required this.text,
    required this.status,
    required this.createdAtMs,
    required this.attemptCount,
    this.transport = 'unknown',
    this.replyToMessageId,
    this.replyPreview,
    this.conversationSequence,
    this.lastAttemptAtMs,
    this.nextAttemptAtMs,
    this.lastErrorCode,
    this.isRead = true,
  });

  factory StoredTextMessage.fromMap(Map<Object?, Object?> map) {
    return StoredTextMessage(
      messageId: map['messageId'] as String? ?? '',
      peerFingerprint: map['peerFingerprint'] as String? ?? '',
      direction: map['direction'] as String? ?? 'unknown',
      text: map['text'] as String? ?? '',
      status: map['status'] as String? ?? 'unknown',
      transport: map['transport'] as String? ?? 'unknown',
      replyToMessageId: map['replyToMessageId'] as String?,
      replyPreview: map['replyPreview'] as String?,
      createdAtMs: map['createdAtMs'] as int? ?? 0,
      attemptCount: map['attemptCount'] as int? ?? 0,
      conversationSequence: map['conversationSequence'] as int?,
      lastAttemptAtMs: map['lastAttemptAtMs'] as int?,
      nextAttemptAtMs: map['nextAttemptAtMs'] as int?,
      lastErrorCode: map['lastErrorCode'] as String?,
      isRead: map['isRead'] as bool? ?? true,
    );
  }

  final String messageId;
  final String peerFingerprint;
  final String direction;
  final String text;
  final String status;
  final String transport;
  final String? replyToMessageId;
  final String? replyPreview;
  final int createdAtMs;
  final int attemptCount;
  final int? conversationSequence;
  final int? lastAttemptAtMs;
  final int? nextAttemptAtMs;
  final String? lastErrorCode;
  final bool isRead;

  StoredTextMessage copyWith({
    String? status,
    bool? isRead,
    int? nextAttemptAtMs,
    bool clearNextAttemptAtMs = false,
    String? lastErrorCode,
    bool clearLastErrorCode = false,
  }) {
    return StoredTextMessage(
      messageId: messageId,
      peerFingerprint: peerFingerprint,
      direction: direction,
      text: text,
      status: status ?? this.status,
      transport: transport,
      replyToMessageId: replyToMessageId,
      replyPreview: replyPreview,
      createdAtMs: createdAtMs,
      attemptCount: attemptCount,
      conversationSequence: conversationSequence,
      lastAttemptAtMs: lastAttemptAtMs,
      nextAttemptAtMs: clearNextAttemptAtMs
          ? null
          : nextAttemptAtMs ?? this.nextAttemptAtMs,
      lastErrorCode: clearLastErrorCode
          ? null
          : lastErrorCode ?? this.lastErrorCode,
      isRead: isRead ?? this.isRead,
    );
  }
}

class StoredMessagePage {
  const StoredMessagePage({
    required this.messages,
    required this.hasMore,
    this.nextBeforeCreatedAtMs,
    this.nextBeforeMessageId,
  });

  factory StoredMessagePage.fromMap(Map<Object?, Object?> map) {
    final rawMessages = map['messages'];
    if (rawMessages is! List<Object?>) {
      throw PlatformException(
        code: 'invalid_message_page',
        message: 'Android returned an invalid saved-message page.',
      );
    }
    final messages = rawMessages
        .map((item) {
          if (item is! Map<Object?, Object?>) {
            throw PlatformException(
              code: 'invalid_message_page',
              message: 'Android returned invalid saved-message data.',
            );
          }
          return StoredTextMessage.fromMap(item);
        })
        .toList(growable: false);
    final hasMore = map['hasMore'] as bool? ?? false;
    final nextCreatedAt = map['nextBeforeCreatedAtMs'] as int?;
    final nextMessageId = map['nextBeforeMessageId'] as String?;
    if (hasMore && (nextCreatedAt == null || nextMessageId == null)) {
      throw PlatformException(
        code: 'invalid_message_page',
        message: 'Android returned an incomplete saved-message cursor.',
      );
    }
    return StoredMessagePage(
      messages: messages,
      hasMore: hasMore,
      nextBeforeCreatedAtMs: nextCreatedAt,
      nextBeforeMessageId: nextMessageId,
    );
  }

  final List<StoredTextMessage> messages;
  final bool hasMore;
  final int? nextBeforeCreatedAtMs;
  final String? nextBeforeMessageId;
}

class StoredConversationSummary {
  const StoredConversationSummary({
    required this.peerFingerprint,
    required this.lastMessage,
    required this.messageCount,
    this.unreadCount = 0,
  });

  factory StoredConversationSummary.fromMap(Map<Object?, Object?> map) {
    final rawLastMessage = map['lastMessage'];
    if (rawLastMessage is! Map<Object?, Object?>) {
      throw PlatformException(
        code: 'invalid_conversation_summary',
        message: 'Android returned an invalid conversation preview.',
      );
    }
    final lastMessage = StoredTextMessage.fromMap(rawLastMessage);
    final fingerprint =
        map['peerFingerprint'] as String? ?? lastMessage.peerFingerprint;
    return StoredConversationSummary(
      peerFingerprint: fingerprint,
      lastMessage: lastMessage,
      messageCount: map['messageCount'] as int? ?? 0,
      unreadCount: map['unreadCount'] as int? ?? 0,
    );
  }

  final String peerFingerprint;
  final StoredTextMessage lastMessage;
  final int messageCount;
  final int unreadCount;
}

class LocalProfile {
  const LocalProfile({required this.displayName, required this.setupComplete});

  factory LocalProfile.fromMap(Map<Object?, Object?> map) {
    return LocalProfile(
      displayName: map['displayName'] as String? ?? 'Hypha user',
      setupComplete: map['setupComplete'] == true,
    );
  }

  final String displayName;
  final bool setupComplete;
}

class StoredAttachment {
  const StoredAttachment({
    required this.attachmentId,
    required this.peerFingerprint,
    required this.direction,
    required this.status,
    required this.kind,
    required this.fileName,
    required this.mimeType,
    required this.bytes,
    required this.chunkCount,
    required this.createdAtMs,
    required this.attemptCount,
    this.nextAttemptAtMs,
    this.lastErrorCode,
  });

  factory StoredAttachment.fromMap(Map<Object?, Object?> map) {
    return StoredAttachment(
      attachmentId: map['attachmentId'] as String? ?? '',
      peerFingerprint: map['peerFingerprint'] as String? ?? '',
      direction: map['direction'] as String? ?? 'unknown',
      status: map['status'] as String? ?? 'unknown',
      kind: map['kind'] as String? ?? 'file',
      fileName: map['fileName'] as String? ?? 'Attachment',
      mimeType: map['mimeType'] as String? ?? 'application/octet-stream',
      bytes: map['bytes'] as int? ?? 0,
      chunkCount: map['chunkCount'] as int? ?? 0,
      createdAtMs: map['createdAtMs'] as int? ?? 0,
      attemptCount: map['attemptCount'] as int? ?? 0,
      nextAttemptAtMs: map['nextAttemptAtMs'] as int?,
      lastErrorCode: map['lastErrorCode'] as String?,
    );
  }

  final String attachmentId;
  final String peerFingerprint;
  final String direction;
  final String status;
  final String kind;
  final String fileName;
  final String mimeType;
  final int bytes;
  final int chunkCount;
  final int createdAtMs;
  final int attemptCount;
  final int? nextAttemptAtMs;
  final String? lastErrorCode;
}

class RelayContact {
  const RelayContact({
    required this.fingerprint,
    required this.displayName,
    required this.verified,
    required this.ready,
    this.relayId,
  });

  factory RelayContact.fromMap(Map<Object?, Object?> map) {
    return RelayContact(
      fingerprint: map['fingerprint'] as String? ?? '',
      displayName: map['displayName'] as String? ?? 'Hypha user',
      relayId: map['relayId'] as String?,
      verified: map['verified'] == true,
      ready: map['ready'] == true,
    );
  }

  final String fingerprint;
  final String displayName;
  final String? relayId;
  final bool verified;
  final bool ready;
}

class MeshQueueResult {
  const MeshQueueResult({
    required this.messageId,
    required this.fingerprint,
    this.createdAtMs,
    this.transport = 'mesh',
    this.replyToMessageId,
    this.replyPreview,
  });

  factory MeshQueueResult.fromMap(Map<Object?, Object?> map) {
    return MeshQueueResult(
      messageId: map['messageId'] as String? ?? '',
      fingerprint: map['fingerprint'] as String? ?? '',
      createdAtMs: map['createdAtMs'] as int?,
      transport: map['transport'] as String? ?? 'mesh',
      replyToMessageId: map['replyToMessageId'] as String?,
      replyPreview: map['replyPreview'] as String?,
    );
  }

  final String messageId;
  final String fingerprint;
  final int? createdAtMs;
  final String transport;
  final String? replyToMessageId;
  final String? replyPreview;

  StoredTextMessage toStoredMessage(String text) => StoredTextMessage(
    messageId: messageId,
    peerFingerprint: fingerprint,
    direction: 'outgoing',
    text: text,
    status: 'queued',
    transport: transport,
    replyToMessageId: replyToMessageId,
    replyPreview: replyPreview,
    createdAtMs: createdAtMs ?? DateTime.now().millisecondsSinceEpoch,
    attemptCount: 0,
  );
}

class RadioCapabilities {
  const RadioCapabilities({
    required this.sdkInt,
    required this.bluetoothPresent,
    required this.bluetoothEnabled,
    required this.multipleAdvertisementSupported,
    required this.le2MPhySupported,
    required this.leCodedPhySupported,
    required this.extendedAdvertisingSupported,
    required this.wifiAwareSupported,
    required this.wifiDirectSupported,
    required this.wifiEnabled,
    required this.wifiDirectPermissionRequired,
    required this.locationServicesEnabled,
    required this.rangingApiAvailable,
    required this.secureCoreReady,
    required this.permissionRequired,
  });

  factory RadioCapabilities.fromMap(Map<Object?, Object?> map) {
    bool flag(String key) => map[key] == true;

    return RadioCapabilities(
      sdkInt: map['sdkInt'] as int? ?? 0,
      bluetoothPresent: flag('bluetoothPresent'),
      bluetoothEnabled: flag('bluetoothEnabled'),
      multipleAdvertisementSupported: flag('multipleAdvertisementSupported'),
      le2MPhySupported: flag('le2MPhySupported'),
      leCodedPhySupported: flag('leCodedPhySupported'),
      extendedAdvertisingSupported: flag('extendedAdvertisingSupported'),
      wifiAwareSupported: flag('wifiAwareSupported'),
      wifiDirectSupported: flag('wifiDirectSupported'),
      wifiEnabled: flag('wifiEnabled'),
      wifiDirectPermissionRequired: flag('wifiDirectPermissionRequired'),
      locationServicesEnabled: flag('locationServicesEnabled'),
      rangingApiAvailable: flag('rangingApiAvailable'),
      secureCoreReady: flag('secureCoreReady'),
      permissionRequired: flag('permissionRequired'),
    );
  }

  final int sdkInt;
  final bool bluetoothPresent;
  final bool bluetoothEnabled;
  final bool multipleAdvertisementSupported;
  final bool le2MPhySupported;
  final bool leCodedPhySupported;
  final bool extendedAdvertisingSupported;
  final bool wifiAwareSupported;
  final bool wifiDirectSupported;
  final bool wifiEnabled;
  final bool wifiDirectPermissionRequired;
  final bool locationServicesEnabled;
  final bool rangingApiAvailable;
  final bool secureCoreReady;
  final bool permissionRequired;
}

class VenueTrustStatus {
  const VenueTrustStatus({
    required this.mode,
    required this.policyState,
    this.version,
    this.venueId,
  });

  const VenueTrustStatus.lab()
    : mode = 'lab',
      policyState = 'lab',
      version = null,
      venueId = null;

  factory VenueTrustStatus.fromMap(Map<Object?, Object?> map) {
    return VenueTrustStatus(
      mode: map['mode'] as String? ?? 'lab',
      policyState: map['policyState'] as String? ?? 'unavailable',
      version: (map['version'] as num?)?.toInt(),
      venueId: map['venueId'] as String?,
    );
  }

  final String mode;
  final String policyState;
  final int? version;
  final String? venueId;

  bool get isManaged => mode == 'managed';
  bool get isReady => isManaged && policyState == 'ready';
}

class VenueInventoryInstallResult {
  const VenueInventoryInstallResult({
    required this.installed,
    required this.status,
    this.reason,
  });

  factory VenueInventoryInstallResult.fromMap(Map<Object?, Object?> map) {
    final rawStatus = map['status'];
    return VenueInventoryInstallResult(
      installed: map['installed'] == true,
      reason: map['reason'] as String?,
      status: rawStatus is Map<Object?, Object?>
          ? VenueTrustStatus.fromMap(rawStatus)
          : const VenueTrustStatus.lab(),
    );
  }

  final bool installed;
  final String? reason;
  final VenueTrustStatus status;
}

class BackgroundRelaySettings {
  const BackgroundRelaySettings({
    required this.backgroundRelayEnabled,
    required this.restartAfterReboot,
    required this.notificationPermissionRequired,
    required this.notificationsEnabled,
    required this.notificationOnboardingDismissed,
    required this.batteryOptimizationExempt,
    required this.manufacturer,
    required this.model,
    required this.sdkInt,
  });

  const BackgroundRelaySettings.defaults()
    : backgroundRelayEnabled = true,
      restartAfterReboot = false,
      notificationPermissionRequired = false,
      notificationsEnabled = true,
      notificationOnboardingDismissed = true,
      batteryOptimizationExempt = false,
      manufacturer = '',
      model = '',
      sdkInt = 0;

  factory BackgroundRelaySettings.fromMap(Map<Object?, Object?> map) {
    bool flag(String key) => map[key] == true;
    return BackgroundRelaySettings(
      backgroundRelayEnabled: flag('backgroundRelayEnabled'),
      restartAfterReboot: flag('restartAfterReboot'),
      notificationPermissionRequired: flag('notificationPermissionRequired'),
      notificationsEnabled: flag('notificationsEnabled'),
      notificationOnboardingDismissed: flag('notificationOnboardingDismissed'),
      batteryOptimizationExempt: flag('batteryOptimizationExempt'),
      manufacturer: map['manufacturer'] as String? ?? '',
      model: map['model'] as String? ?? '',
      sdkInt: map['sdkInt'] as int? ?? 0,
    );
  }

  final bool backgroundRelayEnabled;
  final bool restartAfterReboot;
  final bool notificationPermissionRequired;
  final bool notificationsEnabled;
  final bool notificationOnboardingDismissed;
  final bool batteryOptimizationExempt;
  final String manufacturer;
  final String model;
  final int sdkInt;
}

abstract interface class RelayPlatformApi {
  Stream<BleDiscoveryEvent> get bleDiscoveryEvents;

  Future<RadioCapabilities> probeRadioCapabilities();

  Future<VenueTrustStatus> getVenueTrustStatus();

  Future<VenueInventoryInstallResult?> pickVenueInventory({
    required bool allowAuthorityBootstrap,
  });

  Future<bool> resetVenueTrust(String confirmation);

  Future<bool> requestRadioPermissions();

  Future<bool> requestWifiDirectPermissions();

  Future<BackgroundRelaySettings> getBackgroundSettings();

  Future<BackgroundRelaySettings> setBackgroundRelayEnabled(bool enabled);

  Future<BackgroundRelaySettings> setRestartAfterReboot(bool enabled);

  Future<bool> requestNotificationPermission();

  Future<BackgroundRelaySettings> dismissNotificationOnboarding();

  Future<void> openNotificationSettings();

  Future<void> openBatterySettings();

  Future<StoredAttachment?> pickAttachment(String peerFingerprint, String kind);

  Future<void> sendAttachment(String blePeerToken, String attachmentId);

  Future<void> prepareCourierAttachment(String attachmentId);

  Future<void> pauseAttachment(String attachmentId);

  Future<void> cancelAttachment(String attachmentId);

  Future<List<StoredAttachment>> getStoredAttachments();

  Future<Uint8List?> loadAttachmentPreview(String attachmentId);

  Future<void> openAttachment(String attachmentId);

  Future<String> startBleDiscovery();

  Future<void> stopBleDiscovery();

  Future<void> sendEngineeringTransfer(String peerToken);

  Future<void> sendTamperedEngineeringTransfer(String peerToken);

  Future<void> identifyPeer(String peerToken);

  Future<void> markPeerVerified(String peerToken);

  Future<StoredTextMessage> sendTextMessage(
    String peerToken,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  });

  Future<void> retryTextMessage(String peerToken, String messageId);

  Future<MeshQueueResult> queueMeshText(
    String peerFingerprint,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  });

  Future<MeshQueueResult> queueLastCopyDiagnosticText(
    String peerFingerprint,
    String text,
  );

  Future<void> syncMesh(String peerToken);

  Future<List<RelayContact>> getRelayContacts();

  Future<String> getLocalDisplayName();

  Future<LocalProfile> getLocalProfile();

  Future<String> updateDisplayName(String displayName);

  Future<void> sendWifiTextMessage(
    String blePeerToken,
    String wifiPeerToken,
    String text,
  );

  Future<List<StoredTextMessage>> getStoredMessages();

  Future<StoredMessagePage> getStoredMessagePage(
    String peerFingerprint, {
    int? beforeCreatedAtMs,
    String? beforeMessageId,
    int limit = 40,
  });

  Future<List<StoredConversationSummary>> getConversationSummaries();

  Future<int> markConversationRead(String peerFingerprint);

  Future<String?> consumePendingConversationOpen();

  Future<String> startWifiDirect();

  Future<void> stopWifiDirect();

  Future<void> runWifiDirectSpeedTest(String peerToken);

  Future<void> authorizeWifiUpgrade(String blePeerToken, String wifiPeerToken);
}

class RelayPlatform implements RelayPlatformApi {
  const RelayPlatform();

  static const _channel = MethodChannel('app.projectrelay/radio');
  static const _events = EventChannel('app.projectrelay/radio_events');

  @override
  Stream<BleDiscoveryEvent> get bleDiscoveryEvents {
    return _events.receiveBroadcastStream().map((event) {
      if (event is! Map<Object?, Object?>) {
        throw PlatformException(
          code: 'invalid_event',
          message: 'Android returned an invalid discovery event.',
        );
      }
      return BleDiscoveryEvent.fromMap(event);
    });
  }

  @override
  Future<RadioCapabilities> probeRadioCapabilities() async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'getRadioCapabilities',
    );
    if (response == null) {
      throw PlatformException(
        code: 'empty_response',
        message: 'Android returned no radio capability information.',
      );
    }
    return RadioCapabilities.fromMap(response);
  }

  @override
  Future<VenueTrustStatus> getVenueTrustStatus() async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'getVenueTrustStatus',
    );
    if (response == null) {
      throw PlatformException(
        code: 'empty_venue_trust_status',
        message: 'Android returned no venue trust status.',
      );
    }
    return VenueTrustStatus.fromMap(response);
  }

  @override
  Future<VenueInventoryInstallResult?> pickVenueInventory({
    required bool allowAuthorityBootstrap,
  }) async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'pickVenueInventory',
      {'allowAuthorityBootstrap': allowAuthorityBootstrap},
    );
    return response == null
        ? null
        : VenueInventoryInstallResult.fromMap(response);
  }

  @override
  Future<bool> resetVenueTrust(String confirmation) async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'resetVenueTrust',
      {'confirmation': confirmation},
    );
    return response?['reset'] == true;
  }

  @override
  Future<bool> requestRadioPermissions() async {
    return await _channel.invokeMethod<bool>('requestRadioPermissions') ??
        false;
  }

  @override
  Future<bool> requestWifiDirectPermissions() async {
    return await _channel.invokeMethod<bool>('requestWifiDirectPermissions') ??
        false;
  }

  @override
  Future<BackgroundRelaySettings> getBackgroundSettings() async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'getBackgroundSettings',
    );
    if (response == null) {
      throw PlatformException(
        code: 'empty_background_settings',
        message: 'Android returned no background relay settings.',
      );
    }
    return BackgroundRelaySettings.fromMap(response);
  }

  @override
  Future<BackgroundRelaySettings> setBackgroundRelayEnabled(
    bool enabled,
  ) async {
    return _updateBackgroundSetting('setBackgroundRelayEnabled', enabled);
  }

  @override
  Future<BackgroundRelaySettings> setRestartAfterReboot(bool enabled) async {
    return _updateBackgroundSetting('setRestartAfterReboot', enabled);
  }

  Future<BackgroundRelaySettings> _updateBackgroundSetting(
    String method,
    bool enabled,
  ) async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(method, {
      'enabled': enabled,
    });
    if (response == null) {
      throw PlatformException(
        code: 'empty_background_settings',
        message: 'Android did not confirm the background relay setting.',
      );
    }
    return BackgroundRelaySettings.fromMap(response);
  }

  @override
  Future<bool> requestNotificationPermission() async {
    return await _channel.invokeMethod<bool>('requestNotificationPermission') ??
        false;
  }

  @override
  Future<BackgroundRelaySettings> dismissNotificationOnboarding() async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'dismissNotificationOnboarding',
    );
    if (response == null) {
      throw PlatformException(
        code: 'empty_background_settings',
        message: 'Android did not save the notification choice.',
      );
    }
    return BackgroundRelaySettings.fromMap(response);
  }

  @override
  Future<void> openNotificationSettings() async {
    await _channel.invokeMethod<void>('openNotificationSettings');
  }

  @override
  Future<void> openBatterySettings() async {
    await _channel.invokeMethod<void>('openBatterySettings');
  }

  @override
  Future<StoredAttachment?> pickAttachment(
    String peerFingerprint,
    String kind,
  ) async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'pickAttachment',
      {'fingerprint': peerFingerprint, 'kind': kind},
    );
    return response == null ? null : StoredAttachment.fromMap(response);
  }

  @override
  Future<void> sendAttachment(String blePeerToken, String attachmentId) async {
    await _channel.invokeMethod<void>('sendAttachment', {
      'bleToken': blePeerToken,
      'attachmentId': attachmentId,
    });
  }

  @override
  Future<void> prepareCourierAttachment(String attachmentId) async {
    await _channel.invokeMethod<void>('prepareCourierAttachment', {
      'attachmentId': attachmentId,
    });
  }

  @override
  Future<void> pauseAttachment(String attachmentId) async {
    await _channel.invokeMethod<void>('pauseAttachment', {
      'attachmentId': attachmentId,
    });
  }

  @override
  Future<void> cancelAttachment(String attachmentId) async {
    await _channel.invokeMethod<void>('cancelAttachment', {
      'attachmentId': attachmentId,
    });
  }

  @override
  Future<List<StoredAttachment>> getStoredAttachments() async {
    final response = await _channel.invokeListMethod<Object?>(
      'getStoredAttachments',
    );
    return (response ?? const <Object?>[])
        .map((item) {
          if (item is! Map<Object?, Object?>) {
            throw PlatformException(
              code: 'invalid_attachment_store',
              message: 'Android returned invalid attachment data.',
            );
          }
          return StoredAttachment.fromMap(item);
        })
        .toList(growable: false);
  }

  @override
  Future<Uint8List?> loadAttachmentPreview(String attachmentId) =>
      _channel.invokeMethod<Uint8List>('loadAttachmentPreview', {
        'attachmentId': attachmentId,
      });

  @override
  Future<void> openAttachment(String attachmentId) async {
    await _channel.invokeMethod<void>('openAttachment', {
      'attachmentId': attachmentId,
    });
  }

  @override
  Future<String> startBleDiscovery() async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'startBleDiscovery',
    );
    final token = response?['token'] as String?;
    if (token == null || token.isEmpty) {
      throw PlatformException(
        code: 'missing_token',
        message: 'Android started discovery without a session token.',
      );
    }
    return token;
  }

  @override
  Future<void> stopBleDiscovery() async {
    await _channel.invokeMethod<void>('stopBleDiscovery');
  }

  @override
  Future<void> sendEngineeringTransfer(String peerToken) async {
    await _channel.invokeMethod<void>('sendEngineeringTransfer', {
      'token': peerToken,
    });
  }

  @override
  Future<void> sendTamperedEngineeringTransfer(String peerToken) async {
    await _channel.invokeMethod<void>('sendTamperedEngineeringTransfer', {
      'token': peerToken,
    });
  }

  @override
  Future<void> identifyPeer(String peerToken) async {
    await _channel.invokeMethod<void>('identifyPeer', {'token': peerToken});
  }

  @override
  Future<void> markPeerVerified(String peerToken) async {
    await _channel.invokeMethod<void>('markPeerVerified', {'token': peerToken});
  }

  @override
  Future<StoredTextMessage> sendTextMessage(
    String peerToken,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  }) async {
    final response = await _channel
        .invokeMapMethod<Object?, Object?>('sendTextMessage', {
          'token': peerToken,
          'text': text,
          'replyToMessageId': ?replyToMessageId,
          'replyPreview': ?replyPreview,
        });
    if (response == null) {
      throw PlatformException(
        code: 'empty_text_queue_result',
        message: 'Android did not return the durably queued message.',
      );
    }
    return StoredTextMessage.fromMap(response);
  }

  @override
  Future<void> retryTextMessage(String peerToken, String messageId) async {
    await _channel.invokeMethod<void>('retryTextMessage', {
      'token': peerToken,
      'messageId': messageId,
    });
  }

  @override
  Future<MeshQueueResult> queueMeshText(
    String peerFingerprint,
    String text, {
    String? replyToMessageId,
    String? replyPreview,
  }) async {
    final response = await _channel
        .invokeMapMethod<Object?, Object?>('queueMeshText', {
          'fingerprint': peerFingerprint,
          'text': text,
          'replyToMessageId': ?replyToMessageId,
          'replyPreview': ?replyPreview,
        });
    if (response == null) {
      throw PlatformException(
        code: 'empty_mesh_queue_result',
        message: 'Android did not return the queued mesh message.',
      );
    }
    return MeshQueueResult.fromMap(response);
  }

  @override
  Future<MeshQueueResult> queueLastCopyDiagnosticText(
    String peerFingerprint,
    String text,
  ) async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'queueLastCopyDiagnosticText',
      {'fingerprint': peerFingerprint, 'text': text},
    );
    if (response == null) {
      throw PlatformException(
        code: 'empty_last_copy_queue_result',
        message: 'Android did not return the last-copy diagnostic message.',
      );
    }
    return MeshQueueResult.fromMap(response);
  }

  @override
  Future<void> syncMesh(String peerToken) async {
    await _channel.invokeMethod<void>('syncMesh', {'token': peerToken});
  }

  @override
  Future<List<RelayContact>> getRelayContacts() async {
    final response = await _channel.invokeListMethod<Object?>(
      'getRelayContacts',
    );
    return (response ?? const <Object?>[])
        .map((item) {
          if (item is! Map<Object?, Object?>) {
            throw PlatformException(
              code: 'invalid_contact_store',
              message: 'Android returned invalid Hypha contact data.',
            );
          }
          return RelayContact.fromMap(item);
        })
        .toList(growable: false);
  }

  @override
  Future<String> getLocalDisplayName() async {
    return (await getLocalProfile()).displayName;
  }

  @override
  Future<LocalProfile> getLocalProfile() async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'getLocalProfile',
    );
    if (response == null) {
      throw PlatformException(
        code: 'empty_local_profile',
        message: 'Android returned no local Hypha profile.',
      );
    }
    return LocalProfile.fromMap(response);
  }

  @override
  Future<String> updateDisplayName(String displayName) async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'updateDisplayName',
      {'displayName': displayName},
    );
    return response?['displayName'] as String? ?? displayName.trim();
  }

  @override
  Future<void> sendWifiTextMessage(
    String blePeerToken,
    String wifiPeerToken,
    String text,
  ) async {
    await _channel.invokeMethod<void>('sendWifiTextMessage', {
      'bleToken': blePeerToken,
      'wifiToken': wifiPeerToken,
      'text': text,
    });
  }

  @override
  Future<List<StoredTextMessage>> getStoredMessages() async {
    final response = await _channel.invokeListMethod<Object?>(
      'getStoredMessages',
    );
    return (response ?? const <Object?>[])
        .map((item) {
          if (item is! Map<Object?, Object?>) {
            throw PlatformException(
              code: 'invalid_message_store',
              message: 'Android returned invalid saved message data.',
            );
          }
          return StoredTextMessage.fromMap(item);
        })
        .toList(growable: false);
  }

  @override
  Future<StoredMessagePage> getStoredMessagePage(
    String peerFingerprint, {
    int? beforeCreatedAtMs,
    String? beforeMessageId,
    int limit = 40,
  }) async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'getStoredMessagePage',
      <String, Object?>{
        'fingerprint': peerFingerprint,
        'limit': limit,
        'beforeCreatedAtMs': ?beforeCreatedAtMs,
        'beforeMessageId': ?beforeMessageId,
      },
    );
    if (response == null) {
      throw PlatformException(
        code: 'empty_message_page',
        message: 'Android returned no saved-message page.',
      );
    }
    return StoredMessagePage.fromMap(response);
  }

  @override
  Future<List<StoredConversationSummary>> getConversationSummaries() async {
    final response = await _channel.invokeListMethod<Object?>(
      'getConversationSummaries',
    );
    return (response ?? const <Object?>[])
        .map((item) {
          if (item is! Map<Object?, Object?>) {
            throw PlatformException(
              code: 'invalid_conversation_summary',
              message: 'Android returned invalid conversation preview data.',
            );
          }
          return StoredConversationSummary.fromMap(item);
        })
        .toList(growable: false);
  }

  @override
  Future<int> markConversationRead(String peerFingerprint) async {
    return await _channel.invokeMethod<int>('markConversationRead', {
          'fingerprint': peerFingerprint,
        }) ??
        0;
  }

  @override
  Future<String?> consumePendingConversationOpen() async {
    return _channel.invokeMethod<String>('consumePendingConversationOpen');
  }

  @override
  Future<String> startWifiDirect() async {
    final response = await _channel.invokeMapMethod<Object?, Object?>(
      'startWifiDirect',
    );
    final token = response?['token'] as String?;
    if (token == null || token.isEmpty) {
      throw PlatformException(
        code: 'missing_wifi_token',
        message: 'Android started Wi-Fi Direct without a session token.',
      );
    }
    return token;
  }

  @override
  Future<void> stopWifiDirect() async {
    await _channel.invokeMethod<void>('stopWifiDirect');
  }

  @override
  Future<void> runWifiDirectSpeedTest(String peerToken) async {
    await _channel.invokeMethod<void>('runWifiDirectSpeedTest', {
      'token': peerToken,
    });
  }

  @override
  Future<void> authorizeWifiUpgrade(
    String blePeerToken,
    String wifiPeerToken,
  ) async {
    await _channel.invokeMethod<void>('authorizeWifiUpgrade', {
      'bleToken': blePeerToken,
      'wifiToken': wifiPeerToken,
    });
  }
}
