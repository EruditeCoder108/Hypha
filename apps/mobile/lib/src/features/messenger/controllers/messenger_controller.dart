import 'dart:async';
import 'dart:collection';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:relay_mobile/src/features/messenger/models/conversation_summary.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

enum MessageSendOutcome { delivered, queued, failed }

enum AttachmentSendOutcome { started, queued, cancelled, failed }

enum OfflineDeliveryState {
  checking,
  profileRequired,
  off,
  permissionRequired,
  bluetoothOff,
  active,
  activeButBatteryLimited,
}

enum PrivateNotificationState { enabled, permissionRequired, disabledInSystem }

enum FastAttachmentState {
  checking,
  unsupported,
  permissionRequired,
  wifiOff,
  locationOff,
  ready,
}

class AttachmentTransferProgress {
  const AttachmentTransferProgress({
    required this.phase,
    required this.transferredBytes,
    required this.totalBytes,
    required this.resumedBytes,
    required this.throughputBps,
  });

  final String phase;
  final int transferredBytes;
  final int totalBytes;
  final int resumedBytes;
  final int throughputBps;

  double get fraction =>
      totalBytes <= 0 ? 0 : (transferredBytes / totalBytes).clamp(0.0, 1.0);

  int get percent => (fraction * 100).round();

  AttachmentTransferProgress withPhase(String value) =>
      AttachmentTransferProgress(
        phase: value,
        transferredBytes: transferredBytes,
        totalBytes: totalBytes,
        resumedBytes: resumedBytes,
        throughputBps: throughputBps,
      );
}

/// Coordinates the product UI with the native background-capable radio engine.
///
/// Nearby BLE tokens are deliberately treated as short-lived addresses. A
/// token becomes usable for messaging only after the authenticated identity
/// handshake maps it to a stable, locally verified safety fingerprint.
class MessengerController extends ChangeNotifier {
  MessengerController({required this.platform}) {
    _subscription = platform.bleDiscoveryEvents.listen(
      _onDiscoveryEvent,
      onError: (Object error) {
        _statusError = _friendlyError(error: error);
        _notify();
      },
    );
    _peerPruneTimer = Timer.periodic(
      const Duration(seconds: 2),
      (_) => _removeStalePeers(),
    );
    _attachmentRetryTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => unawaited(_autoResumeAttachment()),
    );
    unawaited(loadStoredMessages());
    unawaited(loadStoredAttachments());
    unawaited(loadContacts());
    unawaited(_loadProfileAndStartDiscovery());
    unawaited(loadBackgroundSettings());
    unawaited(loadRadioCapabilities());
    unawaited(loadVenueTrustStatus());
    unawaited(loadPendingConversationOpen());
  }

  final RelayPlatformApi platform;
  StreamSubscription<BleDiscoveryEvent>? _subscription;
  Timer? _peerPruneTimer;
  Timer? _attachmentRetryTimer;
  Timer? _busyActionTimer;
  Future<void>? _messageReloadFuture;
  bool _messageReloadRequested = false;

  List<StoredTextMessage> _storedMessages = const [];
  List<ConversationSummary> _conversationSummaries = const [];
  final Map<String, _ConversationHistoryState> _historyByPeer = {};
  List<StoredAttachment> _storedAttachments = const [];
  List<RelayContact> _contacts = const [];
  final Map<String, BleDiscoveryEvent> _nearbyPeers = {};
  final Map<String, DateTime> _lastSeenByToken = {};
  final Map<String, String> _fingerprintByToken = {};
  final Map<String, String> _protectionByToken = {};
  final Map<String, String> _trustStateByToken = {};
  final Map<String, String> _statusByToken = {};
  final Map<String, String> _attachmentIssueById = {};
  final Map<String, AttachmentTransferProgress> _attachmentProgressById = {};
  final LinkedHashMap<String, Future<Uint8List?>> _attachmentPreviewById =
      LinkedHashMap();

  bool _isDiscovering = false;
  bool _isRadioRecovering = false;
  bool _isChangingDiscovery = false;
  bool _isChangingBackgroundSettings = false;
  bool _isChangingAttachmentSettings = false;
  bool _isChangingVenueTrust = false;
  bool _isSendingAttachment = false;
  bool _attachmentRetryRunning = false;
  String? _attachmentActionId;
  bool _disposed = false;
  String? _localToken;
  String? _statusError;
  String? _busyToken;
  String? _manualTextActionToken;
  bool? _wifiDirectEnabled;
  String _displayName = 'Hypha user';
  bool _profileLoaded = false;
  bool _profileSetupComplete = false;
  bool _isSavingProfile = false;
  String? _activeConversationFingerprint;
  String? _pendingConversationOpen;
  BackgroundRelaySettings _backgroundSettings =
      const BackgroundRelaySettings.defaults();
  RadioCapabilities? _radioCapabilities;
  VenueTrustStatus _venueTrustStatus = const VenueTrustStatus.lab();

  List<StoredTextMessage> get storedMessages => _storedMessages;
  List<StoredAttachment> get storedAttachments => _storedAttachments;
  List<RelayContact> get contacts => _contacts;
  List<ConversationSummary> get conversationSummaries {
    final contactNames = <String, String>{
      for (final contact in _contacts) contact.fingerprint: contact.displayName,
    };
    return List.unmodifiable(
      _conversationSummaries.map(
        (summary) => summary.copyWith(
          contactName: contactNames[summary.peerFingerprint],
        ),
      ),
    );
  }

  bool isConversationHistoryLoading(String peerFingerprint) =>
      _historyByPeer[peerFingerprint]?.loadingInitial == true;

  bool isLoadingOlderMessages(String peerFingerprint) =>
      _historyByPeer[peerFingerprint]?.loadingOlder == true;

  bool hasOlderMessages(String peerFingerprint) =>
      _historyByPeer[peerFingerprint]?.hasMore == true;

  String contactLabel(String fingerprint) {
    for (final contact in _contacts) {
      if (contact.fingerprint == fingerprint) return contact.displayName;
    }
    final suffix = fingerprint.length <= 4
        ? fingerprint
        : fingerprint.substring(fingerprint.length - 4);
    return 'Hypha device • $suffix';
  }

  Map<String, BleDiscoveryEvent> get nearbyPeers =>
      Map.unmodifiable(_nearbyPeers);
  Map<String, String> get fingerprintByToken =>
      Map.unmodifiable(_fingerprintByToken);
  Map<String, String> get protectionByToken =>
      Map.unmodifiable(_protectionByToken);
  Map<String, String> get trustStateByToken =>
      Map.unmodifiable(_trustStateByToken);
  Map<String, String> get statusByToken => Map.unmodifiable(_statusByToken);

  bool get isDiscovering => _isDiscovering;
  bool get isRadioRecovering => _isRadioRecovering;
  bool get isChangingDiscovery => _isChangingDiscovery;
  bool get isChangingBackgroundSettings => _isChangingBackgroundSettings;
  bool get isChangingAttachmentSettings => _isChangingAttachmentSettings;
  bool get isSendingAttachment => _isSendingAttachment;
  bool isAttachmentActionPending(String attachmentId) =>
      _attachmentActionId == attachmentId;
  AttachmentTransferProgress? attachmentProgress(String attachmentId) =>
      _attachmentProgressById[attachmentId];

  bool attachmentShowsProgress(String attachmentId) =>
      _attachmentProgressById.containsKey(attachmentId);

  String attachmentStatusText(StoredAttachment attachment) {
    if (attachment.status == 'delivered') return 'Delivered';
    if (attachment.status == 'ready') return 'Ready';
    if (attachment.lastErrorCode == 'user_cancelled') return 'Cancelled';
    final progress = _attachmentProgressById[attachment.attachmentId];
    final progressSuffix = progress == null || progress.transferredBytes <= 0
        ? ''
        : ' at ${progress.percent}%';
    if (attachment.lastErrorCode == 'user_paused') {
      return 'Paused$progressSuffix';
    }

    final wifiUnavailable =
        _wifiDirectEnabled == false ||
        (_wifiDirectEnabled == null &&
            _radioCapabilities?.wifiEnabled == false);
    if (wifiUnavailable) {
      return 'Wi-Fi Direct unavailable$progressSuffix - turn Wi-Fi on and hotspot off';
    }
    if (progress?.phase == 'preparing') {
      return progressSuffix.isEmpty
          ? 'Preparing secure Wi-Fi link...'
          : 'Resuming$progressSuffix - preparing secure link';
    }
    if (progress?.phase == 'sending') {
      return _activeAttachmentStatus('Sending', progress!);
    }
    if (progress?.phase == 'receiving') {
      return _activeAttachmentStatus('Receiving', progress!);
    }
    final code =
        _attachmentIssueById[attachment.attachmentId] ??
        attachment.lastErrorCode;
    return switch (code) {
      'wifi_off' =>
        'Wi-Fi Direct unavailable$progressSuffix - turn Wi-Fi on and hotspot off',
      'wifi_direct_radio_busy' =>
        'Wi-Fi radio busy$progressSuffix - turn hotspot off',
      'wifi_permission_required' ||
      'permission_required_wifi' => 'Nearby Wi-Fi permission required',
      'location_off' => 'Location is off - turn it on to continue',
      'wifi_peer_stale' || 'wifi_direct_connection_timeout' =>
        'Waiting for nearby phone$progressSuffix - retrying automatically',
      _ when attachment.status == 'transferring' =>
        attachment.direction == 'outgoing'
            ? 'Sending securely...'
            : 'Receiving securely...',
      _ => 'Waiting$progressSuffix - retrying automatically',
    };
  }

  String _activeAttachmentStatus(
    String action,
    AttachmentTransferProgress progress,
  ) {
    final rate = progress.throughputBps <= 0
        ? ''
        : ' - ${_formatTransferRate(progress.throughputBps)}';
    return '$action ${progress.percent}%$rate';
  }

  String _formatTransferRate(int bytesPerSecond) {
    if (bytesPerSecond >= 1024 * 1024) {
      return '${(bytesPerSecond / (1024 * 1024)).toStringAsFixed(1)} MB/s';
    }
    if (bytesPerSecond >= 1024) {
      return '${(bytesPerSecond / 1024).round()} KB/s';
    }
    return '$bytesPerSecond B/s';
  }

  void _updateAttachmentProgress(
    BleDiscoveryEvent event, {
    required String phase,
  }) {
    final id = event.attachmentId;
    if (id == null) return;
    final previous = _attachmentProgressById[id];
    final total = event.totalBytes ?? event.bytes ?? previous?.totalBytes ?? 0;
    _attachmentProgressById[id] = AttachmentTransferProgress(
      phase: phase,
      transferredBytes:
          event.transferredBytes ?? previous?.transferredBytes ?? 0,
      totalBytes: total,
      resumedBytes: event.resumedBytes ?? previous?.resumedBytes ?? 0,
      throughputBps: event.throughputBps ?? previous?.throughputBps ?? 0,
    );
  }

  void _markAttachmentProgressWaiting(
    String? attachmentId, {
    String phase = 'waiting',
  }) {
    if (attachmentId == null) return;
    final progress = _attachmentProgressById[attachmentId];
    if (progress != null) {
      _attachmentProgressById[attachmentId] = progress.withPhase(phase);
    }
  }

  bool attachmentNeedsAttention(StoredAttachment attachment) {
    if (attachment.status != 'queued' ||
        attachment.lastErrorCode == 'user_cancelled' ||
        attachment.lastErrorCode == 'user_paused') {
      return false;
    }
    if (_wifiDirectEnabled == false ||
        (_wifiDirectEnabled == null &&
            _radioCapabilities?.wifiEnabled == false)) {
      return true;
    }
    final code =
        _attachmentIssueById[attachment.attachmentId] ??
        attachment.lastErrorCode;
    return _inlineAttachmentIssueCodes.contains(code);
  }

  String? get localToken => _localToken;
  String? get statusError => _statusError;
  String? get busyToken => _busyToken;
  String get displayName => _displayName;
  bool get profileLoaded => _profileLoaded;
  bool get profileSetupComplete => _profileSetupComplete;
  bool get needsProfileSetup => _profileLoaded && !_profileSetupComplete;
  bool get isSavingProfile => _isSavingProfile;
  String? get pendingConversationOpen => _pendingConversationOpen;
  BackgroundRelaySettings get backgroundSettings => _backgroundSettings;
  RadioCapabilities? get radioCapabilities => _radioCapabilities;
  VenueTrustStatus get venueTrustStatus => _venueTrustStatus;
  bool get isChangingVenueTrust => _isChangingVenueTrust;
  bool get fastAttachmentsReady {
    final capabilities = _radioCapabilities;
    if (capabilities == null) return false;
    final locationReady =
        capabilities.sdkInt >= 33 || capabilities.locationServicesEnabled;
    return capabilities.wifiDirectSupported &&
        capabilities.wifiEnabled &&
        !capabilities.wifiDirectPermissionRequired &&
        locationReady;
  }

  OfflineDeliveryState get offlineDeliveryState {
    if (!_profileLoaded || _radioCapabilities == null) {
      return OfflineDeliveryState.checking;
    }
    if (!_profileSetupComplete) return OfflineDeliveryState.profileRequired;
    if (!_backgroundSettings.backgroundRelayEnabled) {
      return OfflineDeliveryState.off;
    }
    final capabilities = _radioCapabilities!;
    if (capabilities.permissionRequired) {
      return OfflineDeliveryState.permissionRequired;
    }
    if (!capabilities.bluetoothEnabled) {
      return OfflineDeliveryState.bluetoothOff;
    }
    return _backgroundSettings.batteryOptimizationExempt
        ? OfflineDeliveryState.active
        : OfflineDeliveryState.activeButBatteryLimited;
  }

  PrivateNotificationState get privateNotificationState {
    if (_backgroundSettings.notificationsEnabled) {
      return PrivateNotificationState.enabled;
    }
    return _backgroundSettings.notificationPermissionRequired
        ? PrivateNotificationState.permissionRequired
        : PrivateNotificationState.disabledInSystem;
  }

  FastAttachmentState get fastAttachmentState {
    final capabilities = _radioCapabilities;
    if (capabilities == null) return FastAttachmentState.checking;
    if (!capabilities.wifiDirectSupported) {
      return FastAttachmentState.unsupported;
    }
    if (capabilities.wifiDirectPermissionRequired) {
      return FastAttachmentState.permissionRequired;
    }
    if (!capabilities.wifiEnabled) return FastAttachmentState.wifiOff;
    if (capabilities.sdkInt < 33 && !capabilities.locationServicesEnabled) {
      return FastAttachmentState.locationOff;
    }
    return FastAttachmentState.ready;
  }

  bool get showNotificationOnboarding =>
      _backgroundSettings.notificationPermissionRequired &&
      !_backgroundSettings.notificationOnboardingDismissed;

  @override
  void dispose() {
    _disposed = true;
    _peerPruneTimer?.cancel();
    _attachmentRetryTimer?.cancel();
    _busyActionTimer?.cancel();
    unawaited(_subscription?.cancel());
    // The Android foreground service owns discovery after the UI detaches, so
    // disposing a screen/controller must not silently disable offline delivery.
    super.dispose();
  }

  Future<void> loadStoredMessages() {
    _messageReloadRequested = true;
    final activeReload = _messageReloadFuture;
    if (activeReload != null) return activeReload;

    final reload = _drainStoredMessageReloads();
    _messageReloadFuture = reload;
    return reload;
  }

  Future<void> _drainStoredMessageReloads() async {
    try {
      // Radio sync can emit several events for one logical change. Collapse
      // those requests into one preview refresh plus bounded windows for chats
      // the user has actually opened. This prevents parallel decryptions and
      // keeps cold startup independent of lifetime history size.
      while (_messageReloadRequested && !_disposed) {
        _messageReloadRequested = false;
        final reloadStopwatch = Stopwatch()..start();
        final summaries = await platform.getConversationSummaries();
        final refreshed = <String, StoredMessagePage>{};
        for (final entry in _historyByPeer.entries) {
          final state = entry.value;
          if (!state.initialized || state.activeLoad != null) continue;
          refreshed[entry.key] = await platform.getStoredMessagePage(
            entry.key,
            limit: _historyPageSize,
          );
        }
        debugPrint(
          'HyphaTextTiming stage=flutter_history_loaded '
          'elapsed_ms=${reloadStopwatch.elapsedMilliseconds} '
          'previews=${summaries.length} open_chats=${refreshed.length}',
        );
        _conversationSummaries = List.unmodifiable(
          summaries.map(ConversationSummary.fromStored),
        );
        for (final entry in refreshed.entries) {
          // Keep deliberately loaded older pages in memory while reconciling
          // the newest canonical page after a radio/background event.
          _mergeConversationMessages(entry.key, entry.value.messages);
        }
        _sortConversationSummaries();
        _notify();
      }
    } on Object catch (error) {
      _messageReloadRequested = false;
      _statusError = _friendlyError(error: error);
      _notify();
    } finally {
      _messageReloadFuture = null;
    }
  }

  Future<void> loadInitialConversationHistory(
    String peerFingerprint, {
    bool force = false,
  }) {
    final state = _historyByPeer.putIfAbsent(
      peerFingerprint,
      _ConversationHistoryState.new,
    );
    if (state.initialized && !force) return Future.value();
    final active = state.activeLoad;
    if (active != null) return active;
    late final Future<void> load;
    load = _loadInitialConversationHistory(peerFingerprint, state).whenComplete(
      () {
        if (identical(state.activeLoad, load)) state.activeLoad = null;
      },
    );
    state.activeLoad = load;
    return load;
  }

  Future<void> _loadInitialConversationHistory(
    String peerFingerprint,
    _ConversationHistoryState state,
  ) async {
    state.loadingInitial = true;
    _notify();
    try {
      final pageStopwatch = Stopwatch()..start();
      final page = await platform.getStoredMessagePage(
        peerFingerprint,
        limit: _historyPageSize,
      );
      debugPrint(
        'HyphaTextTiming stage=flutter_history_page_loaded '
        'elapsed_ms=${pageStopwatch.elapsedMilliseconds} '
        'count=${page.messages.length} initial=true',
      );
      _replaceConversationMessages(peerFingerprint, page.messages);
      state.apply(page);
      state.initialized = true;
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      state.loadingInitial = false;
      _notify();
    }
  }

  Future<void> loadOlderMessages(String peerFingerprint) async {
    final state = _historyByPeer.putIfAbsent(
      peerFingerprint,
      _ConversationHistoryState.new,
    );
    if (!state.initialized) {
      await loadInitialConversationHistory(peerFingerprint);
      return;
    }
    final active = state.activeLoad;
    if (active != null) return active;
    if (!state.hasMore) return;
    late final Future<void> load;
    load = _loadOlderMessages(peerFingerprint, state).whenComplete(() {
      if (identical(state.activeLoad, load)) state.activeLoad = null;
    });
    state.activeLoad = load;
    return load;
  }

  Future<void> setConversationVisible(
    String peerFingerprint, {
    required bool visible,
  }) async {
    if (visible) {
      _activeConversationFingerprint = peerFingerprint;
      await markConversationRead(peerFingerprint);
    } else if (_activeConversationFingerprint == peerFingerprint) {
      _activeConversationFingerprint = null;
    }
  }

  Future<void> markConversationRead(String peerFingerprint) async {
    try {
      await platform.markConversationRead(peerFingerprint);
      final summaries = _conversationSummaries.toList(growable: true);
      final summaryIndex = summaries.indexWhere(
        (summary) => summary.peerFingerprint == peerFingerprint,
      );
      if (summaryIndex >= 0 && summaries[summaryIndex].unreadCount != 0) {
        summaries[summaryIndex] = summaries[summaryIndex].copyWith(
          unreadCount: 0,
        );
        _conversationSummaries = List.unmodifiable(summaries);
      }
      final messages = _storedMessages
          .map(
            (message) =>
                message.peerFingerprint == peerFingerprint &&
                    message.direction == 'incoming' &&
                    !message.isRead
                ? message.copyWith(isRead: true)
                : message,
          )
          .toList(growable: false);
      _storedMessages = List.unmodifiable(messages);
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<void> _loadOlderMessages(
    String peerFingerprint,
    _ConversationHistoryState state,
  ) async {
    state.loadingOlder = true;
    _notify();
    try {
      final pageStopwatch = Stopwatch()..start();
      final page = await platform.getStoredMessagePage(
        peerFingerprint,
        beforeCreatedAtMs: state.nextBeforeCreatedAtMs,
        beforeMessageId: state.nextBeforeMessageId,
        limit: _historyPageSize,
      );
      debugPrint(
        'HyphaTextTiming stage=flutter_history_page_loaded '
        'elapsed_ms=${pageStopwatch.elapsedMilliseconds} '
        'count=${page.messages.length} initial=false',
      );
      _mergeConversationMessages(peerFingerprint, page.messages);
      state.apply(page);
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      state.loadingOlder = false;
      _notify();
    }
  }

  Future<void> loadStoredAttachments() async {
    try {
      _storedAttachments = await platform.getStoredAttachments();
      final liveIds = _storedAttachments
          .map((attachment) => attachment.attachmentId)
          .toSet();
      _attachmentIssueById.removeWhere((id, _) => !liveIds.contains(id));
      _attachmentProgressById.removeWhere((id, _) => !liveIds.contains(id));
      _attachmentPreviewById.removeWhere((id, _) => !liveIds.contains(id));
      for (final attachment in _storedAttachments) {
        if (attachment.status == 'delivered' ||
            attachment.status == 'ready' ||
            attachment.lastErrorCode == 'user_cancelled') {
          _attachmentProgressById.remove(attachment.attachmentId);
        }
      }
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<Uint8List?> attachmentPreview(StoredAttachment attachment) {
    final previewable =
        attachment.mimeType.startsWith('image/') ||
        attachment.mimeType.startsWith('video/');
    final payloadReady =
        attachment.direction == 'outgoing' || attachment.status == 'ready';
    if (!previewable || !payloadReady) return Future.value(null);
    final cached = _attachmentPreviewById.remove(attachment.attachmentId);
    if (cached != null) {
      _attachmentPreviewById[attachment.attachmentId] = cached;
      return cached;
    }
    final request = () async {
      try {
        return await platform.loadAttachmentPreview(attachment.attachmentId);
      } on Object {
        // A missing thumbnail leaves a normal file card. It must not turn a
        // successfully transferred attachment into a message error.
        return null;
      }
    }();
    _attachmentPreviewById[attachment.attachmentId] = request;
    while (_attachmentPreviewById.length > _attachmentPreviewMemoryLimit) {
      _attachmentPreviewById.remove(_attachmentPreviewById.keys.first);
    }
    return request;
  }

  static const _attachmentPreviewMemoryLimit = 32;

  Future<void> loadRadioCapabilities() async {
    try {
      _radioCapabilities = await platform.probeRadioCapabilities();
      _wifiDirectEnabled = _radioCapabilities?.wifiEnabled;
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<void> loadContacts() async {
    try {
      _contacts = await platform.getRelayContacts();
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<void> loadProfile() async {
    try {
      final profile = await platform.getLocalProfile();
      _displayName = profile.displayName;
      _profileSetupComplete = profile.setupComplete;
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      _profileLoaded = true;
      _notify();
    }
  }

  Future<void> _loadProfileAndStartDiscovery() async {
    await loadProfile();
    if (_profileSetupComplete) await startDiscoveryIfNeeded();
  }

  Future<void> loadPendingConversationOpen() async {
    try {
      final target = await platform.consumePendingConversationOpen();
      if (target == null || target.isEmpty) return;
      _pendingConversationOpen = target;
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  String? takePendingConversationOpen() {
    final target = _pendingConversationOpen;
    _pendingConversationOpen = null;
    return target;
  }

  Future<void> loadBackgroundSettings() async {
    try {
      _backgroundSettings = await platform.getBackgroundSettings();
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<void> loadVenueTrustStatus() async {
    try {
      _venueTrustStatus = await platform.getVenueTrustStatus();
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<VenueInventoryInstallResult?> pickVenueInventory() async {
    if (_isChangingVenueTrust) return null;
    _isChangingVenueTrust = true;
    _statusError = null;
    _notify();
    try {
      final result = await platform.pickVenueInventory(
        allowAuthorityBootstrap: !_venueTrustStatus.isManaged,
      );
      if (result != null) {
        _venueTrustStatus = result.status;
        if (!result.installed) {
          _statusError = result.reason ?? 'The venue inventory was rejected.';
        }
      }
      return result;
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      return null;
    } finally {
      _isChangingVenueTrust = false;
      _notify();
    }
  }

  Future<bool> resetVenueTrustToLab() async {
    if (_isChangingVenueTrust) return false;
    _isChangingVenueTrust = true;
    _statusError = null;
    _notify();
    try {
      final reset = await platform.resetVenueTrust('RESET HYPHA VENUE TRUST');
      if (reset) {
        _venueTrustStatus = const VenueTrustStatus.lab();
      } else {
        _statusError = 'Managed Venue mode was not reset.';
      }
      return reset;
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      return false;
    } finally {
      _isChangingVenueTrust = false;
      _notify();
    }
  }

  Future<void> setBackgroundRelayEnabled(bool enabled) async {
    if (_isChangingBackgroundSettings) return;
    _isChangingBackgroundSettings = true;
    _statusError = null;
    _notify();
    try {
      if (enabled) {
        final granted = await platform.requestRadioPermissions();
        if (!granted) {
          throw const _ProductException(
            'Allow Nearby devices before turning on background relay.',
          );
        }
      }
      _backgroundSettings = await platform.setBackgroundRelayEnabled(enabled);
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      _isChangingBackgroundSettings = false;
      _notify();
    }
  }

  Future<void> setRestartAfterReboot(bool enabled) async {
    if (_isChangingBackgroundSettings) return;
    _isChangingBackgroundSettings = true;
    _statusError = null;
    _notify();
    try {
      _backgroundSettings = await platform.setRestartAfterReboot(enabled);
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      _isChangingBackgroundSettings = false;
      _notify();
    }
  }

  Future<void> requestNotificationPermission() async {
    if (_isChangingBackgroundSettings) return;
    _isChangingBackgroundSettings = true;
    _statusError = null;
    _notify();
    try {
      final granted = await platform.requestNotificationPermission();
      if (!granted) {
        _backgroundSettings = await platform.dismissNotificationOnboarding();
      }
      _backgroundSettings = await platform.getBackgroundSettings();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      _isChangingBackgroundSettings = false;
      _notify();
    }
  }

  Future<void> dismissNotificationOnboarding() async {
    try {
      _backgroundSettings = await platform.dismissNotificationOnboarding();
      _notify();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<void> openNotificationSettings() async {
    try {
      await platform.openNotificationSettings();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<void> openBatterySettings() async {
    try {
      await platform.openBatterySettings();
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<bool> enableFastAttachments() async {
    if (_isChangingAttachmentSettings) return fastAttachmentsReady;
    _isChangingAttachmentSettings = true;
    _statusError = null;
    _notify();
    try {
      final granted = await platform.requestWifiDirectPermissions();
      await loadRadioCapabilities();
      if (!granted) {
        throw const _ProductException(
          'Allow Nearby Wi-Fi so Hypha can send encrypted images and files.',
        );
      }
      if (_radioCapabilities?.wifiEnabled == false) {
        throw const _ProductException(
          'Turn on Wi-Fi for fast attachments. You do not need internet.',
        );
      }
      if (_radioCapabilities?.wifiDirectSupported == false) {
        throw const _ProductException(
          'This phone does not support direct Wi-Fi attachments.',
        );
      }
      if ((_radioCapabilities?.sdkInt ?? 33) < 33 &&
          _radioCapabilities?.locationServicesEnabled == false) {
        throw const _ProductException(
          'Turn on Location; older Android versions require it for direct Wi-Fi.',
        );
      }
      return fastAttachmentsReady;
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      return false;
    } finally {
      _isChangingAttachmentSettings = false;
      _notify();
    }
  }

  Future<AttachmentSendOutcome> pickAndSendAttachment({
    required String peerFingerprint,
    required String kind,
    String? explicitPeerToken,
  }) async {
    if (_isSendingAttachment) return AttachmentSendOutcome.failed;
    _isSendingAttachment = true;
    _statusError = null;
    _notify();
    StoredAttachment? attachment;
    try {
      await loadContacts();
      final contact = _contacts.where(
        (item) => item.fingerprint == peerFingerprint,
      );
      if (contact.isEmpty || !contact.first.verified || !contact.first.ready) {
        throw const _ProductException(
          'Finish verifying this contact before sending an attachment.',
        );
      }
      attachment = await platform.pickAttachment(peerFingerprint, kind);
      if (attachment == null) return AttachmentSendOutcome.cancelled;
      await loadStoredAttachments();

      final token = _currentVerifiedToken(
        peerFingerprint,
        explicitPeerToken: explicitPeerToken,
      );
      if (token == null) {
        await platform.prepareCourierAttachment(attachment.attachmentId);
        throw const _QueuedAttachmentException(
          'Attachment saved securely. Hypha will send it automatically when both phones are nearby.',
        );
      }
      if (!await enableFastAttachments()) {
        throw const _QueuedAttachmentException(
          'Attachment saved securely. Enable Fast attachments on both phones; Hypha will retry automatically.',
        );
      }
      _beginBusyAction(
        token,
        'Starting encrypted Wi-Fi transfer…',
        timeout: const Duration(seconds: 50),
      );
      await platform.sendAttachment(token, attachment.attachmentId);
      unawaited(loadStoredAttachments());
      return AttachmentSendOutcome.started;
    } on _QueuedAttachmentException {
      return AttachmentSendOutcome.queued;
    } on Object catch (error) {
      if (attachment == null || !_isTransientAttachmentFailure(error: error)) {
        _statusError = _friendlyError(error: error);
      }
      return attachment == null
          ? AttachmentSendOutcome.failed
          : AttachmentSendOutcome.queued;
    } finally {
      _isSendingAttachment = false;
      await loadStoredAttachments();
      _notify();
    }
  }

  Future<void> retryAttachment(
    StoredAttachment attachment, {
    String? explicitPeerToken,
  }) async {
    if (_isSendingAttachment ||
        attachment.direction != 'outgoing' ||
        attachment.status != 'queued' ||
        attachment.lastErrorCode == 'user_cancelled') {
      return;
    }
    _isSendingAttachment = true;
    _attachmentActionId = attachment.attachmentId;
    _statusError = null;
    _notify();
    try {
      final token = _currentVerifiedToken(
        attachment.peerFingerprint,
        explicitPeerToken: explicitPeerToken,
      );
      if (token == null) {
        await platform.prepareCourierAttachment(attachment.attachmentId);
        return;
      }
      if (!await enableFastAttachments()) return;
      _beginBusyAction(
        token,
        'Resuming encrypted Wi-Fi transfer…',
        timeout: const Duration(seconds: 50),
      );
      await platform.sendAttachment(token, attachment.attachmentId);
    } on Object catch (error) {
      _clearBusyAction(null);
      if (!_isTransientAttachmentFailure(error: error)) {
        _statusError = _friendlyError(error: error);
      }
    } finally {
      _isSendingAttachment = false;
      if (_attachmentActionId == attachment.attachmentId) {
        _attachmentActionId = null;
      }
      await loadStoredAttachments();
      _notify();
    }
  }

  Future<void> cancelAttachment(StoredAttachment attachment) async {
    if (_attachmentActionId != null ||
        attachment.direction != 'outgoing' ||
        attachment.status == 'delivered' ||
        attachment.lastErrorCode == 'user_cancelled') {
      return;
    }
    _attachmentActionId = attachment.attachmentId;
    _statusError = null;
    _notify();
    try {
      await platform.cancelAttachment(attachment.attachmentId);
      _clearBusyAction(null);
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      if (_attachmentActionId == attachment.attachmentId) {
        _attachmentActionId = null;
      }
      await loadStoredAttachments();
      _notify();
    }
  }

  Future<void> pauseAttachment(StoredAttachment attachment) async {
    if (attachment.direction != 'outgoing' ||
        attachment.status == 'delivered') {
      return;
    }
    try {
      await platform.pauseAttachment(attachment.attachmentId);
      _clearBusyAction(null);
      _statusError = null;
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
    } finally {
      await loadStoredAttachments();
      _notify();
    }
  }

  Future<void> _autoResumeAttachment() async {
    if (_disposed ||
        _attachmentRetryRunning ||
        _isSendingAttachment ||
        _busyToken != null) {
      return;
    }
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    StoredAttachment? candidate;
    for (final attachment in _storedAttachments) {
      if (attachment.direction == 'outgoing' &&
          attachment.status == 'queued' &&
          (attachment.nextAttemptAtMs == null ||
              attachment.nextAttemptAtMs! <= nowMs) &&
          _currentVerifiedToken(attachment.peerFingerprint) != null) {
        candidate = attachment;
        break;
      }
    }
    if (candidate == null) return;

    _attachmentRetryRunning = true;
    try {
      _radioCapabilities = await platform.probeRadioCapabilities();
      _wifiDirectEnabled = _radioCapabilities?.wifiEnabled;
      if (!fastAttachmentsReady) {
        if (_radioCapabilities?.wifiEnabled == false) {
          _attachmentIssueById[candidate.attachmentId] = 'wifi_off';
        } else if (_radioCapabilities?.wifiDirectPermissionRequired == true) {
          _attachmentIssueById[candidate.attachmentId] =
              'wifi_permission_required';
        } else if ((_radioCapabilities?.sdkInt ?? 33) < 33 &&
            _radioCapabilities?.locationServicesEnabled == false) {
          _attachmentIssueById[candidate.attachmentId] = 'location_off';
        }
        return;
      }
      final token = _currentVerifiedToken(candidate.peerFingerprint);
      if (token == null) return;
      _isSendingAttachment = true;
      _beginBusyAction(
        token,
        'Resuming encrypted attachment automatically…',
        timeout: const Duration(seconds: 50),
      );
      await platform.sendAttachment(token, candidate.attachmentId);
    } on Object {
      _clearBusyAction(null);
      unawaited(loadStoredAttachments());
    } finally {
      _isSendingAttachment = false;
      _attachmentRetryRunning = false;
      _notify();
    }
  }

  Future<void> openAttachment(StoredAttachment attachment) async {
    if (attachment.direction != 'incoming' || attachment.status != 'ready') {
      return;
    }
    try {
      await platform.openAttachment(attachment.attachmentId);
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
    }
  }

  Future<bool> updateDisplayName(String value) async {
    if (_isSavingProfile) return false;
    _isSavingProfile = true;
    _notify();
    try {
      _displayName = await platform.updateDisplayName(value);
      _profileSetupComplete = true;
      _statusError = null;
      _notify();
      unawaited(startDiscoveryIfNeeded());
      return true;
    } on Object catch (error) {
      _statusError = _friendlyError(error: error);
      _notify();
      return false;
    } finally {
      _isSavingProfile = false;
      _notify();
    }
  }

  void clearError() {
    _statusError = null;
    _notify();
  }

  Future<void> toggleDiscovery() async {
    if (_isChangingDiscovery) return;
    _isChangingDiscovery = true;
    _statusError = null;
    _notify();

    try {
      if (_isDiscovering || _isRadioRecovering) {
        await platform.stopBleDiscovery();
        _isDiscovering = false;
        _isRadioRecovering = false;
        _localToken = null;
        _clearNearbyState();
      } else {
        final granted = await platform.requestRadioPermissions();
        if (!granted) {
          throw const _ProductException(
            'Allow Nearby devices so Hypha can find phones around you.',
          );
        }
        _localToken = await platform.startBleDiscovery();
        _isDiscovering = true;
        _isRadioRecovering = false;
        _clearNearbyState();
      }
    } on Object catch (error) {
      if (error is PlatformException && error.code == 'bluetooth_off') {
        _isDiscovering = false;
        _isRadioRecovering = true;
        _localToken = null;
        _clearNearbyState();
      } else {
        _isRadioRecovering = false;
        _statusError = _friendlyError(error: error);
      }
    } finally {
      _isChangingDiscovery = false;
      _notify();
    }
  }

  Future<void> startDiscoveryIfNeeded() async {
    if (!_profileLoaded || !_profileSetupComplete) return;
    if (!_isDiscovering && !_isRadioRecovering && !_isChangingDiscovery) {
      await toggleDiscovery();
    }
  }

  /// Returns a token only after the native identity handshake bound it to the
  /// requested stable fingerprint. There is intentionally no one-peer guess.
  String? findTokenForFingerprint(String peerFingerprint) {
    for (final entry in _fingerprintByToken.entries) {
      if (entry.value == peerFingerprint && isTokenDirectlyNearby(entry.key)) {
        return entry.key;
      }
    }
    return null;
  }

  bool isTokenDirectlyNearby(String token) {
    if (!_nearbyPeers.containsKey(token)) return false;
    final lastSeen = _lastSeenByToken[token];
    return lastSeen != null &&
        DateTime.now().difference(lastSeen) <= _directPresenceLifetime;
  }

  String? _currentVerifiedToken(
    String peerFingerprint, {
    String? explicitPeerToken,
  }) {
    final token =
        explicitPeerToken != null &&
            _nearbyPeers.containsKey(explicitPeerToken) &&
            _fingerprintByToken[explicitPeerToken] == peerFingerprint
        ? explicitPeerToken
        : findTokenForFingerprint(peerFingerprint);
    if (token == null || _trustStateByToken[token] != 'verified') return null;
    return token;
  }

  Future<void> identifyPeer(String peerToken) async {
    if (_busyToken != null) return;
    if (!_nearbyPeers.containsKey(peerToken)) {
      _statusError =
          'That phone is no longer nearby. Keep both screens open and try again.';
      _notify();
      return;
    }

    _beginBusyAction(peerToken, 'Checking identity securely…');

    try {
      await platform.identifyPeer(peerToken);
    } on Object catch (error) {
      _clearBusyAction(peerToken);
      final message = _friendlyError(error: error);
      _statusError = message;
      _statusByToken[peerToken] = message;
      _notify();
    }
  }

  Future<void> markPeerVerified(String peerToken) async {
    if (_busyToken != null) return;
    if (_fingerprintByToken[peerToken] == null) {
      _statusError = 'Identify this phone securely before verifying it.';
      _notify();
      return;
    }

    _beginBusyAction(peerToken, 'Saving verification…');

    try {
      await platform.markPeerVerified(peerToken);
    } on Object catch (error) {
      _clearBusyAction(peerToken);
      final message = _friendlyError(error: error);
      _statusError = message;
      _statusByToken[peerToken] = message;
      _notify();
    }
  }

  /// Sends short text over BLE. For this payload size BLE is the smart path:
  /// it avoids Wi-Fi Direct's multi-second setup cost. Rich-content transfers
  /// will use the already-proven encrypted Wi-Fi upgrade path.
  Future<MessageSendOutcome> sendMessage({
    required String peerFingerprint,
    required String text,
    String? explicitPeerToken,
    String? replyToMessageId,
    String? replyPreview,
  }) async {
    final cleanText = text.trim();
    if (cleanText.isEmpty) return MessageSendOutcome.failed;
    final cleanReplyPreview = replyToMessageId == null
        ? null
        : _boundedReplyPreview(replyPreview ?? 'Original message');

    // Always refresh contacts from persistent storage so verified offline
    // contacts are never missed due to a stale in-memory cache.
    await loadContacts();

    RelayContact? contact;
    for (final item in _contacts) {
      if (item.fingerprint == peerFingerprint) {
        contact = item;
        break;
      }
    }
    if (contact != null) {
      if (contact.verified && !contact.ready) {
        _statusError =
            'This contact is verified but the E2E key exchange is incomplete. '
            'Meet them once with this build to finish the contact-card exchange.';
        _notify();
        return MessageSendOutcome.failed;
      }
      if (!contact.verified) {
        _statusError =
            'Compare the safety code and verify this contact before messaging.';
        _notify();
        return MessageSendOutcome.failed;
      }
      final token =
          explicitPeerToken ?? findTokenForFingerprint(peerFingerprint);
      final canSendDirectly =
          token != null &&
          _fingerprintByToken[token] == peerFingerprint &&
          _nearbyPeers.containsKey(token) &&
          _trustStateByToken[token] == 'verified';
      if (canSendDirectly) {
        return _sendDirectMessage(
          token,
          cleanText,
          replyToMessageId: replyToMessageId,
          replyPreview: cleanReplyPreview,
        );
      }
      try {
        final queued = await platform.queueMeshText(
          peerFingerprint,
          cleanText,
          replyToMessageId: replyToMessageId,
          replyPreview: cleanReplyPreview,
        );
        _statusError = null;
        _upsertStoredMessage(queued.toStoredMessage(cleanText));
        return MessageSendOutcome.queued;
      } on Object catch (error) {
        _statusError = _friendlyError(error: error);
        _notify();
        return MessageSendOutcome.failed;
      }
    }
    final token = explicitPeerToken ?? findTokenForFingerprint(peerFingerprint);
    if (token == null ||
        _fingerprintByToken[token] != peerFingerprint ||
        !_nearbyPeers.containsKey(token)) {
      _statusError =
          'This contact is not identified nearby. Open Nearby people and identify their phone first.';
      _notify();
      return MessageSendOutcome.failed;
    }
    if (_trustStateByToken[token] != 'verified') {
      _statusError =
          'Compare the safety code and verify this phone before messaging.';
      _notify();
      return MessageSendOutcome.failed;
    }

    return _sendDirectMessage(
      token,
      cleanText,
      replyToMessageId: replyToMessageId,
      replyPreview: cleanReplyPreview,
    );
  }

  Future<MessageSendOutcome> _sendDirectMessage(
    String token,
    String cleanText, {
    String? replyToMessageId,
    String? replyPreview,
  }) async {
    final sendStopwatch = Stopwatch()..start();
    debugPrint('HyphaTextTiming stage=flutter_send_started');
    _statusError = null;
    _statusByToken[token] = 'Sending encrypted message…';
    _notify();

    try {
      final queued = await platform.sendTextMessage(
        token,
        cleanText,
        replyToMessageId: replyToMessageId,
        replyPreview: replyPreview,
      );
      debugPrint(
        'HyphaTextTiming stage=native_queue_returned '
        'elapsed_ms=${sendStopwatch.elapsedMilliseconds} transport=${queued.transport}',
      );
      _statusError = null;
      _statusByToken[token] = queued.transport == 'mesh'
          ? 'Carried by Hypha'
          : 'Queued for automatic retry';
      _upsertStoredMessage(queued);
      return MessageSendOutcome.queued;
    } on Object catch (error) {
      final message = _friendlyError(error: error);
      _statusError = message;
      _statusByToken[token] = message;
      _notify();
      return MessageSendOutcome.failed;
    }
  }

  Future<void> retryTextMessage(StoredTextMessage message) async {
    if (_busyToken != null || message.status != 'queued') return;

    // For verified+ready mesh contacts, automatic mesh sync will deliver
    // the queued envelope on the next encounter — no manual BLE retry needed.
    await loadContacts();
    RelayContact? contact;
    for (final item in _contacts) {
      if (item.fingerprint == message.peerFingerprint) {
        contact = item;
        break;
      }
    }
    if (contact != null && contact.verified && contact.ready) {
      _statusError = null;
      _notify();
      return; // Mesh sync handles delivery automatically.
    }

    final token = findTokenForFingerprint(message.peerFingerprint);
    if (token == null || _trustStateByToken[token] != 'verified') {
      _statusError =
          'Find and identify this contact nearby before retrying the queued message.';
      _notify();
      return;
    }

    _manualTextActionToken = token;
    _beginBusyAction(token, 'Retrying queued message…');

    try {
      await platform.retryTextMessage(token, message.messageId);
    } on Object catch (error) {
      _clearBusyAction(token);
      _manualTextActionToken = null;
      final text = _friendlyError(error: error);
      _statusError = text;
      _statusByToken[token] = text;
      _notify();
      unawaited(loadStoredMessages());
    }
  }

  void _onDiscoveryEvent(BleDiscoveryEvent event) {
    final token = event.token;
    if (token != null) {
      if (event.type == 'peer_seen') {
        _nearbyPeers[token] = event;
        _lastSeenByToken[token] = DateTime.now();
      }
      final carriesDirectIdentity = _directIdentityEventTypes.contains(
        event.type,
      );
      final hideAutomaticUnknownProof =
          event.type == 'identity_proof_verified' &&
          event.automatic == true &&
          event.trustState != 'verified' &&
          _busyToken != token;
      if (carriesDirectIdentity &&
          !hideAutomaticUnknownProof &&
          event.fingerprint != null) {
        _fingerprintByToken[token] = event.fingerprint!;
      }
      if (carriesDirectIdentity &&
          !hideAutomaticUnknownProof &&
          event.protection != null) {
        _protectionByToken[token] = event.protection!;
      }
      if (carriesDirectIdentity &&
          !hideAutomaticUnknownProof &&
          event.trustState != null) {
        _trustStateByToken[token] = event.trustState!;
      }
    }

    switch (event.type) {
      case 'discovery_started':
        _isDiscovering = true;
        _isRadioRecovering = false;
        _localToken = token;
        _statusError = null;
        _clearNearbyState();
      case 'discovery_suspended':
        _isDiscovering = false;
        _isRadioRecovering = event.automatic == true;
        _localToken = null;
        _clearNearbyState();
      case 'discovery_stopped':
        _isDiscovering = false;
        _isRadioRecovering = false;
        _localToken = null;
        _clearNearbyState();
      case 'radio_recovery_deferred':
        _isDiscovering = false;
        _isRadioRecovering = true;
        _localToken = null;
        _clearNearbyState();
      case 'link_connecting':
        if (token != null) _statusByToken[token] = 'Connecting securely…';
      case 'identity_proof_verified':
        if (token != null &&
            !(event.automatic == true &&
                event.trustState != 'verified' &&
                _busyToken != token)) {
          _statusByToken[token] = event.trustState == 'verified'
              ? 'Known identity confirmed'
              : 'Identity confirmed—compare the safety code';
        }
      case 'peer_identity_ready':
        if (token != null) {
          _statusByToken[token] = _trustStateByToken[token] == 'verified'
              ? 'Known identity confirmed'
              : 'Identity ready for verification';
          _clearBusyAction(token);
        }
      case 'peer_trust_updated':
        if (token != null) {
          _trustStateByToken[token] = event.trustState ?? 'verified';
          _statusByToken[token] =
              'Verified on this phone. The other person must verify you too.';
          _clearBusyAction(token);
        }
        unawaited(loadContacts());
      case 'contact_ready':
      case 'contact_exchange_ready':
        unawaited(loadContacts());
      case 'mesh_sync_progress':
        // Progress contains no user-visible message state. Reloading the full
        // encrypted history for every fragment causes work proportional to
        // both sync traffic and chat length.
        return;
      case 'mesh_sync_completed':
      case 'mesh_sync_response_ready':
        unawaited(loadStoredMessages());
        unawaited(loadContacts());
        return;
      case 'fixed_node_sync_completed':
        if (event.meshChanged == true) unawaited(loadStoredMessages());
        return;
      case 'text_message_delivered':
      case 'wifi_text_delivered':
        debugPrint('HyphaTextTiming stage=flutter_delivery_event');
        if (token != null) _statusByToken[token] = 'Delivered';
        if (_manualTextActionToken == token) _clearBusyAction(token);
        if (!_markStoredMessageDelivered(event.messageId)) {
          unawaited(loadStoredMessages());
        }
        _notify();
        return;
      case 'text_message_queued':
        if (token != null) {
          _statusByToken[token] = event.code == 'peer_not_verified_by_recipient'
              ? 'Queued—the other person must verify your phone'
              : 'Queued for automatic retry';
        }
        if (_manualTextActionToken == token) _clearBusyAction(token);
        if (event.code != 'locally_queued' &&
            event.code != 'ordered_mesh_backlog') {
          unawaited(loadStoredMessages());
        }
      case 'text_message_received':
      case 'wifi_text_received':
        if (!_upsertDurableReceivedMessage(event)) {
          unawaited(loadStoredMessages());
        }
        return;
      case 'text_message_duplicate':
        // Native duplicate suppression already confirmed the durable record.
        // A duplicate cannot change the visible timeline.
        return;
      case 'wifi_direct_state':
        _wifiDirectEnabled = event.enabled;
        if (event.enabled == true) {
          _attachmentIssueById.removeWhere((_, code) => code == 'wifi_off');
          unawaited(loadRadioCapabilities());
          unawaited(_autoResumeAttachment());
        } else if (event.enabled == false) {
          for (final id in _attachmentProgressById.keys.toList()) {
            _attachmentProgressById[id] = _attachmentProgressById[id]!
                .withPhase('waiting');
          }
          for (final attachment in _storedAttachments) {
            if (attachment.direction == 'outgoing' &&
                attachment.status == 'queued' &&
                attachment.lastErrorCode != 'user_paused' &&
                attachment.lastErrorCode != 'user_cancelled') {
              _attachmentIssueById[attachment.attachmentId] = 'wifi_off';
            }
          }
        }
      case 'attachment_wifi_prepared':
        _updateAttachmentProgress(event, phase: 'preparing');
        if (event.attachmentId != null) {
          _attachmentIssueById.remove(event.attachmentId);
        }
        unawaited(loadStoredAttachments());
      case 'attachment_sending':
        _updateAttachmentProgress(event, phase: 'sending');
        if (event.attachmentId != null) {
          _attachmentIssueById.remove(event.attachmentId);
        }
        if (_busyToken != null) {
          _statusByToken[_busyToken!] = 'Sending encrypted attachment…';
        }
        unawaited(loadStoredAttachments());
      case 'attachment_receiving':
        _updateAttachmentProgress(event, phase: 'receiving');
        unawaited(loadStoredAttachments());
      case 'attachment_send_progress':
        _updateAttachmentProgress(event, phase: 'sending');
      case 'attachment_receive_progress':
        _updateAttachmentProgress(event, phase: 'receiving');
      case 'attachment_delivered':
        if (event.attachmentId != null) {
          _attachmentIssueById.remove(event.attachmentId);
          _attachmentProgressById.remove(event.attachmentId);
        }
        if (_busyToken != null) _statusByToken[_busyToken!] = 'Delivered';
        _clearBusyAction(null);
        unawaited(loadStoredAttachments());
      case 'attachment_received':
        if (event.attachmentId != null) {
          _attachmentIssueById.remove(event.attachmentId);
          _attachmentProgressById.remove(event.attachmentId);
        }
        _clearBusyAction(null);
        unawaited(loadStoredAttachments());
      case 'attachment_paused':
        _markAttachmentProgressWaiting(event.attachmentId, phase: 'paused');
        _clearBusyAction(null);
        _statusError = null;
        unawaited(loadStoredAttachments());
      case 'attachment_cancelled':
        if (event.attachmentId != null) {
          _attachmentIssueById.remove(event.attachmentId);
          _attachmentProgressById.remove(event.attachmentId);
        }
        _clearBusyAction(null);
        _statusError = null;
        unawaited(loadStoredAttachments());
      case 'attachment_waiting_for_radio':
      case 'attachment_waiting_for_turn':
        _markAttachmentProgressWaiting(event.attachmentId);
        if (_busyToken != null) {
          _statusByToken[_busyToken!] = 'Queued — retrying automatically';
        }
        _clearBusyAction(null);
        unawaited(loadStoredAttachments());
      case 'attachment_queued':
        if (event.attachmentId != null && event.code != null) {
          _attachmentIssueById[event.attachmentId!] = event.code!;
        }
        _markAttachmentProgressWaiting(event.attachmentId);
        _clearBusyAction(null);
        if (_isTransientAttachmentFailure(code: event.code) ||
            _inlineAttachmentIssueCodes.contains(event.code)) {
          _statusError = null;
        } else {
          _statusError = _friendlyError(
            code: event.code,
            fallback:
                'The attachment is safely queued and will retry automatically.',
          );
        }
        unawaited(loadStoredAttachments());
      case 'attachment_dispatch_error':
      case 'wifi_direct_error':
        if (event.attachmentId != null && event.code != null) {
          _attachmentIssueById[event.attachmentId!] = event.code!;
        }
        _markAttachmentProgressWaiting(event.attachmentId);
        if (_isSendingAttachment ||
            _busyToken != null ||
            _hasQueuedOutgoingAttachment) {
          _clearBusyAction(null);
          if (_isTransientAttachmentFailure(code: event.code) ||
              _inlineAttachmentIssueCodes.contains(event.code)) {
            _statusError = null;
          } else {
            _statusError = _friendlyError(
              code: event.code,
              fallback: event.message,
            );
          }
          unawaited(loadStoredAttachments());
        }
      case 'error':
        _clearBusyAction(token);
        _statusError = _friendlyError(
          code: event.code,
          fallback: event.message,
        );
        unawaited(loadStoredMessages());
      case 'link_error':
        if (event.automatic == true) {
          if (token != null && _nearbyPeers.containsKey(token)) {
            _statusByToken[token] = 'Reconnecting automatically...';
          }
        } else if (event.queued == true) {
          if (token != null) {
            _statusByToken[token] = 'Saving message for retry…';
          }
        } else if (_hasQueuedOutgoingAttachment &&
            _isTransientAttachmentFailure(code: event.code)) {
          _clearBusyAction(token);
          _statusError = null;
          if (token != null) {
            _statusByToken[token] = 'Queued — retrying automatically';
          }
        } else {
          _clearBusyAction(token);
          _statusError = _friendlyError(
            code: event.code,
            fallback: event.message,
          );
        }
        unawaited(loadStoredMessages());
    }

    if ((event.type == 'identity_proof_verified' &&
            event.trustState == 'verified') ||
        event.type == 'contact_ready' ||
        event.type == 'contact_exchange_ready') {
      unawaited(_autoResumeAttachment());
    }

    _notify();
  }

  void _beginBusyAction(
    String token,
    String status, {
    Duration timeout = const Duration(seconds: 20),
  }) {
    _busyActionTimer?.cancel();
    _busyToken = token;
    _statusError = null;
    _statusByToken[token] = status;
    _busyActionTimer = Timer(timeout, () {
      if (_busyToken != token) return;
      _busyToken = null;
      if (_manualTextActionToken == token) _manualTextActionToken = null;
      _statusByToken[token] = 'Timed out—try again';
      _statusError =
          'The nearby action took too long. Keep both phones close and try again.';
      _notify();
    });
    _notify();
  }

  void _clearBusyAction(String? token) {
    if (token != null && _busyToken != token) return;
    _busyActionTimer?.cancel();
    _busyActionTimer = null;
    _busyToken = null;
    if (token == null || _manualTextActionToken == token) {
      _manualTextActionToken = null;
    }
  }

  void _removeStalePeers() {
    if (!_isDiscovering || _lastSeenByToken.isEmpty) return;
    final cutoff = DateTime.now().subtract(_directPresenceLifetime);
    final stale = _lastSeenByToken.entries
        .where((entry) => entry.value.isBefore(cutoff))
        .map((entry) => entry.key)
        .toList(growable: false);
    if (stale.isEmpty) return;
    for (final token in stale) {
      _nearbyPeers.remove(token);
      _lastSeenByToken.remove(token);
      _fingerprintByToken.remove(token);
      _protectionByToken.remove(token);
      _trustStateByToken.remove(token);
      _statusByToken.remove(token);
      if (_busyToken == token) {
        _clearBusyAction(token);
      }
    }
    _notify();
  }

  void _clearNearbyState() {
    _nearbyPeers.clear();
    _lastSeenByToken.clear();
    _fingerprintByToken.clear();
    _protectionByToken.clear();
    _trustStateByToken.clear();
    _statusByToken.clear();
    _clearBusyAction(null);
  }

  String _friendlyError({Object? error, String? code, String? fallback}) {
    if (error is _ProductException) return error.message;
    if (error is PlatformException) {
      code = error.code;
      fallback = error.message;
    }
    return switch (code) {
      'permission_required' =>
        'Allow Nearby devices in Android settings so Hypha can find phones.',
      'bluetooth_off' => 'Turn on Bluetooth, then try again.',
      'bluetooth_unavailable' => 'Bluetooth is not available on this phone.',
      'advertising_unsupported' =>
        'This phone cannot announce itself over Bluetooth LE.',
      'discovery_stopped' => 'Start nearby discovery, then try again.',
      'peer_stale' =>
        'That phone moved out of range. Keep both screens open and try again.',
      'link_busy' => 'Hypha will retry after the current nearby action.',
      'identity_not_observed' =>
        'Identify this phone securely before verifying it.',
      'peer_not_verified' =>
        'Compare the safety code and verify this phone before messaging.',
      'peer_not_verified_by_recipient' =>
        'The other person must verify your phone before messages can arrive.',
      'queued_peer_mismatch' =>
        'That is not the intended recipient. The queued message was kept.',
      'invalid_message' => 'Messages must contain 1 to 2048 bytes of text.',
      'message_store_failed' =>
        'Hypha could not safely open its saved messages. Try reopening the app.',
      'wifi_permission_required' || 'permission_required_wifi' =>
        'Allow Nearby Wi-Fi for encrypted images and files.',
      'wifi_off' => 'Turn on Wi-Fi for attachments. Internet is not required.',
      'wifi_direct_radio_busy' =>
        'The Wi-Fi radio is busy. Turn hotspot off; Hypha will retry automatically.',
      'location_off' =>
        'Turn on Location; this Android version requires it for direct Wi-Fi.',
      'wifi_direct_unsupported' =>
        'This phone does not support direct Wi-Fi attachments.',
      'wifi_promotion_deferred' =>
        'This small attachment is safely queued while Hypha waits for a useful fast-transfer batch.',
      'wifi_peer_stale' || 'wifi_direct_connection_timeout' =>
        'The attachment is safely queued and will retry automatically when both phones are nearby.',
      'attachment_import_failed' =>
        'Hypha could not securely save that attachment.',
      'attachment_viewer_unavailable' =>
        'No installed app can open this file type.',
      'link_timeout' || 'operation_timeout' =>
        'The nearby connection timed out. Keep both phones close and try again.',
      _ =>
        fallback?.trim().isNotEmpty == true
            ? fallback!.trim()
            : 'Hypha could not complete that action. Try again.',
    };
  }

  bool get _hasQueuedOutgoingAttachment => _storedAttachments.any(
    (attachment) =>
        attachment.direction == 'outgoing' &&
        attachment.status == 'queued' &&
        attachment.lastErrorCode != 'user_paused' &&
        attachment.lastErrorCode != 'user_cancelled',
  );

  bool _isTransientAttachmentFailure({Object? error, String? code}) {
    if (error is PlatformException) code = error.code;
    return _transientAttachmentFailureCodes.contains(code);
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  void _upsertStoredMessage(StoredTextMessage message) {
    final next = _storedMessages.toList(growable: true);
    final existing = next.indexWhere(
      (candidate) => candidate.messageId == message.messageId,
    );
    final inserted = existing < 0;
    if (existing >= 0) {
      next[existing] = message;
    } else {
      next.add(message);
    }
    next.sort(_compareStoredMessagesOldestFirst);
    _storedMessages = List.unmodifiable(next);
    _upsertConversationSummary(message, incrementCount: inserted);
    _notify();
    if (inserted &&
        message.direction == 'incoming' &&
        _activeConversationFingerprint == message.peerFingerprint) {
      unawaited(markConversationRead(message.peerFingerprint));
    }
  }

  bool _markStoredMessageDelivered(String? messageId) {
    if (messageId == null || messageId.isEmpty) return false;
    final next = _storedMessages.toList(growable: true);
    final index = next.indexWhere(
      (candidate) => candidate.messageId == messageId,
    );
    var changed = false;
    if (index >= 0) {
      final delivered = _asDelivered(next[index]);
      next[index] = delivered;
      _storedMessages = List.unmodifiable(next);
      changed = true;
    }
    final summaryIndex = _conversationSummaries.indexWhere(
      (summary) => summary.lastMessage.messageId == messageId,
    );
    if (summaryIndex >= 0) {
      final summaries = _conversationSummaries.toList(growable: true);
      summaries[summaryIndex] = summaries[summaryIndex].copyWith(
        lastMessage: _asDelivered(summaries[summaryIndex].lastMessage),
      );
      _conversationSummaries = List.unmodifiable(summaries);
      changed = true;
    }
    return changed;
  }

  StoredTextMessage _asDelivered(StoredTextMessage current) {
    return StoredTextMessage(
      messageId: current.messageId,
      peerFingerprint: current.peerFingerprint,
      direction: current.direction,
      text: current.text,
      status: 'delivered',
      transport: current.transport,
      replyToMessageId: current.replyToMessageId,
      replyPreview: current.replyPreview,
      createdAtMs: current.createdAtMs,
      attemptCount: current.attemptCount,
      conversationSequence: current.conversationSequence,
      lastAttemptAtMs: current.lastAttemptAtMs,
      nextAttemptAtMs: null,
      lastErrorCode: null,
      isRead: current.isRead,
    );
  }

  void _replaceConversationMessages(
    String peerFingerprint,
    List<StoredTextMessage> messages,
  ) {
    final next =
        _storedMessages
            .where((message) => message.peerFingerprint != peerFingerprint)
            .toList(growable: true)
          ..addAll(messages)
          ..sort(_compareStoredMessagesOldestFirst);
    _storedMessages = List.unmodifiable(next);
  }

  void _mergeConversationMessages(
    String peerFingerprint,
    List<StoredTextMessage> messages,
  ) {
    final byId = <String, StoredTextMessage>{
      for (final message in _storedMessages)
        if (message.peerFingerprint == peerFingerprint)
          message.messageId: message,
      for (final message in messages) message.messageId: message,
    };
    _replaceConversationMessages(peerFingerprint, byId.values.toList());
  }

  void _upsertConversationSummary(
    StoredTextMessage message, {
    required bool incrementCount,
  }) {
    final summaries = _conversationSummaries.toList(growable: true);
    final index = summaries.indexWhere(
      (summary) => summary.peerFingerprint == message.peerFingerprint,
    );
    if (index < 0) {
      summaries.add(
        ConversationSummary(
          peerFingerprint: message.peerFingerprint,
          lastMessage: message,
          messageCount: 1,
          unreadCount: message.direction == 'incoming' && !message.isRead
              ? 1
              : 0,
        ),
      );
    } else {
      final current = summaries[index];
      final latest =
          _compareStoredMessagesOldestFirst(current.lastMessage, message) <= 0
          ? message
          : current.lastMessage;
      summaries[index] = current.copyWith(
        lastMessage: latest,
        messageCount: current.messageCount + (incrementCount ? 1 : 0),
        unreadCount:
            current.unreadCount +
            (incrementCount &&
                    message.direction == 'incoming' &&
                    !message.isRead
                ? 1
                : 0),
      );
    }
    _conversationSummaries = List.unmodifiable(summaries);
    _sortConversationSummaries();
  }

  void _sortConversationSummaries() {
    final summaries = _conversationSummaries.toList(growable: true)
      ..sort(
        (left, right) => _compareStoredMessagesOldestFirst(
          right.lastMessage,
          left.lastMessage,
        ),
      );
    _conversationSummaries = List.unmodifiable(summaries);
  }

  static int _compareStoredMessagesOldestFirst(
    StoredTextMessage left,
    StoredTextMessage right,
  ) {
    final time = left.createdAtMs.compareTo(right.createdAtMs);
    if (time != 0) return time;
    return left.messageId.compareTo(right.messageId);
  }

  bool _upsertDurableReceivedMessage(BleDiscoveryEvent event) {
    final messageId = event.messageId;
    final fingerprint = event.fingerprint;
    final text = event.text;
    if (messageId == null ||
        messageId.isEmpty ||
        fingerprint == null ||
        fingerprint.isEmpty ||
        text == null) {
      return false;
    }
    _upsertStoredMessage(
      StoredTextMessage(
        messageId: messageId,
        peerFingerprint: fingerprint,
        direction: 'incoming',
        text: text,
        status: 'received',
        transport: event.type == 'wifi_text_received' ? 'wifi' : 'direct',
        replyToMessageId: event.replyToMessageId,
        replyPreview: event.replyPreview,
        createdAtMs: DateTime.now().millisecondsSinceEpoch,
        attemptCount: 0,
        isRead: false,
      ),
    );
    return true;
  }

  static const _historyPageSize = 40;
  static const _maxReplyPreviewBytes = 256;

  static String _boundedReplyPreview(String raw) {
    final clean = raw.replaceAll(RegExp(r'\s+'), ' ').trim();
    final fallback = clean.isEmpty ? 'Original message' : clean;
    if (utf8.encode(fallback).length <= _maxReplyPreviewBytes) return fallback;
    const ellipsis = '…';
    final buffer = StringBuffer();
    var usedBytes = utf8.encode(ellipsis).length;
    for (final rune in fallback.runes) {
      final character = String.fromCharCode(rune);
      final characterBytes = utf8.encode(character).length;
      if (usedBytes + characterBytes > _maxReplyPreviewBytes) break;
      buffer.write(character);
      usedBytes += characterBytes;
    }
    return '${buffer.toString().trimRight()}$ellipsis';
  }

  static const _directPresenceLifetime = Duration(seconds: 10);
  static const _directIdentityEventTypes = {
    'peer_seen',
    'identity_proof_verified',
    'peer_trust_updated',
    'contact_ready',
    'contact_exchange_ready',
  };
  static const _transientAttachmentFailureCodes = <String>{
    'link_busy',
    'gatt_connection_failed',
    'link_timeout',
    'operation_timeout',
    'transfer_write_failed',
    'wifi_direct_busy',
    'wifi_peer_stale',
    'wifi_direct_connection_timeout',
    'wifi_direct_connect_failed',
    'wifi_direct_transfer_failed',
    'wifi_direct_disconnected_early',
    'wifi_direct_stopped',
    'wifi_upgrade_failed',
    'wifi_upgrade_stale',
    'attachment_queue_busy',
    'attachment_retry_deferred',
    'attachment_cancelled',
    'wifi_promotion_deferred',
  };
  static const _inlineAttachmentIssueCodes = <String>{
    'wifi_off',
    'wifi_direct_radio_busy',
    'wifi_permission_required',
    'permission_required_wifi',
    'location_off',
  };
}

class _ConversationHistoryState {
  bool initialized = false;
  bool loadingInitial = false;
  bool loadingOlder = false;
  bool hasMore = false;
  int? nextBeforeCreatedAtMs;
  String? nextBeforeMessageId;
  Future<void>? activeLoad;

  void apply(StoredMessagePage page) {
    hasMore = page.hasMore;
    nextBeforeCreatedAtMs = page.nextBeforeCreatedAtMs;
    nextBeforeMessageId = page.nextBeforeMessageId;
  }
}

class _ProductException implements Exception {
  const _ProductException(this.message);

  final String message;
}

class _QueuedAttachmentException implements Exception {
  const _QueuedAttachmentException(this.message);

  final String message;
}
