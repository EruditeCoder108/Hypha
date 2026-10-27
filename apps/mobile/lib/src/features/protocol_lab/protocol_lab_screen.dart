import 'dart:async';

import 'package:flutter/material.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

class ProtocolLabScreen extends StatefulWidget {
  const ProtocolLabScreen({super.key, this.platform = const RelayPlatform()});

  final RelayPlatformApi platform;

  @override
  State<ProtocolLabScreen> createState() => _ProtocolLabScreenState();
}

class _ProtocolLabScreenState extends State<ProtocolLabScreen> {
  RadioCapabilities? _capabilities;
  final Map<String, BleDiscoveryEvent> _nearbyPeers = {};
  final Map<String, String> _linkStatusByToken = {};
  final Map<String, String> _fingerprintByToken = {};
  final Map<String, String> _identityProtectionByToken = {};
  final Map<String, String> _trustStateByToken = {};
  final Map<String, BleDiscoveryEvent> _wifiDirectPeers = {};
  final Map<String, String> _wifiDirectStatusByToken = {};
  final TextEditingController _messageController = TextEditingController();
  List<StoredTextMessage> _storedMessages = const [];
  List<RelayContact> _contacts = const [];
  StreamSubscription<BleDiscoveryEvent>? _discoverySubscription;
  Object? _probeError;
  String? _discoveryError;
  String? _localToken;
  String? _linkBusyToken;
  String? _localWifiDirectToken;
  String? _wifiDirectBusyToken;
  String? _wifiDirectError;
  String? _wifiDirectInfo;
  bool _isProbing = false;
  bool _isDiscovering = false;
  bool _isChangingDiscovery = false;
  bool _isWifiDirectActive = false;
  bool _isChangingWifiDirect = false;
  String? _lastCopyBusyFingerprint;
  String? _lastCopyStatus;

  @override
  void initState() {
    super.initState();
    _discoverySubscription = widget.platform.bleDiscoveryEvents.listen(
      _onDiscoveryEvent,
      onError: (Object error) {
        if (mounted) setState(() => _discoveryError = error.toString());
      },
    );
    unawaited(_loadStoredMessages());
    unawaited(_loadContacts());
  }

  @override
  void dispose() {
    unawaited(_discoverySubscription?.cancel());
    if (_isWifiDirectActive) unawaited(widget.platform.stopWifiDirect());
    _messageController.dispose();
    super.dispose();
  }

  void _onDiscoveryEvent(BleDiscoveryEvent event) {
    if (!mounted) return;
    if (event.type == 'peer_seen' && event.token != null) {
      setState(() => _nearbyPeers[event.token!] = event);
    } else if (event.type == 'link_connecting' && event.token != null) {
      setState(() => _linkStatusByToken[event.token!] = 'Connecting…');
    } else if (event.type == 'link_connected' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Connected; negotiating packet size…';
      });
    } else if (event.type == 'mtu_negotiated' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'MTU ${event.mtu ?? '?'}; starting encrypted handshake...';
      });
    } else if (event.type == 'secure_handshake_started' &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] = 'Exchanging Noise XX handshake...';
      });
    } else if ((event.type == 'secure_handshake_receiving' ||
            event.type == 'secure_handshake_sending' ||
            event.type == 'secure_handshake_reply_ready') &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] = 'Secure handshake in progress...';
      });
    } else if (event.type == 'secure_session_established' &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Encrypted unknown-peer session established';
      });
    } else if ((event.type == 'identity_proof_sending' ||
            event.type == 'identity_proof_receiving') &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Authenticating persistent device identity...';
      });
    } else if (event.type == 'identity_proof_verified' && event.token != null) {
      setState(() {
        if (event.fingerprint != null) {
          _fingerprintByToken[event.token!] = event.fingerprint!;
        }
        if (event.protection != null) {
          _identityProtectionByToken[event.token!] = event.protection!;
        }
        if (event.trustState != null) {
          _trustStateByToken[event.token!] = event.trustState!;
        }
        _linkStatusByToken[event.token!] = event.trustState == 'verified'
            ? 'Previously verified device identity confirmed'
            : 'Device key authenticated (${event.protection ?? 'unknown protection'}); '
                  'compare the safety fingerprint before marking verified';
      });
    } else if (event.type == 'peer_trust_updated' && event.token != null) {
      setState(() {
        if (event.fingerprint != null) {
          _fingerprintByToken[event.token!] = event.fingerprint!;
        }
        if (event.protection != null) {
          _identityProtectionByToken[event.token!] = event.protection!;
        }
        _trustStateByToken[event.token!] = event.trustState ?? 'verified';
        _linkStatusByToken[event.token!] =
            'Fingerprint marked verified on this device';
      });
    } else if (event.type == 'encrypted_transfer_sending' &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Sending encrypted 4 KB test payload...';
      });
    } else if (event.type == 'encrypted_transfer_receiving' &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] = 'Receiving encrypted payload...';
      });
    } else if (event.type == 'encrypted_transfer_received' &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Decrypted and verified ${_formatBytes(event.bytes)}; sending encrypted receipt...';
      });
    } else if (event.type == 'secure_transfer_acknowledged' &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Encrypted ${_formatBytes(event.bytes)} verified end to end in '
            '${event.elapsedMs ?? '?'} ms';
        _linkBusyToken = null;
      });
    } else if (event.type == 'tamper_test_started' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Sending deliberately altered ciphertext...';
      });
    } else if (event.type == 'secure_payload_rejected' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Invalid ciphertext rejected; secure session closed safely';
      });
    } else if (event.type == 'tamper_rejection_confirmed' &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'PASS: tampered ciphertext rejected; app remained stable';
        _linkBusyToken = null;
      });
    } else if (event.type == 'text_message_sending' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] = 'Sending encrypted message...';
      });
    } else if (event.type == 'text_message_retrying' && event.token != null) {
      setState(() {
        _linkBusyToken = event.token;
        _linkStatusByToken[event.token!] = event.automatic == true
            ? 'Nearby recipient found; retrying queued message automatically...'
            : 'Retrying queued message safely with the same message ID...';
      });
      unawaited(_loadStoredMessages());
    } else if (event.type == 'text_message_queued') {
      setState(() {
        final token = event.token;
        if (token != null) {
          final status =
              'Not delivered yet - saved safely and queued for retry';
          if (_wifiDirectPeers.containsKey(token)) {
            _wifiDirectStatusByToken[token] = status;
          } else {
            _linkStatusByToken[token] = status;
          }
        }
        if (_linkBusyToken != null) {
          _linkStatusByToken[_linkBusyToken!] =
              'Not delivered yet - saved safely and queued for retry';
        }
        _linkBusyToken = null;
        _wifiDirectBusyToken = null;
      });
      unawaited(_loadStoredMessages());
    } else if (event.type == 'text_message_receiving' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] = 'Receiving encrypted message...';
      });
    } else if ((event.type == 'text_message_received' ||
            event.type == 'text_message_duplicate') &&
        event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] = event.type == 'text_message_received'
            ? 'Message saved; sending encrypted delivery receipt...'
            : 'Duplicate safely suppressed; receipt sent again';
      });
      unawaited(_loadStoredMessages());
    } else if (event.type == 'text_message_delivered' && event.token != null) {
      if (_messageController.text == event.text) {
        _messageController.clear();
      }
      setState(() {
        _linkStatusByToken[event.token!] =
            'Message delivered and saved on both phones';
        _linkBusyToken = null;
      });
      unawaited(_loadStoredMessages());
    } else if (event.type == 'transfer_receiving' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Receiving ${_formatBytes(event.bytes)} of test data…';
      });
    } else if (event.type == 'transfer_sending' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Sending ${_formatBytes(event.bytes)} in acknowledged chunks…';
      });
    } else if (event.type == 'transfer_received' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            'Received and verified ${_formatBytes(event.bytes)} at '
            '${_formatRate(event.throughputBps)}';
        _linkBusyToken = null;
      });
    } else if (event.type == 'transfer_acknowledged' && event.token != null) {
      setState(() {
        _linkStatusByToken[event.token!] =
            '${_formatBytes(event.bytes)} verified in '
            '${event.elapsedMs ?? '?'} ms • ${_formatRate(event.throughputBps)}';
        _linkBusyToken = null;
      });
    } else if (event.type == 'link_error') {
      setState(() {
        if (event.token != null) {
          _linkStatusByToken[event.token!] =
              event.message ?? 'Direct-link test failed.';
        }
        if (_wifiDirectBusyToken != null) {
          _wifiDirectStatusByToken[_wifiDirectBusyToken!] =
              event.message ?? 'BLE authorization failed.';
          _wifiDirectBusyToken = null;
        }
        _linkBusyToken = null;
      });
      unawaited(_loadStoredMessages());
    } else if (event.type == 'outbox_retry_deferred') {
      setState(() {
        _discoveryError =
            event.message ?? 'A queued message retry was safely deferred.';
      });
    } else if (event.type == 'wifi_upgrade_authorized') {
      setState(() {
        if (event.token != null) {
          _linkStatusByToken[event.token!] =
              'Verified BLE authorized a one-time Wi-Fi key';
        }
        if (_wifiDirectBusyToken != null) {
          _wifiDirectStatusByToken[_wifiDirectBusyToken!] =
              'BLE authorization complete; creating Wi-Fi Direct group...';
        }
        _linkBusyToken = null;
      });
    } else if (event.type == 'wifi_upgrade_noise_established') {
      setState(() {
        final token = _wifiDirectBusyToken ?? event.token;
        if (token != null) {
          _wifiDirectStatusByToken[token] =
              'Fast Noise session established; Wi-Fi records are encrypted...';
        }
      });
    } else if (event.type == 'wifi_text_prepared' && event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Message prepared; authenticating the Wi-Fi path through BLE...';
      });
    } else if (event.type == 'wifi_text_sending' && event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Sending the real message through encrypted Wi-Fi...';
      });
    } else if (event.type == 'wifi_text_receiving' && event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Receiving a real message through encrypted Wi-Fi...';
      });
    } else if ((event.type == 'wifi_text_received' ||
            event.type == 'wifi_text_duplicate') &&
        event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            event.type == 'wifi_text_received'
            ? 'Message saved before the encrypted receipt was sent'
            : 'Duplicate message safely suppressed';
      });
      unawaited(_loadStoredMessages());
    } else if (event.type == 'wifi_text_delivered' && event.token != null) {
      if (_messageController.text == event.text) {
        _messageController.clear();
      }
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Message delivered, verified, and saved on both phones';
        if (_linkBusyToken != null) {
          _linkStatusByToken[_linkBusyToken!] =
              'Message delivered through encrypted Wi-Fi';
        }
        _wifiDirectBusyToken = null;
        _linkBusyToken = null;
      });
      unawaited(_loadStoredMessages());
    } else if (event.type == 'wifi_direct_peer_seen' && event.token != null) {
      setState(() {
        _wifiDirectPeers[event.token!] = event;
        _wifiDirectError = null;
        _wifiDirectInfo = event.limited == true
            ? 'Peer found through a basic Android service record. Hypha will resolve its secure token through BLE.'
            : 'Peer found and ready for outgoing Wi-Fi connections.';
      });
    } else if (event.type == 'wifi_direct_peer_replaced' &&
        event.token != null) {
      setState(() {
        final previous = event.previousToken;
        final previousStatus = previous == null
            ? null
            : _wifiDirectStatusByToken.remove(previous);
        if (previous != null) _wifiDirectPeers.remove(previous);
        _wifiDirectPeers[event.token!] = event;
        _wifiDirectError = null;
        if (previousStatus != null) {
          _wifiDirectStatusByToken[event.token!] = previousStatus;
        }
        _wifiDirectInfo =
            'Android supplied the full peer record; secure Wi-Fi is ready.';
      });
    } else if (event.type == 'wifi_direct_peer_lost' && event.token != null) {
      setState(() {
        _wifiDirectPeers.remove(event.token);
        _wifiDirectStatusByToken.remove(event.token);
        _wifiDirectInfo =
            'That peer record expired. Hypha is searching again automatically.';
      });
    } else if (event.type == 'wifi_direct_passive_ready' ||
        event.type == 'wifi_direct_warning') {
      setState(() {
        _wifiDirectInfo =
            event.message ?? 'Wi-Fi discovery is retrying automatically.';
      });
    } else if (event.type == 'wifi_direct_connecting' && event.token != null) {
      setState(() {
        _wifiDirectError = null;
        _wifiDirectBusyToken = event.token;
        _wifiDirectStatusByToken[event.token!] =
            'Creating offline Wi-Fi connection...';
      });
    } else if (event.type == 'wifi_direct_connect_started' &&
        event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Connection requested; accept the system prompt on the other phone if shown.';
      });
    } else if (event.type == 'wifi_direct_group_ready' && event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Wi-Fi Direct group ready (${event.role ?? 'peer'}); opening local socket...';
      });
    } else if (event.type == 'wifi_direct_transfer_sending' &&
        event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Sending ${_formatBytes(event.bytes)} '
            '${event.secure == true ? 'as encrypted records' : 'random test data'}...';
      });
    } else if (event.type == 'wifi_direct_transfer_receiving' &&
        event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'Receiving ${_formatBytes(event.bytes)} '
            '${event.secure == true ? 'as encrypted records' : 'random test data'}...';
      });
    } else if (event.type == 'wifi_direct_transfer_complete' &&
        event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'PASS${event.secure == true ? ' (BLE-authorized + encrypted)' : ''}: '
            '${_formatBytes(event.bytes)} verified at '
            '${_formatRate(event.throughputBps)} '
            '(connection setup ${event.setupMs ?? '?'} ms)';
        _wifiDirectBusyToken = null;
      });
    } else if (event.type == 'wifi_direct_transfer_received' &&
        event.token != null) {
      setState(() {
        _wifiDirectStatusByToken[event.token!] =
            'PASS${event.secure == true ? ' (encrypted)' : ''}: '
            '${_formatBytes(event.bytes)} received and verified at '
            '${_formatRate(event.throughputBps)}';
      });
    } else if (event.type == 'wifi_direct_error') {
      setState(() {
        _wifiDirectError =
            event.message ?? event.code ?? 'Wi-Fi Direct failed.';
        if (event.token != null) {
          _wifiDirectStatusByToken[event.token!] = _wifiDirectError!;
        }
        _wifiDirectBusyToken = null;
        _linkBusyToken = null;
      });
    } else if (event.type == 'wifi_direct_stopped') {
      setState(() {
        _isWifiDirectActive = false;
        _wifiDirectBusyToken = null;
        _wifiDirectInfo = null;
      });
    } else if (event.type == 'error') {
      setState(() {
        _discoveryError =
            event.message ?? event.code ?? 'BLE discovery failed.';
        _isDiscovering = false;
      });
    }
  }

  String _formatBytes(int? bytes) {
    if (bytes == null) return 'unknown bytes';
    if (bytes >= 1024 && bytes % 1024 == 0) return '${bytes ~/ 1024} KB';
    return '$bytes bytes';
  }

  String _formatRate(int? bytesPerSecond) {
    if (bytesPerSecond == null) return 'unknown speed';
    if (bytesPerSecond >= 1024 * 1024) {
      return '${(bytesPerSecond / (1024 * 1024)).toStringAsFixed(1)} MB/s';
    }
    if (bytesPerSecond >= 1024) {
      return '${(bytesPerSecond / 1024).toStringAsFixed(1)} KB/s';
    }
    return '$bytesPerSecond B/s';
  }

  Future<void> _toggleDiscovery() async {
    if (_isChangingDiscovery) return;
    setState(() {
      _isChangingDiscovery = true;
      _discoveryError = null;
    });
    try {
      if (_isDiscovering) {
        await widget.platform.stopBleDiscovery();
        if (!mounted) return;
        setState(() {
          _isDiscovering = false;
          _localToken = null;
          _nearbyPeers.clear();
          _linkStatusByToken.clear();
          _fingerprintByToken.clear();
          _identityProtectionByToken.clear();
          _trustStateByToken.clear();
        });
      } else {
        final granted = await widget.platform.requestRadioPermissions();
        if (!granted) {
          throw StateError('Nearby Devices permission was not granted.');
        }
        final token = await widget.platform.startBleDiscovery();
        if (!mounted) return;
        setState(() {
          _localToken = token;
          _isDiscovering = true;
          _nearbyPeers.clear();
          _linkStatusByToken.clear();
          _fingerprintByToken.clear();
          _identityProtectionByToken.clear();
          _trustStateByToken.clear();
        });
      }
    } on Object catch (error) {
      if (!mounted) return;
      setState(() => _discoveryError = error.toString());
    } finally {
      if (mounted) setState(() => _isChangingDiscovery = false);
    }
  }

  Future<void> _sendEngineeringTransfer(String peerToken) async {
    if (_linkBusyToken != null) return;
    setState(() {
      _linkBusyToken = peerToken;
      _linkStatusByToken[peerToken] = 'Starting direct link…';
    });
    try {
      await widget.platform.sendEngineeringTransfer(peerToken);
    } on Object catch (error) {
      if (!mounted) return;
      setState(() {
        _linkBusyToken = null;
        _linkStatusByToken[peerToken] = error.toString();
      });
    }
  }

  Future<void> _sendTamperTest(String peerToken) async {
    if (_linkBusyToken != null) return;
    setState(() {
      _linkBusyToken = peerToken;
      _linkStatusByToken[peerToken] = 'Starting tamper-rejection test...';
    });
    try {
      await widget.platform.sendTamperedEngineeringTransfer(peerToken);
    } on Object catch (error) {
      if (!mounted) return;
      setState(() {
        _linkBusyToken = null;
        _linkStatusByToken[peerToken] = error.toString();
      });
    }
  }

  Future<void> _markPeerVerified(String peerToken) async {
    setState(() {
      _linkStatusByToken[peerToken] = 'Saving fingerprint verification...';
    });
    try {
      await widget.platform.markPeerVerified(peerToken);
    } on Object catch (error) {
      if (!mounted) return;
      setState(() => _linkStatusByToken[peerToken] = error.toString());
    }
  }

  Future<void> _sendTextMessage(String peerToken, String text) async {
    if (_linkBusyToken != null || text.trim().isEmpty) return;
    final wifiPeerToken = _isWifiDirectActive && _wifiDirectPeers.length == 1
        ? _wifiDirectPeers.keys.single
        : null;
    setState(() {
      _linkBusyToken = peerToken;
      _linkStatusByToken[peerToken] = wifiPeerToken == null
          ? 'Auto-selected BLE; preparing encrypted message...'
          : 'Auto-selected the verified high-speed Wi-Fi path...';
      if (wifiPeerToken != null) {
        _wifiDirectBusyToken = wifiPeerToken;
        _wifiDirectStatusByToken[wifiPeerToken] =
            'Preparing a real encrypted message...';
      }
    });
    try {
      if (wifiPeerToken == null) {
        await widget.platform.sendTextMessage(peerToken, text);
      } else {
        await widget.platform.sendWifiTextMessage(
          peerToken,
          wifiPeerToken,
          text,
        );
      }
    } on Object catch (error) {
      if (!mounted) return;
      setState(() {
        _linkBusyToken = null;
        _linkStatusByToken[peerToken] = error.toString();
        if (wifiPeerToken != null) {
          _wifiDirectBusyToken = null;
          _wifiDirectStatusByToken[wifiPeerToken] = error.toString();
        }
      });
    }
  }

  Future<void> _retryQueuedMessage(StoredTextMessage message) async {
    if (_linkBusyToken != null || message.status != 'queued') return;
    String? peerToken;
    for (final entry in _fingerprintByToken.entries) {
      if (entry.value == message.peerFingerprint) {
        peerToken = entry.key;
        break;
      }
    }
    peerToken ??= _nearbyPeers.length == 1 ? _nearbyPeers.keys.single : null;
    if (peerToken == null) {
      setState(() {
        _discoveryError = _nearbyPeers.isEmpty
            ? 'Bring the recipient phone nearby and start BLE on both phones.'
            : 'More than one unknown phone is nearby. Open a verified peer first, then retry.';
      });
      return;
    }
    final selectedPeerToken = peerToken;
    setState(() {
      _discoveryError = null;
      _linkBusyToken = selectedPeerToken;
      _linkStatusByToken[selectedPeerToken] =
          'Checking the recipient identity, then retrying the saved message...';
    });
    try {
      await widget.platform.retryTextMessage(
        selectedPeerToken,
        message.messageId,
      );
    } on Object catch (error) {
      if (!mounted) return;
      setState(() {
        _linkBusyToken = null;
        _linkStatusByToken[selectedPeerToken] = error.toString();
      });
      unawaited(_loadStoredMessages());
    }
  }

  Future<void> _loadStoredMessages() async {
    try {
      final messages = await widget.platform.getStoredMessages();
      if (mounted) setState(() => _storedMessages = messages);
    } on Object catch (error) {
      if (mounted) setState(() => _discoveryError = error.toString());
    }
  }

  Future<void> _loadContacts() async {
    try {
      final contacts = await widget.platform.getRelayContacts();
      if (mounted) setState(() => _contacts = contacts);
    } on Object catch (error) {
      if (mounted) setState(() => _lastCopyStatus = error.toString());
    }
  }

  Future<void> _queueLastCopyDiagnostic(RelayContact contact) async {
    if (_lastCopyBusyFingerprint != null) return;
    final suffix = DateTime.now().millisecondsSinceEpoch
        .toRadixString(16)
        .toUpperCase();
    final text = 'LAST-COPY-PROBE-${suffix.substring(suffix.length - 6)}';
    setState(() {
      _lastCopyBusyFingerprint = contact.fingerprint;
      _lastCopyStatus = 'Creating one private final-copy envelope...';
    });
    try {
      final queued = await widget.platform.queueLastCopyDiagnosticText(
        contact.fingerprint,
        text,
      );
      if (!mounted) return;
      setState(() {
        _lastCopyStatus =
            'Queued $text for ${contact.displayName}. Message ID '
            '${queued.messageId.length > 8 ? queued.messageId.substring(0, 8) : queued.messageId}.';
      });
      unawaited(_loadStoredMessages());
    } on Object catch (error) {
      if (mounted) setState(() => _lastCopyStatus = error.toString());
    } finally {
      if (mounted) setState(() => _lastCopyBusyFingerprint = null);
    }
  }

  Future<void> _toggleWifiDirect() async {
    if (_isChangingWifiDirect) return;
    setState(() {
      _isChangingWifiDirect = true;
      _wifiDirectError = null;
    });
    try {
      if (_isWifiDirectActive) {
        await widget.platform.stopWifiDirect();
        if (!mounted) return;
        setState(() {
          _isWifiDirectActive = false;
          _localWifiDirectToken = null;
          _wifiDirectPeers.clear();
          _wifiDirectStatusByToken.clear();
          _wifiDirectInfo = null;
        });
      } else {
        final granted = await widget.platform.requestWifiDirectPermissions();
        if (!granted) {
          throw StateError('Nearby Wi-Fi permission was not granted.');
        }
        final token = await widget.platform.startWifiDirect();
        if (!mounted) return;
        setState(() {
          _localWifiDirectToken = token;
          _isWifiDirectActive = true;
          _wifiDirectPeers.clear();
          _wifiDirectStatusByToken.clear();
          _wifiDirectInfo =
              'Looking for outgoing peers. This phone is already ready to receive.';
        });
      }
    } on Object catch (error) {
      if (mounted) setState(() => _wifiDirectError = error.toString());
    } finally {
      if (mounted) setState(() => _isChangingWifiDirect = false);
    }
  }

  Future<void> _runWifiDirectSpeedTest(String peerToken) async {
    if (_wifiDirectBusyToken != null) return;
    setState(() {
      _wifiDirectBusyToken = peerToken;
      _wifiDirectStatusByToken[peerToken] =
          'Preparing 4 MB random speed payload...';
    });
    try {
      await widget.platform.runWifiDirectSpeedTest(peerToken);
    } on Object catch (error) {
      if (!mounted) return;
      setState(() {
        _wifiDirectBusyToken = null;
        _wifiDirectStatusByToken[peerToken] = error.toString();
      });
    }
  }

  Future<void> _runSecureWifiDirectSpeedTest(String wifiPeerToken) async {
    if (_wifiDirectBusyToken != null || _linkBusyToken != null) return;
    if (!_isDiscovering || _nearbyPeers.length != 1) {
      setState(() {
        _wifiDirectStatusByToken[wifiPeerToken] =
            'Keep BLE discovery active with exactly one nearby Hypha phone.';
      });
      return;
    }
    final blePeerToken = _nearbyPeers.keys.single;
    setState(() {
      _wifiDirectBusyToken = wifiPeerToken;
      _linkBusyToken = blePeerToken;
      _wifiDirectStatusByToken[wifiPeerToken] =
          'Authorizing a one-time Wi-Fi key through verified BLE...';
      _linkStatusByToken[blePeerToken] =
          'Authorizing encrypted Wi-Fi upgrade...';
    });
    try {
      await widget.platform.authorizeWifiUpgrade(blePeerToken, wifiPeerToken);
    } on Object catch (error) {
      if (!mounted) return;
      setState(() {
        _wifiDirectBusyToken = null;
        _linkBusyToken = null;
        _wifiDirectStatusByToken[wifiPeerToken] = error.toString();
      });
    }
  }

  Future<void> _runProbe() async {
    setState(() {
      _isProbing = true;
      _probeError = null;
    });
    try {
      var capabilities = await widget.platform.probeRadioCapabilities();
      if (capabilities.permissionRequired) {
        final granted = await widget.platform.requestRadioPermissions();
        if (granted) {
          capabilities = await widget.platform.probeRadioCapabilities();
        }
      }
      if (!mounted) return;
      setState(() => _capabilities = capabilities);
    } on Object catch (error) {
      if (!mounted) return;
      setState(() => _probeError = error);
    } finally {
      if (mounted) setState(() => _isProbing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Hypha Protocol Lab'),
        actions: const [
          Padding(
            padding: EdgeInsets.only(right: 16),
            child: Center(child: _PhaseBadge()),
          ),
        ],
      ),
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final horizontalPadding = constraints.maxWidth >= 720 ? 32.0 : 16.0;
            return SingleChildScrollView(
              padding: EdgeInsets.fromLTRB(
                horizontalPadding,
                16,
                horizontalPadding,
                32,
              ),
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 720),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _IntroCard(theme: theme),
                      const SizedBox(height: 24),
                      Text(
                        'Foundation status',
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 12),
                      const _FoundationCard(),
                      const SizedBox(height: 24),
                      _ProbeHeader(isProbing: _isProbing, onProbe: _runProbe),
                      const SizedBox(height: 12),
                      _CapabilityCard(
                        capabilities: _capabilities,
                        error: _probeError,
                        onRetry: _runProbe,
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'Live BLE discovery',
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 12),
                      _DiscoveryCard(
                        isDiscovering: _isDiscovering,
                        isChanging: _isChangingDiscovery,
                        localToken: _localToken,
                        peers: _nearbyPeers.values.toList(),
                        linkStatusByToken: _linkStatusByToken,
                        fingerprintByToken: _fingerprintByToken,
                        identityProtectionByToken: _identityProtectionByToken,
                        trustStateByToken: _trustStateByToken,
                        linkBusyToken: _linkBusyToken,
                        error: _discoveryError,
                        onToggle: _toggleDiscovery,
                        onPing: _sendEngineeringTransfer,
                        onTamper: _sendTamperTest,
                        onVerify: _markPeerVerified,
                        messageController: _messageController,
                        onSendMessage: _sendTextMessage,
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'Offline messages',
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 12),
                      _MessageHistoryCard(
                        messages: _storedMessages,
                        canRetry:
                            _isDiscovering &&
                            _nearbyPeers.isNotEmpty &&
                            _linkBusyToken == null,
                        onRetry: _retryQueuedMessage,
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'Private last-copy routing',
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 12),
                      _LastCopyDiagnosticCard(
                        contacts: _contacts
                            .where(
                              (contact) => contact.verified && contact.ready,
                            )
                            .toList(growable: false),
                        busyFingerprint: _lastCopyBusyFingerprint,
                        status: _lastCopyStatus,
                        onQueue: _queueLastCopyDiagnostic,
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'High-speed offline link',
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 12),
                      _WifiDirectCard(
                        isActive: _isWifiDirectActive,
                        isChanging: _isChangingWifiDirect,
                        localToken: _localWifiDirectToken,
                        peers: _wifiDirectPeers.values.toList(),
                        statusByToken: _wifiDirectStatusByToken,
                        busyToken: _wifiDirectBusyToken,
                        error: _wifiDirectError,
                        info: _wifiDirectInfo,
                        onToggle: _toggleWifiDirect,
                        onRunTest: _runWifiDirectSpeedTest,
                        onRunSecureTest: _runSecureWifiDirectSpeedTest,
                        canAuthorize:
                            _isDiscovering && _nearbyPeers.length == 1,
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'Next engineering gates',
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 12),
                      const _GateCard(),
                    ],
                  ),
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}

class _LastCopyDiagnosticCard extends StatelessWidget {
  const _LastCopyDiagnosticCard({
    required this.contacts,
    required this.busyFingerprint,
    required this.status,
    required this.onQueue,
  });

  final List<RelayContact> contacts;
  final String? busyFingerprint;
  final String? status;
  final ValueChanged<RelayContact> onQueue;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(Icons.route_rounded, color: colors.primary),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Recipient-only final-copy test',
                    style: theme.textTheme.titleMedium,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'Turn the selected recipient\'s Bluetooth off first. Hypha will '
              'offer only an anonymous routing hint; other phones must reject '
              'it without storing the encrypted message.',
            ),
            if (contacts.isEmpty) ...[
              const SizedBox(height: 12),
              const Text('No ready and verified contacts are stored yet.'),
            ],
            for (final contact in contacts) ...[
              const SizedBox(height: 12),
              OutlinedButton.icon(
                key: ValueKey('last_copy_${contact.fingerprint}'),
                onPressed: busyFingerprint == null
                    ? () => onQueue(contact)
                    : null,
                icon: busyFingerprint == contact.fingerprint
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.lock_person_rounded),
                label: Text(
                  'Queue for ${contact.displayName} • '
                  '${contact.fingerprint.substring(contact.fingerprint.length - 6)}',
                ),
              ),
            ],
            if (status != null) ...[
              const SizedBox(height: 12),
              Text(status!, style: TextStyle(color: colors.primary)),
            ],
          ],
        ),
      ),
    );
  }
}

class _DiscoveryCard extends StatelessWidget {
  const _DiscoveryCard({
    required this.isDiscovering,
    required this.isChanging,
    required this.localToken,
    required this.peers,
    required this.linkStatusByToken,
    required this.fingerprintByToken,
    required this.identityProtectionByToken,
    required this.trustStateByToken,
    required this.linkBusyToken,
    required this.error,
    required this.onToggle,
    required this.onPing,
    required this.onTamper,
    required this.onVerify,
    required this.messageController,
    required this.onSendMessage,
  });

  final bool isDiscovering;
  final bool isChanging;
  final String? localToken;
  final List<BleDiscoveryEvent> peers;
  final Map<String, String> linkStatusByToken;
  final Map<String, String> fingerprintByToken;
  final Map<String, String> identityProtectionByToken;
  final Map<String, String> trustStateByToken;
  final String? linkBusyToken;
  final String? error;
  final VoidCallback onToggle;
  final ValueChanged<String> onPing;
  final ValueChanged<String> onTamper;
  final ValueChanged<String> onVerify;
  final TextEditingController messageController;
  final void Function(String peerToken, String text) onSendMessage;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(
                  isDiscovering
                      ? Icons.bluetooth_searching_rounded
                      : Icons.bluetooth_disabled_rounded,
                  color: isDiscovering
                      ? colors.primary
                      : colors.onSurfaceVariant,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    isDiscovering
                        ? 'Advertising and scanning'
                        : 'Discovery is stopped',
                    style: theme.textTheme.titleMedium,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              isDiscovering
                  ? 'Nearby Hypha phones: ${peers.length}. Keep this screen open during the test.'
                  : 'Starts an anonymous foreground BLE beacon for the two-phone test.',
            ),
            if (localToken != null) ...[
              const SizedBox(height: 8),
              Text(
                'This session: ${localToken!.substring(localToken!.length - 6)}',
                style: theme.textTheme.bodySmall,
              ),
            ],
            if (error != null) ...[
              const SizedBox(height: 12),
              Text(error!, style: TextStyle(color: colors.error)),
            ],
            if (peers.isNotEmpty) ...[
              const SizedBox(height: 12),
              for (final peer in peers)
                Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      ListTile(
                        contentPadding: EdgeInsets.zero,
                        leading: const Icon(Icons.phone_android_rounded),
                        title: Text(
                          'Hypha phone ${peer.token!.substring(peer.token!.length - 6)}',
                        ),
                        subtitle: Text(
                          [
                            'Signal ${peer.rssi} dBm • ${peer.primaryPhy ?? 'unknown'} PHY',
                            if (fingerprintByToken[peer.token!] != null)
                              'Safety fingerprint (${identityProtectionByToken[peer.token!] ?? 'unknown protection'}): '
                                  '${fingerprintByToken[peer.token!]}',
                            ?linkStatusByToken[peer.token!],
                          ].join('\n'),
                        ),
                      ),
                      OutlinedButton.icon(
                        onPressed: linkBusyToken == null
                            ? () => onPing(peer.token!)
                            : null,
                        icon: linkBusyToken == peer.token
                            ? const SizedBox.square(
                                dimension: 18,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : const Icon(Icons.cable_rounded),
                        label: const Text('Test encrypted BLE transfer'),
                      ),
                      const SizedBox(height: 8),
                      TextButton.icon(
                        onPressed: linkBusyToken == null
                            ? () => onTamper(peer.token!)
                            : null,
                        icon: const Icon(Icons.gpp_bad_outlined),
                        label: const Text('Test tamper rejection'),
                      ),
                      if (fingerprintByToken[peer.token!] != null) ...[
                        const SizedBox(height: 8),
                        if (trustStateByToken[peer.token!] == 'verified')
                          Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              const Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(Icons.verified_user_outlined, size: 20),
                                  SizedBox(width: 8),
                                  Text('Fingerprint verified on this device'),
                                ],
                              ),
                              const SizedBox(height: 12),
                              TextField(
                                controller: messageController,
                                maxLines: 3,
                                minLines: 1,
                                maxLength: 2048,
                                textInputAction: TextInputAction.newline,
                                decoration: const InputDecoration(
                                  border: OutlineInputBorder(),
                                  labelText: 'Offline message',
                                  hintText: 'Type a message',
                                ),
                              ),
                              FilledButton.icon(
                                onPressed: linkBusyToken == null
                                    ? () => onSendMessage(
                                        peer.token!,
                                        messageController.text,
                                      )
                                    : null,
                                icon: const Icon(Icons.send_rounded),
                                label: const Text('Send encrypted message'),
                              ),
                            ],
                          )
                        else
                          OutlinedButton.icon(
                            onPressed: () => onVerify(peer.token!),
                            icon: const Icon(Icons.fact_check_outlined),
                            label: const Text(
                              'Mark compared fingerprint verified',
                            ),
                          ),
                      ],
                    ],
                  ),
                ),
            ],
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: isChanging ? null : onToggle,
              icon: isChanging
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Icon(
                      isDiscovering
                          ? Icons.stop_rounded
                          : Icons.play_arrow_rounded,
                    ),
              label: Text(isDiscovering ? 'Stop BLE test' : 'Start BLE test'),
            ),
          ],
        ),
      ),
    );
  }
}

class _MessageHistoryCard extends StatelessWidget {
  const _MessageHistoryCard({
    required this.messages,
    required this.canRetry,
    required this.onRetry,
  });

  final List<StoredTextMessage> messages;
  final bool canRetry;
  final ValueChanged<StoredTextMessage> onRetry;

  @override
  Widget build(BuildContext context) {
    if (messages.isEmpty) {
      return const Card(
        child: Padding(
          padding: EdgeInsets.all(20),
          child: Text(
            'No messages yet. Verified offline messages will appear here.',
          ),
        ),
      );
    }
    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(
          children: [
            for (final message in messages)
              ListTile(
                leading: Icon(
                  message.direction == 'outgoing'
                      ? Icons.north_east_rounded
                      : Icons.south_west_rounded,
                ),
                title: Text(message.text),
                subtitle: Text(
                  '${message.direction} • ${message.status} • '
                  '${message.messageId.length > 8 ? message.messageId.substring(0, 8) : message.messageId}',
                ),
                trailing:
                    message.direction == 'outgoing' &&
                        message.status == 'queued'
                    ? TextButton(
                        key: ValueKey('retry_${message.messageId}'),
                        onPressed: canRetry ? () => onRetry(message) : null,
                        child: const Text('Retry'),
                      )
                    : null,
              ),
          ],
        ),
      ),
    );
  }
}

class _WifiDirectCard extends StatelessWidget {
  const _WifiDirectCard({
    required this.isActive,
    required this.isChanging,
    required this.localToken,
    required this.peers,
    required this.statusByToken,
    required this.busyToken,
    required this.error,
    required this.info,
    required this.onToggle,
    required this.onRunTest,
    required this.onRunSecureTest,
    required this.canAuthorize,
  });

  final bool isActive;
  final bool isChanging;
  final String? localToken;
  final List<BleDiscoveryEvent> peers;
  final Map<String, String> statusByToken;
  final String? busyToken;
  final String? error;
  final String? info;
  final VoidCallback onToggle;
  final ValueChanged<String> onRunTest;
  final ValueChanged<String> onRunSecureTest;
  final bool canAuthorize;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(Icons.wifi_tethering_rounded, color: colors.primary),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    isActive
                        ? 'High-speed offline Wi-Fi ready'
                        : 'High-speed path stopped',
                    style: theme.textTheme.titleMedium,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              'Hypha uses BLE to verify the phone, then opens encrypted Wi-Fi '
              'automatically for fast transfers. No router or internet is needed.',
            ),
            if (localToken != null) ...[
              const SizedBox(height: 8),
              Text(
                'This Wi-Fi session: ${localToken!.substring(localToken!.length - 6)}',
                style: theme.textTheme.bodySmall,
              ),
            ],
            if (isActive && peers.isEmpty) ...[
              const SizedBox(height: 12),
              const Text(
                'No outgoing peer listing yet. This phone can still receive an '
                'incoming Hypha connection, and discovery retries automatically.',
              ),
            ],
            if (info != null) ...[
              const SizedBox(height: 12),
              Text(info!, style: TextStyle(color: colors.primary)),
            ],
            if (error != null) ...[
              const SizedBox(height: 12),
              Text(error!, style: TextStyle(color: colors.error)),
            ],
            for (final peer in peers) ...[
              const SizedBox(height: 12),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.phone_android_rounded),
                title: Text(
                  'Hypha Wi-Fi peer ${peer.token!.substring(peer.token!.length - 6)}',
                ),
                subtitle: statusByToken[peer.token!] == null
                    ? Text(
                        peer.limited == true
                            ? 'Ready. Android gave a basic record; BLE will securely resolve the rest.'
                            : 'Ready for outgoing secure Wi-Fi',
                      )
                    : Text(statusByToken[peer.token!]!),
              ),
              OutlinedButton.icon(
                onPressed: busyToken == null
                    ? () => onRunTest(peer.token!)
                    : null,
                icon: busyToken == peer.token
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.speed_rounded),
                label: const Text('Diagnostic: raw 4 MB speed test'),
              ),
              const SizedBox(height: 8),
              FilledButton.tonalIcon(
                onPressed: busyToken == null && canAuthorize
                    ? () => onRunSecureTest(peer.token!)
                    : null,
                icon: busyToken == peer.token
                    ? const SizedBox.square(
                        dimension: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.enhanced_encryption_rounded),
                label: const Text('Diagnostic: secure 4 MB test'),
              ),
              if (!canAuthorize) ...[
                const SizedBox(height: 6),
                const Text(
                  'Start BLE discovery with one nearby phone for the secure diagnostic.',
                ),
              ],
            ],
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: isChanging || busyToken != null ? null : onToggle,
              icon: isChanging
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Icon(
                      isActive ? Icons.stop_rounded : Icons.play_arrow_rounded,
                    ),
              label: Text(
                isActive
                    ? 'Disable high-speed Wi-Fi'
                    : 'Enable high-speed Wi-Fi',
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ProbeHeader extends StatelessWidget {
  const _ProbeHeader({required this.isProbing, required this.onProbe});

  final bool isProbing;
  final VoidCallback onProbe;

  @override
  Widget build(BuildContext context) {
    final title = Text(
      'This device',
      style: Theme.of(context).textTheme.titleLarge,
    );
    final button = FilledButton.icon(
      onPressed: isProbing ? null : onProbe,
      icon: isProbing
          ? const SizedBox.square(
              dimension: 18,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.radar_rounded),
      label: Text(isProbing ? 'Measuring' : 'Run device probe'),
    );
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [title, const SizedBox(height: 12), button],
          );
        }
        return Row(
          children: [
            Expanded(child: title),
            const SizedBox(width: 16),
            button,
          ],
        );
      },
    );
  }
}

class _PhaseBadge extends StatelessWidget {
  const _PhaseBadge();

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Semantics(
      label: 'Current project stage: Phase zero',
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: colors.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
          child: Text(
            'PHASE 0',
            style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: colors.onSurfaceVariant,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.8,
            ),
          ),
        ),
      ),
    );
  }
}

class _IntroCard extends StatelessWidget {
  const _IntroCard({required this.theme});

  final ThemeData theme;

  @override
  Widget build(BuildContext context) {
    final colors = theme.colorScheme;
    return Card(
      color: colors.primaryContainer,
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.hub_rounded, size: 36, color: colors.onPrimaryContainer),
            const SizedBox(height: 16),
            Text(
              'The internet is optional.',
              style: theme.textTheme.headlineMedium?.copyWith(
                color: colors.onPrimaryContainer,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'We are validating the protocol, device radios, and delivery guarantees before building the messenger interface.',
              style: theme.textTheme.bodyLarge?.copyWith(
                color: colors.onPrimaryContainer,
                height: 1.5,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _FoundationCard extends StatelessWidget {
  const _FoundationCard();

  @override
  Widget build(BuildContext context) {
    return const Card(
      child: Padding(
        padding: EdgeInsets.symmetric(vertical: 8),
        child: Column(
          children: [
            _StatusRow(
              icon: Icons.check_circle_outline_rounded,
              title: 'Flutter product shell',
              detail: 'Android project and accessible theme ready',
              state: 'READY',
            ),
            Divider(height: 1),
            _StatusRow(
              icon: Icons.memory_rounded,
              title: 'Rust protocol workspace',
              detail: 'Wire, router, core, simulator, and bridge crates',
              state: 'BUILDING',
            ),
            Divider(height: 1),
            _StatusRow(
              icon: Icons.bluetooth_searching_rounded,
              title: 'Native Android radio layer',
              detail: 'Capability probe first; live discovery follows',
              state: 'PROBE',
            ),
          ],
        ),
      ),
    );
  }
}

class _StatusRow extends StatelessWidget {
  const _StatusRow({
    required this.icon,
    required this.title,
    required this.detail,
    required this.state,
  });

  final IconData icon;
  final String title;
  final String detail;
  final String state;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: colors.primary, semanticLabel: '$title status'),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: theme.textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(detail, style: theme.textTheme.bodyMedium),
              ],
            ),
          ),
          const SizedBox(width: 8),
          Text(
            state,
            style: theme.textTheme.labelSmall?.copyWith(
              color: colors.primary,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.6,
            ),
          ),
        ],
      ),
    );
  }
}

class _CapabilityCard extends StatelessWidget {
  const _CapabilityCard({
    required this.capabilities,
    required this.error,
    required this.onRetry,
  });

  final RadioCapabilities? capabilities;
  final Object? error;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    if (error != null) {
      final colors = Theme.of(context).colorScheme;
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.error_outline_rounded, color: colors.error),
                  const SizedBox(width: 8),
                  const Expanded(child: Text('Device probe could not finish.')),
                ],
              ),
              const SizedBox(height: 8),
              const Text(
                'Check that this build is running on Android, then try again.',
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: onRetry,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('Retry probe'),
              ),
            ],
          ),
        ),
      );
    }
    if (capabilities == null) {
      return const Card(
        child: Padding(
          padding: EdgeInsets.all(20),
          child: Row(
            children: [
              Icon(Icons.phone_android_rounded),
              SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Not measured yet. Run the probe on a physical Android phone to record its offline-radio capabilities.',
                ),
              ),
            ],
          ),
        ),
      );
    }

    final items = <(String, bool)>[
      ('Bluetooth present', capabilities!.bluetoothPresent),
      ('Bluetooth enabled', capabilities!.bluetoothEnabled),
      ('Multiple advertising', capabilities!.multipleAdvertisementSupported),
      ('BLE 2M PHY', capabilities!.le2MPhySupported),
      ('BLE Coded PHY', capabilities!.leCodedPhySupported),
      ('Extended advertising', capabilities!.extendedAdvertisingSupported),
      ('Wi-Fi Aware', capabilities!.wifiAwareSupported),
      ('Wi-Fi Direct', capabilities!.wifiDirectSupported),
      ('Wi-Fi enabled', capabilities!.wifiEnabled),
      ('Android ranging API', capabilities!.rangingApiAvailable),
      ('Rust secure core', capabilities!.secureCoreReady),
    ];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Android API ${capabilities!.sdkInt}'),
            if (capabilities!.permissionRequired) ...[
              const SizedBox(height: 8),
              const Text(
                'Nearby-device permission is required for complete results.',
              ),
            ],
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (final item in items)
                  Chip(
                    avatar: Icon(
                      item.$2 ? Icons.check_rounded : Icons.close_rounded,
                      size: 18,
                    ),
                    label: Text(item.$1),
                  ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _GateCard extends StatelessWidget {
  const _GateCard();

  @override
  Widget build(BuildContext context) {
    return const Card(
      child: Padding(
        padding: EdgeInsets.symmetric(vertical: 8),
        child: Column(
          children: [
            ListTile(
              leading: Icon(Icons.compare_arrows_rounded),
              title: Text('Reconciliation shootout'),
              subtitle: Text(
                'Rateless IBLT vs Minisketch vs deterministic fallback',
              ),
            ),
            Divider(height: 1),
            ListTile(
              leading: Icon(Icons.route_rounded),
              title: Text('Routing simulator'),
              subtitle: Text('Flood, spray-and-wait, and encounter scoring'),
            ),
            Divider(height: 1),
            ListTile(
              leading: Icon(Icons.security_rounded),
              title: Text('Direct encrypted link'),
              subtitle: Text('Only after parser and transport invariants pass'),
            ),
          ],
        ),
      ),
    );
  }
}
