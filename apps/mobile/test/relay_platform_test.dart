import 'package:flutter_test/flutter_test.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

void main() {
  test('parses peer events without any Bluetooth address or device name', () {
    final event = BleDiscoveryEvent.fromMap(const {
      'type': 'peer_seen',
      'token': '0011223344556677',
      'rssi': -61,
      'primaryPhy': '1M',
    });

    expect(event.type, 'peer_seen');
    expect(event.token, '0011223344556677');
    expect(event.rssi, -61);
    expect(event.primaryPhy, '1M');
  });

  test('parses encrypted text delivery events', () {
    final event = BleDiscoveryEvent.fromMap(const {
      'type': 'text_message_delivered',
      'token': '0011223344556677',
      'messageId': '00112233445566778899aabbccddeeff',
      'text': 'hello offline',
      'fingerprint': 'AA-BB',
    });

    expect(event.messageId, '00112233445566778899aabbccddeeff');
    expect(event.text, 'hello offline');
    expect(event.fingerprint, 'AA-BB');
  });

  test('parses privacy-preserving service-only Wi-Fi peers', () {
    final event = BleDiscoveryEvent.fromMap(const {
      'type': 'wifi_direct_peer_seen',
      'token': '8899aabbccddeeff',
      'discovery': 'service_only',
      'limited': true,
    });

    expect(event.token, '8899aabbccddeeff');
    expect(event.discovery, 'service_only');
    expect(event.limited, isTrue);
  });

  test('parses durable queued message retry metadata', () {
    final message = StoredTextMessage.fromMap(const {
      'messageId': '00112233445566778899aabbccddeeff',
      'peerFingerprint': 'AA-BB-CC',
      'direction': 'outgoing',
      'text': 'survives restart',
      'status': 'queued',
      'createdAtMs': 1000,
      'attemptCount': 3,
      'conversationSequence': 7,
      'lastAttemptAtMs': 2000,
      'nextAttemptAtMs': 4000,
      'lastErrorCode': 'gatt_timeout',
    });

    expect(message.status, 'queued');
    expect(message.attemptCount, 3);
    expect(message.conversationSequence, 7);
    expect(message.nextAttemptAtMs, 4000);
    expect(message.lastErrorCode, 'gatt_timeout');
  });

  test('parses automatic outbox retry events', () {
    final event = BleDiscoveryEvent.fromMap(const {
      'type': 'text_message_retrying',
      'token': '0011223344556677',
      'messageId': '00112233445566778899aabbccddeeff',
      'attemptCount': 2,
      'automatic': true,
    });

    expect(event.automatic, isTrue);
    expect(event.attemptCount, 2);
  });

  test('parses fixed-node durable mesh-change evidence', () {
    final event = BleDiscoveryEvent.fromMap(const {
      'type': 'fixed_node_sync_completed',
      'meshChanged': true,
    });

    expect(event.meshChanged, isTrue);
  });
}
