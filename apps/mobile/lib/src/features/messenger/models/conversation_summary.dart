import 'package:relay_mobile/src/platform/relay_platform.dart';

class ConversationSummary {
  const ConversationSummary({
    required this.peerFingerprint,
    required this.lastMessage,
    required this.messageCount,
    this.unreadCount = 0,
    this.contactName,
  });

  final String peerFingerprint;
  final StoredTextMessage lastMessage;
  final int messageCount;
  final int unreadCount;
  final String? contactName;

  factory ConversationSummary.fromStored(StoredConversationSummary summary) {
    return ConversationSummary(
      peerFingerprint: summary.peerFingerprint,
      lastMessage: summary.lastMessage,
      messageCount: summary.messageCount,
      unreadCount: summary.unreadCount,
    );
  }

  ConversationSummary copyWith({
    StoredTextMessage? lastMessage,
    int? messageCount,
    int? unreadCount,
    String? contactName,
  }) {
    return ConversationSummary(
      peerFingerprint: peerFingerprint,
      lastMessage: lastMessage ?? this.lastMessage,
      messageCount: messageCount ?? this.messageCount,
      unreadCount: unreadCount ?? this.unreadCount,
      contactName: contactName ?? this.contactName,
    );
  }

  String get displayLabel {
    if (contactName?.trim().isNotEmpty == true) return contactName!.trim();
    if (peerFingerprint.isEmpty) return 'Hypha device';
    final len = peerFingerprint.length;
    final suffix = len <= 4
        ? peerFingerprint
        : peerFingerprint.substring(len - 4);
    return 'Hypha device • $suffix';
  }

  static List<ConversationSummary> groupFromMessages(
    List<StoredTextMessage> messages, [
    Map<String, String> contactNames = const {},
  ]) {
    if (messages.isEmpty) return const [];

    final map = <String, List<StoredTextMessage>>{};
    for (final msg in messages) {
      map.putIfAbsent(msg.peerFingerprint, () => []).add(msg);
    }

    final summaries = <ConversationSummary>[];
    map.forEach((fingerprint, msgList) {
      // Sort message list by createdAtMs ascending so last element is latest
      msgList.sort((a, b) => a.createdAtMs.compareTo(b.createdAtMs));
      summaries.add(
        ConversationSummary(
          peerFingerprint: fingerprint,
          lastMessage: msgList.last,
          messageCount: msgList.length,
          unreadCount: msgList
              .where(
                (message) => message.direction == 'incoming' && !message.isRead,
              )
              .length,
          contactName: contactNames[fingerprint],
        ),
      );
    });

    // Sort conversations by latest message timestamp descending
    summaries.sort(
      (a, b) => b.lastMessage.createdAtMs.compareTo(a.lastMessage.createdAtMs),
    );

    return summaries;
  }
}
