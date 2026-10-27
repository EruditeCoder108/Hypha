import 'package:flutter/material.dart';
import 'package:relay_mobile/src/features/messenger/models/conversation_summary.dart';
import 'package:relay_mobile/src/features/messenger/widgets/status_badge.dart';

class ConversationTile extends StatelessWidget {
  const ConversationTile({
    super.key,
    required this.summary,
    required this.onTap,
  });

  final ConversationSummary summary;
  final VoidCallback onTap;

  String _formatDate(int epochMs) {
    if (epochMs <= 0) return '';
    final dt = DateTime.fromMillisecondsSinceEpoch(epochMs);
    final now = DateTime.now();
    if (dt.year == now.year && dt.month == now.month && dt.day == now.day) {
      final hour = dt.hour.toString().padLeft(2, '0');
      final minute = dt.minute.toString().padLeft(2, '0');
      return '$hour:$minute';
    }
    return '${dt.month}/${dt.day}';
  }

  String _avatarInitial(String label) {
    final trimmed = label.trim();
    if (trimmed.isEmpty) return 'H';
    final firstChar = trimmed.substring(0, 1).toUpperCase();
    if (RegExp(r'[A-Z0-9]').hasMatch(firstChar)) {
      return firstChar;
    }
    return 'H';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final lastMsg = summary.lastMessage;
    final isOutgoing = lastMsg.direction == 'outgoing';
    final timeText = _formatDate(lastMsg.createdAtMs);
    final initial = _avatarInitial(summary.displayLabel);
    final isUnread = summary.unreadCount > 0;
    final displayUnread = summary.unreadCount > 99
        ? '99+'
        : '${summary.unreadCount}';
    final unreadSemantic = isUnread
        ? '${summary.unreadCount} unread message${summary.unreadCount == 1 ? '' : 's'}. '
        : '';
    final avatarColors = [
      scheme.primaryContainer,
      scheme.tertiaryContainer,
      scheme.surfaceContainerHigh,
      scheme.surfaceContainerHighest,
    ];
    final avatarColor =
        avatarColors[summary.displayLabel.hashCode.abs() % avatarColors.length];

    return Semantics(
      button: true,
      label:
          '${summary.displayLabel}. $unreadSemantic${isOutgoing ? "You: " : ""}${lastMsg.text}. ${timeText.isNotEmpty ? "Sent $timeText" : ""}',
      child: InkWell(
        onTap: onTap,
        child: Container(
          constraints: const BoxConstraints(minHeight: 86),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
          decoration: BoxDecoration(
            border: Border(
              bottom: BorderSide(
                color: scheme.outlineVariant.withValues(alpha: 0.4),
              ),
            ),
          ),
          child: Row(
            children: [
              CircleAvatar(
                radius: 29,
                backgroundColor: avatarColor,
                foregroundColor: scheme.onSurface,
                child: Text(
                  initial,
                  style: theme.textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w700,
                    color: scheme.onSurface,
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Expanded(
                          child: Text(
                            summary.displayLabel,
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: isUnread
                                  ? FontWeight.bold
                                  : FontWeight.w600,
                              fontSize: 17,
                              height: 1.25,
                              color: scheme.onSurface,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (timeText.isNotEmpty) ...[
                          const SizedBox(width: 8),
                          Text(
                            timeText,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: isUnread
                                  ? scheme.primary
                                  : scheme.onSurfaceVariant,
                              fontSize: 12,
                              fontWeight: isUnread
                                  ? FontWeight.bold
                                  : FontWeight.w500,
                            ),
                          ),
                        ],
                      ],
                    ),
                    const SizedBox(height: 6),
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            lastMsg.text,
                            style: theme.textTheme.bodyMedium?.copyWith(
                              color: isUnread
                                  ? scheme.onSurface
                                  : scheme.onSurfaceVariant,
                              fontSize: 15,
                              fontWeight: isUnread
                                  ? FontWeight.w600
                                  : FontWeight.normal,
                              height: 1.3,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (isOutgoing) ...[
                          const SizedBox(width: 8),
                          StatusBadge(status: lastMsg.status, compact: true),
                        ],
                        if (isUnread) ...[
                          const SizedBox(width: 10),
                          ExcludeSemantics(
                            child: Badge(
                              backgroundColor: scheme.primary,
                              textColor: scheme.onPrimary,
                              largeSize: 22,
                              padding: const EdgeInsets.symmetric(
                                horizontal: 7,
                              ),
                              label: Text(
                                displayUnread,
                                style: const TextStyle(
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
