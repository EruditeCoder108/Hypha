import 'package:flutter/material.dart';
import 'package:relay_mobile/src/features/messenger/widgets/status_badge.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

class MessageBubble extends StatelessWidget {
  const MessageBubble({
    super.key,
    required this.message,
    required this.isSelected,
    required this.selectionMode,
    required this.onTap,
    required this.onLongPress,
    this.onRetry,
  });

  final StoredTextMessage message;
  final bool isSelected;
  final bool selectionMode;
  final VoidCallback onTap;
  final VoidCallback onLongPress;
  final VoidCallback? onRetry;

  bool get isOutgoing => message.direction == 'outgoing';

  String _formatTime(int epochMs) {
    if (epochMs <= 0) return '';
    final dt = DateTime.fromMillisecondsSinceEpoch(epochMs);
    final hour = dt.hour.toString().padLeft(2, '0');
    final minute = dt.minute.toString().padLeft(2, '0');
    return '$hour:$minute';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final quote = message.replyPreview;
    final bubbleColor = isOutgoing ? scheme.primaryContainer : scheme.surface;
    final foreground = isOutgoing
        ? scheme.onPrimaryContainer
        : scheme.onSurface;
    final textStyle = (theme.textTheme.bodyLarge ?? const TextStyle()).copyWith(
      color: foreground,
      fontSize: 16,
      height: 1.32,
    );
    final time = _formatTime(message.createdAtMs);

    return Semantics(
      selected: isSelected,
      label: isSelected ? 'Selected message' : 'Message',
      child: Material(
        color: isSelected
            ? scheme.primaryContainer.withValues(alpha: 0.52)
            : Colors.transparent,
        child: InkWell(
          onTap: selectionMode ? onTap : null,
          onLongPress: onLongPress,
          child: Stack(
            children: [
              LayoutBuilder(
                builder: (context, constraints) {
                  final maxBubbleWidth = (constraints.maxWidth * 0.8)
                      .clamp(200.0, 520.0)
                      .toDouble();
                  return Align(
                    alignment: isOutgoing
                        ? Alignment.centerRight
                        : Alignment.centerLeft,
                    child: Container(
                      constraints: BoxConstraints(maxWidth: maxBubbleWidth),
                      margin: EdgeInsets.only(
                        left: isOutgoing || selectionMode ? 56 : 16,
                        right: isOutgoing ? 16 : 56,
                        top: 3,
                        bottom: 3,
                      ),
                      padding: const EdgeInsets.fromLTRB(14, 10, 12, 7),
                      decoration: BoxDecoration(
                        color: bubbleColor,
                        border: isOutgoing
                            ? null
                            : Border.all(color: scheme.outlineVariant),
                        borderRadius: BorderRadius.only(
                          topLeft: const Radius.circular(20),
                          topRight: const Radius.circular(20),
                          bottomLeft: Radius.circular(isOutgoing ? 20 : 6),
                          bottomRight: Radius.circular(isOutgoing ? 6 : 20),
                        ),
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          if (quote != null) ...[
                            Container(
                              width: double.infinity,
                              padding: const EdgeInsets.fromLTRB(9, 6, 8, 6),
                              decoration: BoxDecoration(
                                color: foreground.withValues(alpha: 0.07),
                                border: Border(
                                  left: BorderSide(
                                    color: scheme.primary,
                                    width: 3,
                                  ),
                                ),
                                borderRadius: BorderRadius.circular(8),
                              ),
                              child: Text(
                                quote,
                                maxLines: 3,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: foreground.withValues(alpha: 0.78),
                                  height: 1.25,
                                ),
                              ),
                            ),
                            const SizedBox(height: 6),
                          ],
                          Text(message.text, style: textStyle),
                          const SizedBox(height: 2),
                          Row(
                            mainAxisSize: MainAxisSize.min,
                            mainAxisAlignment: MainAxisAlignment.end,
                            children: [
                              if (time.isNotEmpty)
                                Text(
                                  time,
                                  style: theme.textTheme.labelSmall?.copyWith(
                                    color: foreground.withValues(alpha: 0.64),
                                    fontSize: 11,
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                              if (isOutgoing) ...[
                                const SizedBox(width: 4),
                                StatusBadge(
                                  status: message.status,
                                  compact: true,
                                ),
                              ],
                            ],
                          ),
                          if (!selectionMode &&
                              isOutgoing &&
                              message.status == 'queued' &&
                              message.transport != 'mesh' &&
                              message.lastErrorCode != null &&
                              onRetry != null) ...[
                            const SizedBox(height: 6),
                            TextButton.icon(
                              onPressed: onRetry,
                              style: TextButton.styleFrom(
                                minimumSize: const Size(48, 48),
                                foregroundColor: scheme.error,
                              ),
                              icon: const Icon(Icons.refresh_rounded, size: 18),
                              label: const Text('Retry'),
                            ),
                          ],
                        ],
                      ),
                    ),
                  );
                },
              ),
              if (selectionMode)
                Positioned(
                  left: 8,
                  top: 0,
                  bottom: 0,
                  child: Center(
                    child: Icon(
                      isSelected
                          ? Icons.check_circle_rounded
                          : Icons.radio_button_unchecked_rounded,
                      color: isSelected
                          ? scheme.primary
                          : scheme.onSurfaceVariant,
                      size: 26,
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
