import 'package:flutter/material.dart';

class StatusBadge extends StatelessWidget {
  const StatusBadge({super.key, required this.status, this.compact = false});

  final String status;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    final IconData iconData;
    final String labelText;
    final Color color;
    final Color bgColor;

    switch (status.toLowerCase()) {
      case 'sending':
        iconData = Icons.access_time_rounded;
        labelText = compact ? 'Sending' : 'Sending…';
        color = scheme.onSurfaceVariant;
        bgColor = scheme.surfaceContainerHighest.withValues(alpha: 0.5);
        break;
      case 'queued':
        iconData = Icons.schedule_rounded;
        labelText = compact ? 'Waiting' : 'Waiting for an encounter';
        color = scheme.tertiary;
        bgColor = scheme.tertiaryContainer.withValues(alpha: 0.4);
        break;
      case 'relayed':
        iconData = Icons.hub_outlined;
        labelText = compact ? 'Carried' : 'Carried by Hypha';
        color = scheme.onSurfaceVariant;
        bgColor = scheme.surfaceContainerHighest.withValues(alpha: 0.5);
        break;
      case 'delivered':
        iconData = Icons.done_all_rounded;
        labelText = 'Delivered';
        color = scheme.secondary;
        bgColor = scheme.surfaceContainerHighest.withValues(alpha: 0.5);
        break;
      case 'expired':
        iconData = Icons.timer_off_outlined;
        labelText = 'Expired';
        color = scheme.error;
        bgColor = scheme.errorContainer.withValues(alpha: 0.5);
        break;
      case 'received':
        iconData = Icons.arrow_downward_rounded;
        labelText = 'Received';
        color = scheme.onSurfaceVariant;
        bgColor = scheme.surfaceContainerHighest.withValues(alpha: 0.5);
        break;
      default:
        iconData = Icons.info_outline_rounded;
        labelText = status;
        color = scheme.onSurfaceVariant;
        bgColor = scheme.surfaceContainerHighest.withValues(alpha: 0.5);
        break;
    }

    return Semantics(
      label: 'Status: $labelText',
      child: ExcludeSemantics(
        child: compact
            ? Tooltip(
                message: labelText,
                child: Icon(iconData, size: 15, color: color),
              )
            : AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeOut,
                padding: const EdgeInsets.symmetric(
                  horizontal: 10,
                  vertical: 4,
                ),
                decoration: BoxDecoration(
                  color: bgColor,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: color.withValues(alpha: 0.25),
                    width: 1,
                  ),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    Icon(iconData, size: 15, color: color),
                    const SizedBox(width: 4),
                    Text(
                      labelText,
                      style: theme.textTheme.labelSmall?.copyWith(
                        color: color,
                        fontWeight: FontWeight.w600,
                        fontSize: 12,
                        letterSpacing: -0.1,
                      ),
                    ),
                  ],
                ),
              ),
      ),
    );
  }
}
