import 'package:flutter/material.dart';

/// The small connected-node mark used throughout Hypha's consumer UI.
class HyphaBrandMark extends StatelessWidget {
  const HyphaBrandMark({super.key, this.size = 32, this.color});

  final double size;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final markColor = color ?? Theme.of(context).colorScheme.primary;
    return Semantics(
      image: true,
      label: 'Hypha logo',
      child: ExcludeSemantics(
        child: Image.asset(
          'assets/branding/hypha-mark-v3-flat.png',
          width: size,
          height: size,
          fit: BoxFit.contain,
          color: markColor,
          colorBlendMode: BlendMode.srcIn,
          filterQuality: FilterQuality.high,
        ),
      ),
    );
  }
}

class HyphaWordmark extends StatelessWidget {
  const HyphaWordmark({
    super.key,
    this.markSize = 30,
    this.textSize = 27,
    this.color,
  });

  final double markSize;
  final double textSize;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final foreground = color ?? Theme.of(context).colorScheme.onSurface;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        HyphaBrandMark(size: markSize, color: foreground),
        SizedBox(width: markSize * 0.28),
        Text(
          'Hypha',
          style: TextStyle(
            color: foreground,
            fontSize: textSize,
            fontWeight: FontWeight.w900,
            letterSpacing: -1.55,
            height: 0.96,
          ),
        ),
      ],
    );
  }
}
