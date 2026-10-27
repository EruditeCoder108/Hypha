import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:relay_mobile/src/features/messenger/controllers/messenger_controller.dart';
import 'package:relay_mobile/src/features/messenger/screens/nearby_people_screen.dart';
import 'package:relay_mobile/src/features/messenger/widgets/message_bubble.dart';
import 'package:relay_mobile/src/platform/relay_platform.dart';

class ConversationScreen extends StatefulWidget {
  const ConversationScreen({
    super.key,
    required this.controller,
    required this.peerFingerprint,
    this.explicitPeerToken,
  });

  final MessengerController controller;
  final String peerFingerprint;
  final String? explicitPeerToken;

  @override
  State<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends State<ConversationScreen> {
  final TextEditingController _textController = TextEditingController();
  final FocusNode _composerFocusNode = FocusNode();
  final ScrollController _scrollController = ScrollController();
  StoredTextMessage? _replyingToMessage;
  final Set<String> _selectedMessageIds = <String>{};
  bool _sending = false;
  bool _showLatestButton = false;
  int _lastItemCount = -1;
  bool _scrollScheduled = false;
  bool _forceScheduledScroll = false;
  bool _loadingOlderFromScroll = false;
  List<StoredTextMessage>? _lastMessageSource;
  List<StoredAttachment>? _lastAttachmentSource;
  List<_ConversationItem> _timeline = const [];

  @override
  void initState() {
    super.initState();
    widget.controller.loadContacts();
    widget.controller.loadStoredAttachments();
    _scrollController.addListener(_handleHistoryScroll);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      unawaited(_openConversation());
    });
  }

  Future<void> _openConversation() async {
    await widget.controller.loadInitialConversationHistory(
      widget.peerFingerprint,
    );
    if (!mounted) return;
    await widget.controller.setConversationVisible(
      widget.peerFingerprint,
      visible: true,
    );
  }

  String get _displayTitle =>
      widget.controller.contactLabel(widget.peerFingerprint);

  String get _avatarInitial {
    final label = _displayTitle.trim();
    if (label.isEmpty) return 'H';
    final initial = label.substring(0, 1).toUpperCase();
    return RegExp(r'[A-Z0-9]').hasMatch(initial) ? initial : 'H';
  }

  bool get _isSelectingMessages => _selectedMessageIds.isNotEmpty;

  void _selectMessage(StoredTextMessage message) {
    HapticFeedback.selectionClick();
    FocusScope.of(context).unfocus();
    setState(() => _selectedMessageIds.add(message.messageId));
  }

  void _toggleMessageSelection(StoredTextMessage message) {
    setState(() {
      if (!_selectedMessageIds.remove(message.messageId)) {
        _selectedMessageIds.add(message.messageId);
      }
    });
  }

  void _clearMessageSelection() {
    if (_selectedMessageIds.isEmpty) return;
    setState(_selectedMessageIds.clear);
  }

  void _replyToMessage(StoredTextMessage message) {
    setState(() {
      _selectedMessageIds.clear();
      _replyingToMessage = message;
    });
    _composerFocusNode.requestFocus();
  }

  void _copyMessages(List<StoredTextMessage> messages) {
    final text = messages.map((message) => message.text).join('\n\n');
    Clipboard.setData(ClipboardData(text: text));
    setState(_selectedMessageIds.clear);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          messages.length == 1
              ? 'Message copied.'
              : '${messages.length} messages copied.',
        ),
      ),
    );
  }

  PreferredSizeWidget _selectionAppBar(
    BuildContext context,
    List<StoredTextMessage> messages,
  ) {
    final singleMessage = messages.length == 1 ? messages.single : null;
    return AppBar(
      toolbarHeight: 64,
      leading: IconButton(
        onPressed: _clearMessageSelection,
        tooltip: 'Cancel selection',
        icon: const Icon(Icons.close_rounded),
      ),
      titleSpacing: 0,
      title: Semantics(
        liveRegion: true,
        label: '${messages.length} messages selected',
        child: Text(
          '${messages.length}',
          style: Theme.of(
            context,
          ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700),
        ),
      ),
      actions: [
        if (singleMessage != null)
          IconButton(
            onPressed: () => _replyToMessage(singleMessage),
            tooltip: 'Reply',
            icon: const Icon(Icons.reply_rounded),
          ),
        IconButton(
          onPressed: () => _copyMessages(messages),
          tooltip: messages.length == 1 ? 'Copy message' : 'Copy messages',
          icon: const Icon(Icons.content_copy_rounded),
        ),
        IconButton(
          onPressed: () {
            final messagesToForward = List<StoredTextMessage>.unmodifiable(
              messages,
            );
            setState(_selectedMessageIds.clear);
            _showForwardContactPickerSheet(context, messagesToForward);
          },
          tooltip: messages.length == 1
              ? 'Forward message'
              : 'Forward messages',
          icon: const Icon(Icons.forward_rounded),
        ),
        if (singleMessage != null)
          IconButton(
            onPressed: () {
              setState(_selectedMessageIds.clear);
              _showMessageDetailsSheet(context, singleMessage);
            },
            tooltip: 'Message info',
            icon: const Icon(Icons.info_outline_rounded),
          ),
        const SizedBox(width: 4),
      ],
    );
  }

  @override
  void dispose() {
    unawaited(
      widget.controller.setConversationVisible(
        widget.peerFingerprint,
        visible: false,
      ),
    );
    _scrollController.removeListener(_handleHistoryScroll);
    _textController.dispose();
    _composerFocusNode.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _handleHistoryScroll() {
    if (!_scrollController.hasClients) return;
    final shouldShowLatest = _scrollController.position.extentAfter > 180;
    if (shouldShowLatest != _showLatestButton && mounted) {
      setState(() => _showLatestButton = shouldShowLatest);
    }
    if (_scrollController.position.pixels > 160 ||
        _loadingOlderFromScroll ||
        !widget.controller.hasOlderMessages(widget.peerFingerprint)) {
      return;
    }
    unawaited(_loadOlderMessagesPreservingPosition());
  }

  Future<void> _loadOlderMessagesPreservingPosition() async {
    if (_loadingOlderFromScroll || !_scrollController.hasClients) return;
    _loadingOlderFromScroll = true;
    final previousMaxExtent = _scrollController.position.maxScrollExtent;
    final previousPixels = _scrollController.position.pixels;
    await widget.controller.loadOlderMessages(widget.peerFingerprint);
    if (!mounted) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || !_scrollController.hasClients) return;
      final addedExtent =
          _scrollController.position.maxScrollExtent - previousMaxExtent;
      _scrollController.jumpTo(
        (previousPixels + addedExtent)
            .clamp(
              _scrollController.position.minScrollExtent,
              _scrollController.position.maxScrollExtent,
            )
            .toDouble(),
      );
    });
    _loadingOlderFromScroll = false;
  }

  Future<void> _sendMessage() async {
    final rawDraft = _textController.text;
    final cleanDraft = rawDraft.trim();
    if (cleanDraft.isEmpty || _sending) return;
    final reply = _replyingToMessage;

    setState(() {
      _sending = true;
      _replyingToMessage = null;
    });

    _textController.clear();
    _composerFocusNode.requestFocus();

    final outcome = await widget.controller.sendMessage(
      peerFingerprint: widget.peerFingerprint,
      text: cleanDraft,
      explicitPeerToken: widget.explicitPeerToken,
      replyToMessageId: reply?.messageId,
      replyPreview: reply?.text,
    );
    if (!mounted) return;
    if (outcome == MessageSendOutcome.failed && _textController.text.isEmpty) {
      _textController.value = TextEditingValue(
        text: rawDraft,
        selection: TextSelection.collapsed(offset: rawDraft.length),
      );
    }
    setState(() {
      _sending = false;
      if (outcome == MessageSendOutcome.failed) {
        _replyingToMessage = reply;
      }
    });
    _composerFocusNode.requestFocus();

    if (outcome != MessageSendOutcome.failed) {
      _scrollToLatest(force: true, animate: true);
    }
  }

  void _showForwardContactPickerSheet(
    BuildContext context,
    List<StoredTextMessage> messages,
  ) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final controller = widget.controller;

    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      backgroundColor: scheme.surface,
      builder: (sheetContext) {
        final summaries = controller.conversationSummaries;
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Forward to…',
                  style: theme.textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  messages.length == 1
                      ? 'Choose a conversation'
                      : '${messages.length} messages selected',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: scheme.onSurfaceVariant,
                  ),
                ),
                const SizedBox(height: 12),
                if (summaries.isEmpty)
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: Text(
                      'No saved conversations to forward to.',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: scheme.onSurfaceVariant,
                      ),
                    ),
                  )
                else
                  Flexible(
                    child: ListView.builder(
                      shrinkWrap: true,
                      itemCount: summaries.length,
                      itemBuilder: (ctx, index) {
                        final summary = summaries[index];
                        return ListTile(
                          leading: CircleAvatar(
                            backgroundColor: scheme.primaryContainer,
                            foregroundColor: scheme.onPrimaryContainer,
                            child: Text(
                              summary.displayLabel.isEmpty
                                  ? 'H'
                                  : summary.displayLabel
                                        .substring(0, 1)
                                        .toUpperCase(),
                            ),
                          ),
                          title: Text(
                            summary.displayLabel,
                            style: const TextStyle(fontWeight: FontWeight.w600),
                          ),
                          subtitle: Text(
                            messages.length == 1
                                ? 'Send as a new Hypha message'
                                : 'Send ${messages.length} messages',
                          ),
                          onTap: () async {
                            final messenger = ScaffoldMessenger.of(context);
                            Navigator.pop(sheetContext);
                            var failed = 0;
                            for (final message in messages) {
                              final outcome = await controller.sendMessage(
                                peerFingerprint: summary.peerFingerprint,
                                text: message.text,
                              );
                              if (outcome == MessageSendOutcome.failed) {
                                failed++;
                              }
                            }
                            final targetName = summary.displayLabel;
                            messenger.showSnackBar(
                              SnackBar(
                                content: Text(
                                  failed == 0
                                      ? messages.length == 1
                                            ? 'Forward queued for $targetName'
                                            : '${messages.length} forwards queued for $targetName'
                                      : 'Could not forward ${failed == messages.length ? 'to $targetName' : '$failed of ${messages.length} messages'}',
                                ),
                              ),
                            );
                          },
                        );
                      },
                    ),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

  void _showMessageDetailsSheet(
    BuildContext context,
    StoredTextMessage message,
  ) {
    final theme = Theme.of(context);
    final dt = DateTime.fromMillisecondsSinceEpoch(message.createdAtMs);
    final formattedTime =
        '${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')} ${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
    final isOutgoing = message.direction == 'outgoing';

    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (sheetContext) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Message Info',
                style: theme.textTheme.titleLarge?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'Direction: ${isOutgoing ? "Sent (Outgoing)" : "Received (Incoming)"}',
              ),
              const SizedBox(height: 8),
              Text('Status: ${_humanMessageStatus(message.status)}'),
              const SizedBox(height: 8),
              Text('Timestamp: $formattedTime'),
            ],
          ),
        ),
      ),
    );
  }

  String _humanMessageStatus(String status) => switch (status.toLowerCase()) {
    'sending' => 'Sending',
    'queued' => 'Waiting for an encounter',
    'relayed' => 'Carried by Hypha',
    'delivered' => 'Delivered',
    'received' => 'Received',
    'expired' => 'Expired',
    _ => 'Unavailable',
  };

  Future<void> _pickAttachment(String kind) async {
    final outcome = await widget.controller.pickAndSendAttachment(
      peerFingerprint: widget.peerFingerprint,
      kind: kind,
      explicitPeerToken: widget.explicitPeerToken,
    );
    if (!mounted) return;
    if (outcome == AttachmentSendOutcome.started) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Encrypted attachment transfer started.')),
      );
      _scrollToLatest(force: true, animate: true);
    }
  }

  Future<void> _showAttachmentPicker() async {
    final kind = await showModalBottomSheet<String>(
      context: context,
      showDragHandle: true,
      backgroundColor: Theme.of(context).colorScheme.surface,
      builder: (sheetContext) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                'Send an attachment',
                style: Theme.of(
                  sheetContext,
                ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              Text(
                'Hypha encrypts the file first, then uses direct Wi-Fi when it saves time. Internet is not required. Text stays on Bluetooth.',
                style: Theme.of(sheetContext).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(sheetContext).colorScheme.onSurfaceVariant,
                  height: 1.35,
                ),
              ),
              const SizedBox(height: 16),
              Card(
                margin: EdgeInsets.zero,
                child: Column(
                  children: [
                    ListTile(
                      minTileHeight: 56,
                      leading: CircleAvatar(
                        backgroundColor: Theme.of(
                          sheetContext,
                        ).colorScheme.primaryContainer,
                        foregroundColor: Theme.of(
                          sheetContext,
                        ).colorScheme.onPrimaryContainer,
                        child: const Icon(Icons.photo_outlined),
                      ),
                      title: const Text(
                        'Photo',
                        style: TextStyle(fontWeight: FontWeight.w600),
                      ),
                      subtitle: const Text(
                        'JPEG, PNG, WebP, GIF, or HEIC • up to 25 MB',
                      ),
                      onTap: () => Navigator.pop(sheetContext, 'image'),
                    ),
                    const Divider(height: 1),
                    ListTile(
                      minTileHeight: 56,
                      leading: CircleAvatar(
                        backgroundColor: Theme.of(
                          sheetContext,
                        ).colorScheme.tertiaryContainer,
                        foregroundColor: Theme.of(
                          sheetContext,
                        ).colorScheme.onTertiaryContainer,
                        child: const Icon(Icons.attach_file_rounded),
                      ),
                      title: const Text(
                        'File',
                        style: TextStyle(fontWeight: FontWeight.w600),
                      ),
                      subtitle: const Text('Any file • up to 96 MB'),
                      onTap: () => Navigator.pop(sheetContext, 'file'),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
    if (kind != null && mounted) await _pickAttachment(kind);
  }

  void _scrollToLatest({bool force = false, bool animate = false}) {
    if (!force &&
        _scrollController.hasClients &&
        _scrollController.position.extentAfter > 160) {
      return;
    }
    _forceScheduledScroll = _forceScheduledScroll || force;
    if (_scrollScheduled) return;
    _scrollScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final forceThisScroll = _forceScheduledScroll;
      _scrollScheduled = false;
      _forceScheduledScroll = false;
      if (!mounted || !_scrollController.hasClients) return;
      final target = _scrollController.position.maxScrollExtent;
      if (animate && forceThisScroll) {
        _scrollController.animateTo(
          target,
          duration: const Duration(milliseconds: 180),
          curve: Curves.easeOut,
        );
      } else {
        _scrollController.jumpTo(target);
      }
    });
  }

  List<_ConversationItem> _conversationTimeline(
    MessengerController controller,
  ) {
    final messageSource = controller.storedMessages;
    final attachmentSource = controller.storedAttachments;
    if (identical(messageSource, _lastMessageSource) &&
        identical(attachmentSource, _lastAttachmentSource)) {
      return _timeline;
    }

    _lastMessageSource = messageSource;
    _lastAttachmentSource = attachmentSource;
    final timeline = <_ConversationItem>[
      for (final message in messageSource)
        if (message.peerFingerprint == widget.peerFingerprint)
          _ConversationItem.message(message),
      for (final attachment in attachmentSource)
        if (attachment.peerFingerprint == widget.peerFingerprint)
          _ConversationItem.attachment(attachment),
    ]..sort((a, b) => a.createdAtMs.compareTo(b.createdAtMs));
    _restoreSenderSequence(timeline, 'incoming');
    _restoreSenderSequence(timeline, 'outgoing');
    _timeline = List.unmodifiable(timeline);
    return _timeline;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final controller = widget.controller;

    return ListenableBuilder(
      listenable: controller,
      builder: (context, _) {
        final timeline = _conversationTimeline(controller);
        final selectedMessages = <StoredTextMessage>[
          for (final item in timeline)
            if (item.message case final message?
                when _selectedMessageIds.contains(message.messageId))
              message,
        ];

        final explicitToken = widget.explicitPeerToken;
        final explicitTokenIsCurrent =
            explicitToken != null &&
            controller.isTokenDirectlyNearby(explicitToken) &&
            controller.fingerprintByToken[explicitToken] ==
                widget.peerFingerprint;
        final activeToken = explicitTokenIsCurrent
            ? explicitToken
            : controller.findTokenForFingerprint(widget.peerFingerprint);
        final isPeerNearby = activeToken != null;
        RelayContact? savedContact;
        for (final contact in controller.contacts) {
          if (contact.fingerprint == widget.peerFingerprint) {
            savedContact = contact;
            break;
          }
        }
        final trustState = activeToken == null
            ? null
            : controller.trustStateByToken[activeToken];
        final isVerified =
            trustState == 'verified' || savedContact?.verified == true;

        final statusText = isPeerNearby
            ? (isVerified
                  ? 'Directly nearby • Verified'
                  : 'Directly nearby • Verification required')
            : 'Not nearby • Messages wait safely for a Hypha encounter';
        final statusColor = isPeerNearby
            ? (isVerified ? scheme.secondary : scheme.tertiary)
            : scheme.onSurfaceVariant;

        if (timeline.length != _lastItemCount) {
          _lastItemCount = timeline.length;
          _scrollToLatest();
        }

        return PopScope(
          canPop: !_isSelectingMessages,
          onPopInvokedWithResult: (didPop, result) {
            if (!didPop && _isSelectingMessages) {
              _clearMessageSelection();
            }
          },
          child: Scaffold(
            appBar: _isSelectingMessages
                ? _selectionAppBar(context, selectedMessages)
                : AppBar(
                    toolbarHeight: 76,
                    titleSpacing: 0,
                    title: Row(
                      children: [
                        CircleAvatar(
                          radius: 21,
                          backgroundColor: scheme.primaryContainer,
                          foregroundColor: scheme.onPrimaryContainer,
                          child: Text(
                            _avatarInitial,
                            style: const TextStyle(fontWeight: FontWeight.w800),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              Text(
                                _displayTitle,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                style: theme.textTheme.titleMedium?.copyWith(
                                  fontWeight: FontWeight.w700,
                                  letterSpacing: -0.3,
                                ),
                              ),
                              const SizedBox(height: 3),
                              Row(
                                children: [
                                  Container(
                                    width: 8,
                                    height: 8,
                                    decoration: BoxDecoration(
                                      color: statusColor,
                                      shape: BoxShape.circle,
                                    ),
                                  ),
                                  const SizedBox(width: 6),
                                  Expanded(
                                    child: Text(
                                      statusText,
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                      style: theme.textTheme.labelMedium
                                          ?.copyWith(
                                            color: statusColor,
                                            fontWeight: FontWeight.w500,
                                            fontSize: 12,
                                          ),
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
            body: SafeArea(
              child: Column(
                children: [
                  if (controller.statusError != null)
                    MaterialBanner(
                      content: Text(
                        controller.statusError!,
                        style: TextStyle(color: scheme.onErrorContainer),
                      ),
                      backgroundColor: scheme.errorContainer,
                      actions: [
                        TextButton(
                          onPressed: controller.clearError,
                          child: Text(
                            'Dismiss',
                            style: TextStyle(color: scheme.onErrorContainer),
                          ),
                        ),
                      ],
                    ),
                  if (!isVerified)
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.fromLTRB(16, 10, 12, 10),
                      decoration: BoxDecoration(
                        color: scheme.surfaceContainerHigh,
                        border: Border(
                          bottom: BorderSide(color: scheme.outlineVariant),
                        ),
                      ),
                      child: Row(
                        children: [
                          Icon(
                            isPeerNearby
                                ? Icons.shield_outlined
                                : Icons.radar_rounded,
                            color: isPeerNearby
                                ? scheme.tertiary
                                : scheme.onSurfaceVariant,
                            size: 20,
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              isPeerNearby
                                  ? 'Verify this phone before sending.'
                                  : 'Meet this contact once to exchange and verify identities.',
                              style: theme.textTheme.bodyMedium?.copyWith(
                                fontSize: 13.5,
                                height: 1.3,
                              ),
                            ),
                          ),
                          TextButton(
                            onPressed: () => Navigator.of(context).push(
                              MaterialPageRoute<void>(
                                builder: (_) =>
                                    NearbyPeopleScreen(controller: controller),
                              ),
                            ),
                            style: TextButton.styleFrom(
                              minimumSize: const Size(48, 40),
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                              ),
                            ),
                            child: Text(isPeerNearby ? 'Verify' : 'Find'),
                          ),
                        ],
                      ),
                    ),
                  Expanded(
                    child:
                        timeline.isEmpty &&
                            controller.isConversationHistoryLoading(
                              widget.peerFingerprint,
                            )
                        ? const Center(child: CircularProgressIndicator())
                        : timeline.isEmpty
                        ? Center(
                            child: Padding(
                              padding: const EdgeInsets.all(24),
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(
                                    Icons.chat_outlined,
                                    size: 48,
                                    color: scheme.onSurfaceVariant.withValues(
                                      alpha: 0.5,
                                    ),
                                  ),
                                  const SizedBox(height: 12),
                                  Text(
                                    'No messages yet',
                                    style: theme.textTheme.titleMedium
                                        ?.copyWith(
                                          color: scheme.onSurfaceVariant,
                                          fontWeight: FontWeight.w600,
                                        ),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    'Send a message over encrypted offline radio.',
                                    style: theme.textTheme.bodyMedium?.copyWith(
                                      color: scheme.onSurfaceVariant,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          )
                        : ListView.builder(
                            controller: _scrollController,
                            padding: const EdgeInsets.symmetric(vertical: 12),
                            itemCount:
                                timeline.length +
                                (controller.isLoadingOlderMessages(
                                      widget.peerFingerprint,
                                    )
                                    ? 1
                                    : 0),
                            itemBuilder: (context, index) {
                              final loadingOlder = controller
                                  .isLoadingOlderMessages(
                                    widget.peerFingerprint,
                                  );
                              if (loadingOlder && index == 0) {
                                return const Padding(
                                  padding: EdgeInsets.symmetric(vertical: 12),
                                  child: Center(
                                    child: SizedBox.square(
                                      dimension: 24,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                      ),
                                    ),
                                  ),
                                );
                              }
                              final item =
                                  timeline[loadingOlder ? index - 1 : index];
                              final message = item.message;
                              if (message != null) {
                                return MessageBubble(
                                  key: ValueKey('message_${message.messageId}'),
                                  message: message,
                                  isSelected: _selectedMessageIds.contains(
                                    message.messageId,
                                  ),
                                  selectionMode: _isSelectingMessages,
                                  onTap: () => _toggleMessageSelection(message),
                                  onLongPress: () => _selectMessage(message),
                                  onRetry: () =>
                                      controller.retryTextMessage(message),
                                );
                              }
                              final attachment = item.attachment!;
                              final paused =
                                  attachment.lastErrorCode == 'user_paused';
                              final cancelled =
                                  attachment.lastErrorCode == 'user_cancelled';
                              final actionPending = controller
                                  .isAttachmentActionPending(
                                    attachment.attachmentId,
                                  );
                              final statusText = controller
                                  .attachmentStatusText(attachment);
                              final needsAttention = controller
                                  .attachmentNeedsAttention(attachment);
                              final transferProgress = controller
                                  .attachmentProgress(attachment.attachmentId);
                              return _AttachmentBubble(
                                attachment: attachment,
                                actionPending: actionPending,
                                statusText: statusText,
                                needsAttention: needsAttention,
                                showProgress: controller
                                    .attachmentShowsProgress(
                                      attachment.attachmentId,
                                    ),
                                progress: transferProgress?.phase == 'preparing'
                                    ? null
                                    : transferProgress?.fraction,
                                preview: controller.attachmentPreview(
                                  attachment,
                                ),
                                onOpen:
                                    attachment.direction == 'incoming' &&
                                        attachment.status == 'ready'
                                    ? () =>
                                          controller.openAttachment(attachment)
                                    : null,
                                onResume:
                                    attachment.direction == 'outgoing' &&
                                        attachment.status == 'queued' &&
                                        paused &&
                                        !actionPending
                                    ? () => controller.retryAttachment(
                                        attachment,
                                        explicitPeerToken:
                                            widget.explicitPeerToken,
                                      )
                                    : null,
                                onCancel:
                                    attachment.direction == 'outgoing' &&
                                        attachment.status != 'delivered' &&
                                        !paused &&
                                        !cancelled &&
                                        !actionPending
                                    ? () => controller.cancelAttachment(
                                        attachment,
                                      )
                                    : null,
                              );
                            },
                          ),
                  ),

                  if (_showLatestButton)
                    Align(
                      alignment: Alignment.centerRight,
                      child: Padding(
                        padding: const EdgeInsets.fromLTRB(12, 4, 12, 4),
                        child: FilledButton.tonalIcon(
                          onPressed: () =>
                              _scrollToLatest(force: true, animate: true),
                          icon: const Icon(Icons.keyboard_arrow_down_rounded),
                          label: const Text('Latest'),
                          style: FilledButton.styleFrom(
                            minimumSize: const Size(48, 44),
                            visualDensity: VisualDensity.compact,
                          ),
                        ),
                      ),
                    ),

                  if (_replyingToMessage case final replyingTo?)
                    Container(
                      width: double.infinity,
                      padding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
                      decoration: BoxDecoration(
                        color: scheme.surfaceContainerLow,
                        border: Border(
                          top: BorderSide(color: scheme.outlineVariant),
                          left: BorderSide(color: scheme.primary, width: 3),
                        ),
                      ),
                      child: Row(
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Text(
                                  'Replying to',
                                  style: theme.textTheme.labelMedium?.copyWith(
                                    color: scheme.primary,
                                    fontWeight: FontWeight.w700,
                                  ),
                                ),
                                Text(
                                  replyingTo.text,
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: scheme.onSurfaceVariant,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          IconButton(
                            onPressed: () =>
                                setState(() => _replyingToMessage = null),
                            tooltip: 'Cancel reply',
                            icon: const Icon(Icons.close_rounded),
                          ),
                        ],
                      ),
                    ),

                  // Composer Container
                  Container(
                    padding: const EdgeInsets.fromLTRB(12, 9, 12, 12),
                    decoration: BoxDecoration(
                      color: theme.scaffoldBackgroundColor,
                      border: Border(
                        top: BorderSide(color: scheme.outlineVariant),
                      ),
                    ),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.center,
                      children: [
                        Semantics(
                          label: 'Attach photo or file',
                          button: true,
                          child: IconButton.filledTonal(
                            onPressed:
                                !isVerified || controller.isSendingAttachment
                                ? null
                                : _showAttachmentPicker,
                            icon: controller.isSendingAttachment
                                ? const SizedBox.square(
                                    dimension: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                    ),
                                  )
                                : const Icon(Icons.add_rounded),
                            tooltip: 'Attach photo or file',
                          ),
                        ),
                        const SizedBox(width: 4),
                        Expanded(
                          child: TextField(
                            controller: _textController,
                            focusNode: _composerFocusNode,
                            textCapitalization: TextCapitalization.sentences,
                            minLines: 1,
                            maxLines: 4,
                            style: TextStyle(
                              fontSize: 16,
                              color: scheme.onSurface,
                            ),
                            decoration: InputDecoration(
                              hintText: 'Message',
                              hintStyle: TextStyle(
                                color: scheme.onSurfaceVariant,
                                fontSize: 15,
                              ),
                              isDense: true,
                              contentPadding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 12,
                              ),
                              fillColor: scheme.surfaceContainerLow,
                              filled: true,
                              border: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(24),
                                borderSide: BorderSide(
                                  color: scheme.outlineVariant,
                                ),
                              ),
                              enabledBorder: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(24),
                                borderSide: BorderSide(
                                  color: scheme.outlineVariant,
                                ),
                              ),
                              focusedBorder: OutlineInputBorder(
                                borderRadius: BorderRadius.circular(24),
                                borderSide: BorderSide(
                                  color: scheme.primary,
                                  width: 2,
                                ),
                              ),
                            ),
                            onSubmitted: (_) => _sendMessage(),
                          ),
                        ),
                        const SizedBox(width: 8),

                        // Send button with at least 48dp touch target and accessibility label
                        Semantics(
                          label: 'Send message',
                          button: true,
                          child: ExcludeSemantics(
                            child: SizedBox(
                              width: 48,
                              height: 48,
                              child: IconButton(
                                onPressed: _sending ? null : _sendMessage,
                                icon: _sending
                                    ? const SizedBox.square(
                                        dimension: 20,
                                        child: CircularProgressIndicator(
                                          strokeWidth: 2,
                                        ),
                                      )
                                    : const Icon(Icons.send_rounded, size: 20),
                                style: IconButton.styleFrom(
                                  backgroundColor: scheme.primary,
                                  foregroundColor: scheme.onPrimary,
                                  disabledBackgroundColor:
                                      scheme.surfaceContainerHighest,
                                  minimumSize: const Size(48, 48),
                                ),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

class _ConversationItem {
  _ConversationItem.message(StoredTextMessage value)
    : message = value,
      attachment = null,
      createdAtMs = value.createdAtMs;

  _ConversationItem.attachment(StoredAttachment value)
    : attachment = value,
      message = null,
      createdAtMs = value.createdAtMs;

  final StoredTextMessage? message;
  final StoredAttachment? attachment;
  final int createdAtMs;
}

void _restoreSenderSequence(
  List<_ConversationItem> timeline,
  String direction,
) {
  final indices = <int>[];
  final ordered = <_ConversationItem>[];
  for (var index = 0; index < timeline.length; index++) {
    final message = timeline[index].message;
    if (message?.direction == direction &&
        message?.conversationSequence != null) {
      indices.add(index);
      ordered.add(timeline[index]);
    }
  }
  ordered.sort((left, right) {
    final leftMessage = left.message!;
    final rightMessage = right.message!;
    final sequence = leftMessage.conversationSequence!.compareTo(
      rightMessage.conversationSequence!,
    );
    if (sequence != 0) return sequence;
    return leftMessage.messageId.compareTo(rightMessage.messageId);
  });
  for (var index = 0; index < indices.length; index++) {
    timeline[indices[index]] = ordered[index];
  }
}

class _AttachmentBubble extends StatelessWidget {
  const _AttachmentBubble({
    required this.attachment,
    required this.actionPending,
    required this.statusText,
    required this.needsAttention,
    required this.showProgress,
    required this.progress,
    required this.preview,
    required this.onOpen,
    required this.onResume,
    required this.onCancel,
  });

  final StoredAttachment attachment;
  final bool actionPending;
  final String statusText;
  final bool needsAttention;
  final bool showProgress;
  final double? progress;
  final Future<Uint8List?> preview;
  final VoidCallback? onOpen;
  final VoidCallback? onResume;
  final VoidCallback? onCancel;

  String get _size {
    final bytes = attachment.bytes;
    if (bytes >= 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / 1024).ceil()} KB';
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final outgoing = attachment.direction == 'outgoing';
    return Align(
      alignment: outgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 320),
        child: Card(
          margin: EdgeInsets.fromLTRB(
            outgoing ? 48 : 12,
            4,
            outgoing ? 12 : 48,
            4,
          ),
          color: outgoing
              ? scheme.primaryContainer
              : scheme.surfaceContainerHighest,
          child: InkWell(
            borderRadius: BorderRadius.circular(12),
            onTap: onOpen,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                _AttachmentPreview(attachment: attachment, preview: preview),
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(
                        attachment.mimeType.startsWith('video/')
                            ? Icons.videocam_outlined
                            : attachment.kind == 'image'
                            ? Icons.image_outlined
                            : Icons.insert_drive_file_outlined,
                        color: outgoing
                            ? scheme.onPrimaryContainer
                            : scheme.onSurfaceVariant,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              attachment.fileName,
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: const TextStyle(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              '$_size • $statusText',
                              style: needsAttention
                                  ? TextStyle(
                                      color: scheme.error,
                                      fontWeight: FontWeight.w600,
                                    )
                                  : null,
                            ),
                            if (showProgress) ...[
                              const SizedBox(height: 8),
                              Semantics(
                                label: 'Attachment transfer progress',
                                value: progress == null
                                    ? 'Preparing'
                                    : '${(progress! * 100).round()} percent',
                                child: LinearProgressIndicator(value: progress),
                              ),
                            ],
                          ],
                        ),
                      ),
                      if (actionPending)
                        const Padding(
                          padding: EdgeInsets.all(12),
                          child: SizedBox.square(
                            dimension: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          ),
                        )
                      else if (onCancel != null)
                        IconButton(
                          onPressed: onCancel,
                          tooltip: 'Cancel attachment',
                          icon: const Icon(Icons.close_rounded),
                        )
                      else if (onResume != null)
                        IconButton(
                          onPressed: onResume,
                          tooltip: 'Resume transfer',
                          icon: const Icon(Icons.play_arrow_rounded),
                        )
                      else if (onOpen != null)
                        const Icon(Icons.open_in_new_rounded, size: 20),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _AttachmentPreview extends StatelessWidget {
  const _AttachmentPreview({required this.attachment, required this.preview});

  final StoredAttachment attachment;
  final Future<Uint8List?> preview;

  bool get _isPreviewable =>
      attachment.mimeType.startsWith('image/') ||
      attachment.mimeType.startsWith('video/');

  @override
  Widget build(BuildContext context) {
    if (!_isPreviewable) return const SizedBox.shrink();
    final video = attachment.mimeType.startsWith('video/');
    return FutureBuilder<Uint8List?>(
      future: preview,
      builder: (context, snapshot) {
        final bytes = snapshot.data;
        if (snapshot.connectionState != ConnectionState.done) {
          return SizedBox(
            height: 176,
            width: double.infinity,
            child: ColoredBox(
              color: Theme.of(context).colorScheme.surfaceContainer,
              child: Center(
                child: Icon(
                  video ? Icons.videocam_outlined : Icons.image_outlined,
                  semanticLabel: video
                      ? 'Loading video preview'
                      : 'Loading image preview',
                ),
              ),
            ),
          );
        }
        if (bytes == null || bytes.isEmpty) return const SizedBox.shrink();
        return Semantics(
          image: true,
          label: video
              ? 'Video preview for ${attachment.fileName}'
              : 'Image preview for ${attachment.fileName}',
          child: ClipRRect(
            borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
            child: SizedBox(
              key: ValueKey('attachment_preview_${attachment.attachmentId}'),
              width: double.infinity,
              height: 176,
              child: Stack(
                fit: StackFit.expand,
                children: [
                  Image.memory(
                    bytes,
                    fit: BoxFit.cover,
                    cacheWidth: 640,
                    filterQuality: FilterQuality.medium,
                    gaplessPlayback: true,
                    errorBuilder: (_, _, _) => const SizedBox.shrink(),
                  ),
                  if (video)
                    Center(
                      child: DecoratedBox(
                        decoration: const BoxDecoration(
                          color: Color(0xB3000000),
                          shape: BoxShape.circle,
                        ),
                        child: Padding(
                          padding: const EdgeInsets.all(10),
                          child: Icon(
                            Icons.play_arrow_rounded,
                            color: Colors.white,
                            size: 32,
                            semanticLabel: 'Open video',
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}
