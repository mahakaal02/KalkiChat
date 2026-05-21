import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import 'chat_controller.dart';

class ChatScreen extends ConsumerStatefulWidget {
  const ChatScreen({super.key});

  @override
  ConsumerState<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends ConsumerState<ChatScreen> {
  final TextEditingController _ctrl = TextEditingController();
  final ScrollController _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    ref.read(chatControllerProvider.notifier).connect();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    _scroll.dispose();
    ref.read(chatControllerProvider.notifier).disconnect();
    super.dispose();
  }

  void _send() {
    final String text = _ctrl.text.trim();
    if (text.isEmpty) return;
    ref.read(chatControllerProvider.notifier).sendText(text);
    _ctrl.clear();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.animateTo(
          _scroll.position.minScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final ChatState state = ref.watch(chatControllerProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Admin'),
        actions: <Widget>[
          IconButton(
            icon: const Icon(Icons.lock_outline, size: 18),
            tooltip: 'End-to-end encrypted',
            onPressed: () {},
          ),
        ],
      ),
      body: Column(
        children: <Widget>[
          Expanded(
            child: ListView.builder(
              controller: _scroll,
              reverse: true,
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              itemCount: state.messages.length,
              itemBuilder: (BuildContext c, int i) =>
                  _bubble(state.messages[i]),
            ),
          ),
          SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: <Widget>[
                  Expanded(
                    child: TextField(
                      controller: _ctrl,
                      minLines: 1,
                      maxLines: 5,
                      // Disable native copy/paste menu on this field.
                      enableInteractiveSelection: false,
                      autocorrect: false,
                      enableSuggestions: false,
                      textInputAction: TextInputAction.send,
                      onSubmitted: (_) => _send(),
                      // Strip pasted content as defence-in-depth.
                      inputFormatters: <TextInputFormatter>[
                        FilteringTextInputFormatter.deny(RegExp(r'[​-‏]')),
                      ],
                      decoration: const InputDecoration(
                        hintText: 'Message',
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton.filled(
                    onPressed: _send,
                    icon: const Icon(Icons.arrow_upward),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _bubble(ChatMessage m) {
    final bool out = m.direction == MessageDirection.outgoing;
    final Color bg =
        out ? const Color(0xFF7AE2CF) : const Color(0xFF1A2230);
    final Color fg = out ? const Color(0xFF062A24) : Colors.white;
    return Align(
      alignment: out ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: BoxConstraints(
            maxWidth: MediaQuery.of(context).size.width * 0.78),
        margin: const EdgeInsets.symmetric(vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(16),
            topRight: const Radius.circular(16),
            bottomLeft: Radius.circular(out ? 16 : 4),
            bottomRight: Radius.circular(out ? 4 : 16),
          ),
        ),
        child: Column(
          crossAxisAlignment:
              out ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: <Widget>[
            // SelectableText with copy disabled — we want long-press to show
            // the *timestamp*, not the system copy menu.
            Text(
              m.plaintext,
              style: TextStyle(color: fg, fontSize: 15),
            ),
            const SizedBox(height: 4),
            Text(
              DateFormat.Hm().format(m.createdAt),
              style: TextStyle(color: fg.withOpacity(0.6), fontSize: 11),
            ),
          ],
        ),
      ),
    );
  }
}
