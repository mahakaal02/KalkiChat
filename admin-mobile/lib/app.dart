import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import 'features/auth/login_screen.dart';
import 'features/auth/totp_screen.dart';
import 'features/users/users_screen.dart';
import 'features/users/user_detail_screen.dart';
import 'features/config/whatsapp_screen.dart';
import 'features/audit/audit_screen.dart';

final routerProvider = Provider<GoRouter>((ref) {
  return GoRouter(
    initialLocation: '/login',
    routes: <RouteBase>[
      GoRoute(path: '/login', builder: (_, __) => const AdminLoginScreen()),
      GoRoute(path: '/totp', builder: (_, __) => const AdminTotpScreen()),
      GoRoute(path: '/users', builder: (_, __) => const UsersScreen()),
      GoRoute(
        path: '/users/:id',
        builder: (BuildContext c, GoRouterState s) =>
            UserDetailScreen(userId: s.pathParameters['id']!),
      ),
      GoRoute(path: '/config/whatsapp', builder: (_, __) => const WhatsAppScreen()),
      GoRoute(path: '/audit', builder: (_, __) => const AuditScreen()),
    ],
  );
});

class KalkiAdminApp extends ConsumerWidget {
  const KalkiAdminApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp.router(
      title: 'KalkiChat Admin',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF0A0E14),
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF7AE2CF),
          surface: Color(0xFF11161F),
        ),
      ),
      routerConfig: ref.watch(routerProvider),
    );
  }
}
