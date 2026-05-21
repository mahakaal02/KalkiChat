import 'package:flutter/material.dart';

/// Shown when [SecurityGate] detects a root/jailbroken environment.
/// The app does not load any messages or keys from this screen.
class SecurityBlockScreen extends StatelessWidget {
  const SecurityBlockScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Center(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: const <Widget>[
              Icon(Icons.gpp_bad, size: 96, color: Colors.redAccent),
              SizedBox(height: 24),
              Text(
                'Device cannot be trusted',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.w600,
                  color: Colors.white,
                ),
                textAlign: TextAlign.center,
              ),
              SizedBox(height: 12),
              Text(
                'This device appears to be rooted, jailbroken, or in '
                'developer mode. For your safety, KalkiChat will not open.',
                style: TextStyle(color: Colors.white70, fontSize: 14),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
