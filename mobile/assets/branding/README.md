# App branding assets

`app_icon.png` is the source image processed by `flutter_launcher_icons` into
the per-density Android mipmaps and the iOS `AppIcon.appiconset`. Single
source of truth — do not edit individual launcher PNGs by hand; they get
regenerated.

## Constraints

- Square PNG, 1024×1024 is the ideal size. Anything smaller scales up; anything
  rectangular gets squished.
- iOS strips the alpha channel automatically on icon generation (see
  `remove_alpha_ios: true` in pubspec.yaml). Android keeps it.
- Bottom-edge text gets clipped on devices with aggressive icon masks
  (circle / squircle / teardrop). If your logo has text near the edge,
  expect it to be hard to read at launcher sizes.

## To regenerate icons after replacing `app_icon.png`

```bash
cd mobile
flutter pub get
dart run flutter_launcher_icons
```

The command rewrites both Android and iOS icon directories.
