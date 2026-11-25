# iphonese-ios16
iOS 16.1, on a 4-inch iPhone!

And no, this is not for iPhone 5S.

This creates a custom iOS 16 restore IPSW for iPhone SE 1st generation for tether upgrading unofficially.

# Requirements

A Mac/Hackintosh on a modern macOS version (preferably, macOS 14 and up).

At least 40-50GB of free space.

`python3` (used by the audio driver port, the one shipped with macOS / Xcode Command Line Tools is fine).

Common sense

# IPSWs needed

[iPhone SE 15.8.8 IPSW](https://updates.cdn-apple.com/2025FallFCS/fullrestores/122-77321/C113B49D-5014-4DEA-9C43-9AA3D772355B/iPhone_4.0_64bit_15.8.8_19H422_Restore.ipsw)

[iPhone 8 16.1 IPSW](https://updates.cdn-apple.com/2022FallFCS/fullrestores/012-93302/55AD63F9-AC84-4990-8CD8-4025CE5454DE/iPhone_4.7_P3_16.1_20B82_Restore.ipsw)

[iPad 5 16.1 IPSW](https://updates.cdn-apple.com/2022FallFCS/fullrestores/012-93170/0E98AA01-052C-470B-9A14-7D610C1A97C6/iPad_64bit_TouchID_ASTC_16.1_20B82_Restore.ipsw)

Place these inside the downloaded repo.

# Usage

Assuming all IPSWs are present, here is the usage!

`chmod +x build-ipsw.sh`

`./build-ipsw.sh`

# What works

- Baseband (cellular functionality is NOT fully tested, as my SE 1 is carrier locked to AT&T)
- Wallpaper (thanks to [awazustamin](https://github.com/awazustamin) for [the PR!](https://github.com/pwnerblu/iphonese-ios16/pull/2))
- Flashlight
- Bluetooth
- Device audio (speaker)
- Wi-Fi
- Apple services
- SEP
- Touch ID

# What does not work

- Camera
- Jailbreaking
- Other things I have not tested. They may have issues.

This is an incomplete project, and still has issues. Do not try this on a main device. Proof Of Concept.

After `iPhone_4.0_64bit_16.1_20B82_Restore.ipsw` is created, tether restore this with [turdus merula](https://sep.lol).
