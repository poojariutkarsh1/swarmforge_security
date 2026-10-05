# SwarmForge Security (ESP32 #2)

Security demonstration for **SwarmForge**, a low-cost smart warehouse swarm robot system (college ideathon prototype).

This project runs on **one ESP32 (the Security node)** and demonstrates a layered secure-messaging flow using real cryptography:

```text
Robot wants to communicate
        ↓
ECDH Key Exchange          (both sides derive the same shared secret)
        ↓
Fuzzy Extractor            (noisy physical input → stable secret)
        ↓
Key Derivation             (SHA-256 mixes both secrets into two keys)
        ↓
HMAC Authentication        (proves sender knows the key, data unmodified)
        ↓
AES-GCM Encryption         (hides the message + integrity tag)
        ↓
Secure message
```

> **This is an ideathon prototype, not a production security system.** See [Limitations](#limitations).

---

## What the demo shows

| # | Demonstration | Expected result |
|---|---------------|-----------------|
| 1 | ECDH key exchange (P-256) | Both sides compute an identical shared secret |
| 2 | Prototype fuzzy extractor | Noisy readings → same secret; different device → different secret |
| 3 | HMAC authentication | Real key accepted, attacker's guessed key rejected |
| 4 | AES-GCM encryption | Message encrypted, then decrypted correctly |
| 5 | Tampered message | Rejected (HMAC mismatch) |
| 6 | Replay of an old packet | Rejected (counter already used) |

---

## Project files

```text
SwarmForge_Security/
├── SwarmForge_Security.ino   ← all ESP32 logic (one file)
├── dashboard.html            ← presentation dashboard (open in a browser)
└── README.md                 ← this file
```

The `.ino` file and its folder **must have the same name** (`SwarmForge_Security`), or Arduino IDE will complain.

---

## Hardware needed

- 1 × ESP32 development board
- 1 × USB **data** cable (not a charge-only cable)
- A laptop with Wi-Fi

The other robot/security participant is **simulated inside the same ESP32**, so no second board is required for this demo.

## Libraries needed

**None to install.** Everything used is built into the ESP32 Arduino core:

- `mbedTLS` – ECDH, SHA-256, HMAC, AES-GCM
- `WiFi` and `WebServer` – hotspot and dashboard endpoint

---

## Setup (from zero)

1. Install **Arduino IDE 2.x** from [arduino.cc](https://www.arduino.cc/en/software).
2. Open **File → Preferences**. In *Additional boards manager URLs* paste:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
   Click **OK**.
3. Open **Tools → Board → Boards Manager**, search `esp32`, and install **"esp32 by Espressif Systems"**.
4. Create a folder named `SwarmForge_Security`. Put `SwarmForge_Security.ino` and `dashboard.html` inside.
5. Open the `.ino` file in Arduino IDE.
6. Select **Tools → Board → esp32 → ESP32 Dev Module**.
7. Plug in the ESP32. If no port appears, install the **CP210x** or **CH340** USB driver (check the chip printed on your board).
8. Select **Tools → Port → COMx** (Windows) or `/dev/cu.usbserial…` (Mac).
9. Click **Upload** (→). If it shows `Connecting......`, hold the **BOOT** button on the ESP32 until upload starts.
10. Open **Tools → Serial Monitor**, set baud rate to **115200**.

---

## Running the demo

### Option A: Serial Monitor

Type a character in the Serial Monitor and press Enter:

| Key | Action |
|-----|--------|
| `1` | Run the complete security demo |
| `2` | ECDH demo |
| `3` | Authentication demo |
| `4` | Encrypt and decrypt a message |
| `5` | Tamper with the message |
| `6` | Replay an old message |
| `7` | Fuzzy extractor demo |
| `m` | Show the menu |

**Recommended presentation order:** `1` for the full run. For a step-by-step walk-through use `2 → 7 → 3 → 4 → 5 → 6`.

Steps 3–6 automatically run the earlier steps first if keys have not been created yet.

### Option B: Web dashboard

1. On your laptop, join the Wi-Fi network **`SwarmForge-Security`** (password: `swarmforge123`).
2. Double-click `dashboard.html` to open it in a browser.
3. Keep the IP as `192.168.4.1` and click **Run on ESP32**.
   The ESP32 runs the full demo and the dashboard displays the real result.
4. No ESP32 handy? Click **Run simulated demo** (works offline with built-in sample data).

The ESP32 exposes two endpoints:

| Endpoint | What it does |
|----------|--------------|
| `GET /status` | Returns the current results as JSON |
| `GET /run` | Runs the full demo, then returns results as JSON |

---

## Expected Serial output

Hex values change every run because keys are random.

```text
================================
      SWARMFORGE SECURITY
================================

[1] Starting Security System

[2] ECDH KEY EXCHANGE
ESP32-A public key generated: 04A3F19C...
ESP32-B public key generated: 04711BE0...
Shared secret (A): 5C02E9D1...
Shared secret (B): 5C02E9D1...

✓ ECDH EXCHANGE SUCCESSFUL (both secrets identical)

[3] FUZZY EXTRACTOR (Prototype Fuzzy Extractor)
Enrollment completed. Secret: 8E41B7A2...
Noisy reading #1: 1197 2882 547 3317 ...  -> secret: 8E41B7A2...
Noisy reading #2: 1209 2871 533 3326 ...  -> secret: 8E41B7A2...
Noisy reading #3: 1201 2880 541 3319 ...  -> secret: 8E41B7A2...
Different device (clone) gets: 17C9D03F...

✓ FUZZY SECRET SUCCESSFUL (stable despite noise, clone rejected)

[4] AUTHENTICATION
HMAC generated: B2F4...
HMAC verified

✓ AUTHENTICATION SUCCESSFUL (fake robot rejected)

[5] AES-GCM
Original message:
"ROBOT_002 MOVE TO ZONE_B"

Decrypted message:
"ROBOT_002 MOVE TO ZONE_B"

✓ ENCRYPTION SUCCESSFUL  (NORMAL PACKET ACCEPTED)

[6] ATTACK DEMONSTRATION
Tampering with encrypted message...

✗ AUTHENTICATION FAILED (HMAC mismatch)
✗ MESSAGE REJECTED

[7] REPLAY DEMONSTRATION
Replaying old packet...

✗ REPLAY DETECTED (counter already used)
✗ MESSAGE REJECTED
```

---

## How it works (plain language)

### ECDH: Elliptic Curve Diffie-Hellman
> Both devices exchange public information and independently calculate the same shared secret, without directly sending the secret.

Each side makes a private key and a public key, and swaps only the public halves. Combining your own private key with the other side's public key gives both sides the identical secret. Uses curve **P-256**.

### Fuzzy extractor (prototype)
> Small variations in the physical input are converted into a stable secret representation.

A sensor never reads exactly the same value twice, but a key must be identical every time. The prototype takes 8 sensor values (a simulated "physical fingerprint" plus random noise):

- **Enrollment:** store *helper data* that shifts each reading to the middle of a bucket of width 32.
- **Reconstruction:** a new noisy reading plus the helper data lands in the same bucket (if noise is within ±16). The bucket numbers are hashed with SHA-256 into the secret.

A different device with different readings lands in different buckets, so it gets a completely different secret.

### Key derivation
The ECDH secret and fuzzy secret are joined and hashed:

```text
material = SHA256(ECDH secret + Fuzzy secret)
encKey   = HMAC(material, "ENC")   → used for AES-GCM
macKey   = HMAC(material, "MAC")   → used for HMAC
```

Two separate keys are used so that the encryption key and authentication key are never the same.

### HMAC
> Proves that the message came from an authenticated source and was not modified.

Authentication demo: the security node sends a random challenge, the robot answers with `HMAC(macKey, robotID + challenge)`, and the node recomputes and compares. An attacker with a wrong key produces a different result and fails.

### AES-GCM
> Encrypts the actual message so an attacker cannot read it, while also providing integrity protection.

A fresh random IV is used for every packet. The packet counter is passed in as *additional authenticated data*, so it can't be edited either.

### Packet format

```text
[ counter 4 B ][ IV 12 B ][ ciphertext N B ][ GCM tag 16 B ][ HMAC 32 B ]
```

### How a received packet is checked

The receiver runs three checks in this order:

1. **HMAC** over everything before it. Fails → *tampered*.
2. **Counter** must be higher than the last accepted one. Fails → *replay*.
3. **AES-GCM tag** during decryption. Fails → *tampered*.

| Message type | What happens | Result |
|--------------|--------------|--------|
| Normal | HMAC OK → counter new → GCM OK → decrypted | ✓ Accepted |
| Modified (1 bit flipped) | HMAC no longer matches | ✗ Rejected at check 1 |
| Replay (exact copy of old packet) | HMAC is valid, but counter was already used | ✗ Rejected at check 2 |

---

## 1–2 minute explanation for judges

"Our warehouse robots talk over radio, so anyone could listen in, edit commands, or record and resend them. SwarmForge secures each message in layers.

First, **ECDH**: two devices exchange public information and independently calculate the same shared secret, without ever sending the secret itself.

Second, a **fuzzy extractor**: physical readings are never exactly the same twice, but a key must be. We convert small variations in a physical input into a stable secret. A different device gets a completely different one.

We mix both secrets into encryption and authentication keys. **HMAC** proves a message came from an authenticated source and wasn't modified. **AES-GCM** encrypts the message so an attacker can't read it, and adds integrity protection.

Live, you'll see three cases: a normal message is accepted; a message with one flipped bit is rejected; and a genuine old packet that is replayed is rejected because its counter was already used. All of this is real cryptography running on a board that costs a few dollars."

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| No COM port shows up | Try another USB cable (must carry data) and install the CP210x/CH340 driver |
| Upload stuck at `Connecting......` | Hold the **BOOT** button on the ESP32 until upload starts |
| Garbled text in Serial Monitor | Set baud rate to **115200** |
| ✓ / ✗ symbols look broken | Use Arduino IDE 2.x, or ignore it; the demo still works |
| Compile error about `mbedtls_ecdh_*` | The mbedTLS API changed between ESP32 core versions. Update **esp32 by Espressif** in Boards Manager to the latest 3.x release (or try 2.0.x if you're on a very new/old one) and recompile |
| Dashboard says "ESP32 NOT REACHABLE" | Make sure the laptop is joined to `SwarmForge-Security` Wi-Fi (not your normal Wi-Fi) and the IP is `192.168.4.1` |
| Dashboard works but nothing changes | Use **Run simulated demo** as a backup while showing the real run in Serial Monitor |

---

## Limitations

This is a **demonstration**, not production security.

- **Simulated peer:** "Robot A" and "Security node B" both run on one ESP32. In a real system each lives on its own board and the public keys travel over the swarm radio. The ECDH math is identical.
- **Fuzzy extractor is a simplified quantization scheme.** The fingerprint is simulated (fixed values + random noise), the helper data leaks some information, and noise tolerance is limited to ±16 counts. A production version would use a code-offset scheme with error-correcting codes and a real PUF or biometric source.
- **ECDH alone does not prove identity.** It cannot stop a man-in-the-middle by itself. Here the fuzzy secret binds the keys to a device; production would add certificates or ECDSA signatures.
- **Keys live in RAM only,** and the replay counter resets on reboot. Production would use secure storage / eFuse and persistent counters.
- **The Wi-Fi hotspot and dashboard use plain HTTP** with a hard-coded password. Fine for a demo only.
- **No side-channel hardening, key rotation, or formal testing.**

## Connecting to the swarm ESP32s later

Only two functions are needed by the swarm code:

- `buildPacket(msg, pkt)` on the **sender**: encrypts and authenticates a message, returns the packet length.
- `receivePacket(pkt, len, out)` on the **receiver**: returns `0` accepted, `1` HMAC failed, `2` replay, `3` GCM tag failed.

Send the bytes from `buildPacket()` over ESP32 #3 ↔ #4 (ESP-NOW, Wi-Fi, etc.) and call `receivePacket()` on the other side. Both boards need the same `encKey` and `macKey`, so run the ECDH exchange over the link and derive the keys on each side.

---

## Credits

Built for the **SwarmForge** ideathon prototype. Cryptography provided by **mbedTLS**, bundled with the ESP32 Arduino core.
