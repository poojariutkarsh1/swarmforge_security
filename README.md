# 🔐 SwarmForge Security Module

A lightweight security prototype for **SwarmForge**, a low-cost smart warehouse swarm robot system.

This module demonstrates how robots in a swarm can establish a secure session, authenticate each other, encrypt commands, and detect common communication attacks.

> **Prototype:** The complete security demonstration runs on **one ESP32**.  
> The second robot is simulated internally so the security workflow can be demonstrated without requiring multiple physical boards.

---

## 🚀 Features

The prototype demonstrates:

- 🔑 **ECDH P-256 Key Exchange**
- 🧬 **Fuzzy Extractor-based Device Secret**
- 🔐 **SHA-256 Session Key Derivation**
- 🛡️ **HMAC-based Authentication**
- 🔒 **AES-GCM Encryption**
- 🧨 **Tamper Detection**
- 🔁 **Replay Attack Detection**
- 📡 **ESP32 Wi-Fi Access Point**
- 💻 **Web Dashboard**
- 🤖 Simulated robot-to-robot communication

---

## 🏗️ System Architecture

```text
                 SwarmForge Security
                        │
                  ┌─────▼─────┐
                  │  ESP32 #2 │
                  │ SECURITY  │
                  └─────┬─────┘
                        │
              ┌─────────┴─────────┐
              │                   │
        Simulated Robot A   Security Robot B
              │                   │
              └─────── ECDH ─────┘
                        │
                 Shared Secret
                        │
                Fuzzy Extractor
                        │
                  Key Derivation
                        │
              ┌─────────┴─────────┐
              │                   │
             HMAC             AES-GCM
              │                   │
        Authentication       Encryption
              │                   │
              └─────────┬─────────┘
                        │
                 Secure Packet
                        │
             ┌──────────┴──────────┐
             │                     │
        Tamper Check          Replay Check
