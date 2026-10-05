/*
  SwarmForge Security Demo - ESP32 #2
  Real crypto (mbedTLS, built into ESP32 core):
    ECDH (P-256), SHA-256, HMAC-SHA256, AES-256-GCM
  Fuzzy extractor is a simplified PROTOTYPE (explained below).
  The "other robot" is simulated inside this same ESP32.
*/
#include <WiFi.h>
#include <WebServer.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

// ---------- Wi-Fi hotspot so dashboard.html can read status ----------
const char* AP_SSID = "SwarmForge-Security";
const char* AP_PASS = "swarmforge123";
WebServer server(80);

// ---------- Status (shown on dashboard) ----------
bool st_ecdh = false, st_fuzzy = false, st_hmac = false, st_aes = false;
int  st_normal = 0, st_tamper = 0, st_replay = 0;   // 0=not tested, 1=accepted, 2=rejected
String st_msg = "", st_cipher = "";

// ---------- Keys and packet memory ----------
uint8_t ecdhSecret[32];     // shared secret from ECDH
uint8_t fuzzySecret[32];    // secret from fuzzy extractor
uint8_t encKey[32];         // AES key
uint8_t macKey[32];         // HMAC key
bool keysReady = false;
uint32_t sendCounter = 0;       // sender's packet number
uint32_t lastSeenCounter = 0;   // receiver remembers highest number it accepted
uint8_t lastPacket[128];
size_t  lastPacketLen = 0;

// ---------- Small helpers ----------
// Random numbers from the ESP32 hardware random generator (needed by crypto)
int myRng(void*, unsigned char* out, size_t len) { esp_fill_random(out, len); return 0; }

void printHex(const uint8_t* d, size_t n, size_t maxShow = 9999) {
  for (size_t i = 0; i < n && i < maxShow; i++) { if (d[i] < 16) Serial.print('0'); Serial.print(d[i], HEX); }
  if (n > maxShow) Serial.print("...");
  Serial.println();
}
String toHex(const uint8_t* d, size_t n) {
  String s = ""; const char* h = "0123456789ABCDEF";
  for (size_t i = 0; i < n; i++) { s += h[d[i] >> 4]; s += h[d[i] & 15]; }
  return s;
}
void sha256(const uint8_t* in, size_t len, uint8_t* out) {
  mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), in, len, out);
}
void hmac256(const uint8_t* key, size_t klen, const uint8_t* in, size_t len, uint8_t* out) {
  mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, klen, in, len, out);
}
// Compare two byte arrays in a way that takes the same time every time
bool sameBytes(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0; for (size_t i = 0; i < n; i++) diff |= a[i] ^ b[i]; return diff == 0;
}
void banner(const char* t) { Serial.println(); Serial.println("================================"); Serial.println(t); Serial.println("================================"); }

/* =====================================================================
   STEP 1: ECDH KEY EXCHANGE
   WHAT IT DOES : Two devices create the SAME secret without sending it.
   WHY WE NEED IT: Robots can't carry a pre-shared password safely.
   IN THE CODE  : A and B each make a private+public key. They swap public
                  keys only. Each combines its own private key with the
                  other's public key -> both get an identical secret.
   ===================================================================== */
void stepECDH() {
  Serial.println("\n[2] ECDH KEY EXCHANGE");
  mbedtls_ecdh_context A, B;                       // A = robot, B = security node
  mbedtls_ecdh_init(&A); mbedtls_ecdh_init(&B);
  uint8_t pubA[100], pubB[100], secA[32], secB[32];
  size_t lenA = 0, lenB = 0, sA = 0, sB = 0;

  int r = mbedtls_ecdh_setup(&A, MBEDTLS_ECP_DP_SECP256R1);            // P-256 curve
  if (r == 0) r = mbedtls_ecdh_setup(&B, MBEDTLS_ECP_DP_SECP256R1);
  if (r == 0) r = mbedtls_ecdh_make_public(&A, &lenA, pubA, sizeof(pubA), myRng, NULL);
  if (r == 0) r = mbedtls_ecdh_make_public(&B, &lenB, pubB, sizeof(pubB), myRng, NULL);
  if (r == 0) {
    Serial.print("ESP32-A public key generated: "); printHex(pubA, lenA, 12);
    Serial.print("ESP32-B public key generated: "); printHex(pubB, lenB, 12);
  }
  if (r == 0) r = mbedtls_ecdh_read_public(&A, pubB, lenB);            // A receives B's public key
  if (r == 0) r = mbedtls_ecdh_read_public(&B, pubA, lenA);            // B receives A's public key
  if (r == 0) r = mbedtls_ecdh_calc_secret(&A, &sA, secA, sizeof(secA), myRng, NULL);
  if (r == 0) r = mbedtls_ecdh_calc_secret(&B, &sB, secB, sizeof(secB), myRng, NULL);
  mbedtls_ecdh_free(&A); mbedtls_ecdh_free(&B);

  st_ecdh = (r == 0 && sA == 32 && sA == sB && sameBytes(secA, secB, 32));
  if (st_ecdh) {
    memcpy(ecdhSecret, secA, 32);
    Serial.print("Shared secret (A): "); printHex(secA, 32, 12);
    Serial.print("Shared secret (B): "); printHex(secB, 32, 12);
    Serial.println("\n✓ ECDH EXCHANGE SUCCESSFUL (both secrets identical)");
  } else Serial.println("\n✗ ECDH FAILED");
}

/* =====================================================================
   STEP 2: FUZZY EXTRACTOR  (*** PROTOTYPE FUZZY EXTRACTOR ***)
   WHAT IT DOES : Turns a NOISY reading into the SAME secret every time.
   WHY WE NEED IT: Physical readings (sensors) never repeat exactly, but a
                  key must be exactly the same. Hashing raw readings would
                  give a totally different key each time.
   IN THE CODE  : 8 sensor values (a robot's "physical fingerprint").
     Enrollment: we store HELPER DATA that shifts each reading to the
                 middle of a bucket of width Q=32.
     Later     : noisy reading + helper -> same bucket number (as long as
                 noise is under +-16). Bucket numbers are hashed (SHA-256)
                 into the secret.
   LIMITS (honest): It is a simple quantization scheme, not a full
     code-offset extractor. Helper data leaks a little information, and the
     fingerprint here is SIMULATED (fixed values + random noise).
     Replace readSensor() with analogRead() on a real sensor to go further.
   ===================================================================== */
const int N = 8;                 // number of sensor values
const int Q = 32;                // bucket size (noise tolerance = +-Q/2)
const int FINGERPRINT[N] = {1203, 2876, 540, 3321, 1789, 2410, 905, 3777};
int helperData[N];

int readSensor(int i, int noiseRange) {              // simulated noisy sensor
  return FINGERPRINT[i] + (int)(esp_random() % (2 * noiseRange + 1)) - noiseRange;
}
void bucketsToSecret(const int* reading, uint8_t* secretOut) {
  uint8_t b[N * 2];
  for (int i = 0; i < N; i++) {
    int bucket = (reading[i] + helperData[i]) / Q;   // same bucket if noise is small
    b[2 * i] = bucket >> 8; b[2 * i + 1] = bucket & 255;
  }
  sha256(b, sizeof(b), secretOut);
}
void stepFuzzy() {
  Serial.println("\n[3] FUZZY EXTRACTOR (Prototype Fuzzy Extractor)");
  int r[N]; uint8_t enrolled[32], again[32], clone[32];

  for (int i = 0; i < N; i++) { r[i] = readSensor(i, 8); helperData[i] = Q / 2 - (r[i] % Q); }
  bucketsToSecret(r, enrolled);                      // ENROLLMENT
  Serial.print("Enrollment completed. Secret: "); printHex(enrolled, 32, 12);

  bool allSame = true;
  for (int t = 1; t <= 3; t++) {                     // RECONSTRUCT 3 times with new noise
    for (int i = 0; i < N; i++) r[i] = readSensor(i, 8);
    bucketsToSecret(r, again);
    Serial.print("Noisy reading #"); Serial.print(t); Serial.print(": ");
    for (int i = 0; i < 4; i++) { Serial.print(r[i]); Serial.print(" "); }
    Serial.print("...  -> secret: "); printHex(again, 32, 12);
    if (!sameBytes(enrolled, again, 32)) allSame = false;
  }
  for (int i = 0; i < N; i++) r[i] = readSensor(i, 8) + 100 * (i % 2 ? 1 : -1);  // different device
  bucketsToSecret(r, clone);
  Serial.print("Different device (clone) gets: "); printHex(clone, 32, 12);

  st_fuzzy = allSame && !sameBytes(enrolled, clone, 32);
  if (st_fuzzy) { memcpy(fuzzySecret, enrolled, 32); Serial.println("\n✓ FUZZY SECRET SUCCESSFUL (stable despite noise, clone rejected)"); }
  else Serial.println("\n✗ FUZZY EXTRACTOR FAILED");
}

// Mix both secrets into two separate keys
void stepDeriveKeys() {
  uint8_t both[64], material[32];
  memcpy(both, ecdhSecret, 32); memcpy(both + 32, fuzzySecret, 32);
  sha256(both, 64, material);
  hmac256(material, 32, (const uint8_t*)"ENC", 3, encKey);   // AES key
  hmac256(material, 32, (const uint8_t*)"MAC", 3, macKey);   // HMAC key
  keysReady = st_ecdh && st_fuzzy;
  sendCounter = 0; lastSeenCounter = 0; lastPacketLen = 0;   // new session
  Serial.println("\nSession keys derived: SHA256(ECDH secret + Fuzzy secret)");
}
void ensureKeys() { if (!keysReady) { stepECDH(); stepFuzzy(); stepDeriveKeys(); } }

/* =====================================================================
   STEP 3: HMAC AUTHENTICATION (challenge-response)
   WHAT IT DOES : Proves "I know the secret key" and "data not modified".
   WHY WE NEED IT: Stops fake robots and edited packets.
   IN THE CODE  : Security node sends a random challenge. Robot answers
                  with HMAC(key, robotID+challenge). Node recomputes it and
                  compares. An attacker with a wrong key fails.
   ===================================================================== */
void stepAuth() {
  ensureKeys();
  Serial.println("\n[4] AUTHENTICATION");
  uint8_t data[9 + 16], good[32], expect[32], fake[32], badKey[32];
  memcpy(data, "ROBOT_002", 9); esp_fill_random(data + 9, 16);     // ID + random challenge
  hmac256(macKey, 32, data, sizeof(data), good);                   // robot's answer
  Serial.print("HMAC generated: "); printHex(good, 32, 12);
  hmac256(macKey, 32, data, sizeof(data), expect);                 // node's own calculation
  bool ok = sameBytes(good, expect, 32);
  Serial.println(ok ? "HMAC verified" : "HMAC mismatch");
  esp_fill_random(badKey, 32);                                     // attacker guesses a key
  hmac256(badKey, 32, data, sizeof(data), fake);
  bool attackerOk = sameBytes(fake, expect, 32);
  st_hmac = ok && !attackerOk;
  Serial.println(st_hmac ? "\n✓ AUTHENTICATION SUCCESSFUL (fake robot rejected)" : "\n✗ AUTHENTICATION FAILED");
}

/* =====================================================================
   STEP 4: AES-GCM ENCRYPTION  + packet format
   Packet = [counter 4][IV 12][ciphertext][GCM tag 16][HMAC 32]
   WHAT IT DOES : Hides the message and detects changes (GCM tag).
   WHY WE NEED IT: Attackers on the radio link must not read/edit commands.
   IN THE CODE  : Fresh random IV for every packet. Counter is passed as
                  "additional data" so it is protected too. HMAC covers
                  everything before it.
   ===================================================================== */
size_t buildPacket(const char* msg, uint8_t* pkt) {
  size_t m = strlen(msg);
  sendCounter++;
  pkt[0] = sendCounter >> 24; pkt[1] = sendCounter >> 16; pkt[2] = sendCounter >> 8; pkt[3] = sendCounter;
  uint8_t* iv = pkt + 4; uint8_t* ct = pkt + 16; uint8_t* tag = pkt + 16 + m; uint8_t* mac = pkt + 32 + m;
  esp_fill_random(iv, 12);
  mbedtls_gcm_context g; mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, encKey, 256);
  mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, m, iv, 12, pkt, 4, (const uint8_t*)msg, ct, 16, tag);
  mbedtls_gcm_free(&g);
  hmac256(macKey, 32, pkt, 32 + m, mac);
  return 64 + m;
}
// Returns: 0 = accepted, 1 = HMAC failed (tampered), 2 = replay, 3 = AES-GCM tag failed
int receivePacket(const uint8_t* pkt, size_t len, char* out) {
  if (len < 64 || len > 120) return 1;
  size_t m = len - 64;
  uint8_t calc[32];
  hmac256(macKey, 32, pkt, len - 32, calc);
  if (!sameBytes(calc, pkt + len - 32, 32)) return 1;               // CHECK 1: HMAC
  uint32_t c = ((uint32_t)pkt[0] << 24) | (pkt[1] << 16) | (pkt[2] << 8) | pkt[3];
  if (c <= lastSeenCounter) return 2;                               // CHECK 2: replay counter
  mbedtls_gcm_context g; mbedtls_gcm_init(&g);
  mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, encKey, 256);
  int r = mbedtls_gcm_auth_decrypt(&g, m, pkt + 4, 12, pkt, 4, pkt + 16 + m, 16, pkt + 16, (uint8_t*)out);
  mbedtls_gcm_free(&g);
  if (r != 0) return 3;                                             // CHECK 3: AES-GCM tag
  out[m] = 0; lastSeenCounter = c; return 0;
}

void stepEncrypt() {
  ensureKeys();
  Serial.println("\n[5] AES-GCM");
  const char* msg = "ROBOT_002 MOVE TO ZONE_B";
  Serial.print("Original message:\n\""); Serial.print(msg); Serial.println("\"");
  lastPacketLen = buildPacket(msg, lastPacket);
  Serial.print("\nEncrypted packet:\n"); printHex(lastPacket, lastPacketLen);
  char out[100]; int r = receivePacket(lastPacket, lastPacketLen, out);
  st_aes = (r == 0); st_normal = st_aes ? 1 : 2;
  st_msg = msg; st_cipher = toHex(lastPacket + 16, strlen(msg));
  if (st_aes) { Serial.print("\nDecrypted message:\n\""); Serial.print(out); Serial.println("\"\n\n✓ ENCRYPTION SUCCESSFUL  (NORMAL PACKET ACCEPTED)"); }
  else Serial.println("\n✗ ENCRYPTION FAILED");
}

void stepTamper() {
  if (lastPacketLen == 0) stepEncrypt();
  Serial.println("\n[6] ATTACK DEMONSTRATION\nTampering with encrypted message...");
  uint8_t bad[128]; memcpy(bad, lastPacket, lastPacketLen);
  bad[16] ^= 0x01;                                                  // attacker flips ONE bit
  char out[100]; int r = receivePacket(bad, lastPacketLen, out);
  st_tamper = (r != 0) ? 2 : 1;
  if (r == 1) Serial.println("\n✗ AUTHENTICATION FAILED (HMAC mismatch)\n✗ MESSAGE REJECTED");
  else if (r == 3) Serial.println("\n✗ AES-GCM TAG FAILED\n✗ MESSAGE REJECTED");
  else Serial.println("!! Tampered packet was accepted (this should never happen)");
}

void stepReplay() {
  if (lastPacketLen == 0) stepEncrypt();
  Serial.println("\n[7] REPLAY DEMONSTRATION\nReplaying old packet...");
  char out[100]; int r = receivePacket(lastPacket, lastPacketLen, out);   // exact copy, valid HMAC
  st_replay = (r != 0) ? 2 : 1;
  if (r == 2) Serial.println("\n✗ REPLAY DETECTED (counter already used)\n✗ MESSAGE REJECTED");
  else Serial.println("!! Replay was accepted (this should never happen)");
}

void runFull() {
  banner("      SWARMFORGE SECURITY");
  Serial.println("\n[1] Starting Security System");
  keysReady = false;
  stepECDH(); stepFuzzy(); stepDeriveKeys();
  stepAuth(); stepEncrypt(); stepTamper(); stepReplay();
  banner("      DEMO COMPLETE");
}

void showMenu() {
  Serial.println("\n===== SWARMFORGE MENU =====");
  Serial.println("1 -> Run complete security demo");
  Serial.println("2 -> ECDH demo");
  Serial.println("3 -> Authentication demo");
  Serial.println("4 -> Encrypt message");
  Serial.println("5 -> Tamper with message");
  Serial.println("6 -> Replay old message");
  Serial.println("7 -> Fuzzy extractor demo");
  Serial.println("m -> Show this menu");
}

// ---------- Web server: dashboard.html reads /status ----------
String statusJson() {
  String s = "{";
  s += "\"ecdh\":" + String(st_ecdh) + ",\"fuzzy\":" + String(st_fuzzy) + ",\"hmac\":" + String(st_hmac) + ",\"aes\":" + String(st_aes);
  s += ",\"normal\":" + String(st_normal) + ",\"tamper\":" + String(st_tamper) + ",\"replay\":" + String(st_replay);
  s += ",\"msg\":\"" + st_msg + "\",\"cipher\":\"" + st_cipher + "\"}";
  return s;
}
void sendStatus() { server.sendHeader("Access-Control-Allow-Origin", "*"); server.send(200, "application/json", statusJson()); }
void handleRun()  { runFull(); sendStatus(); }

void setup() {
  Serial.begin(115200);
  delay(1000);
  WiFi.softAP(AP_SSID, AP_PASS);
  server.on("/status", sendStatus);
  server.on("/run", handleRun);
  server.begin();
  Serial.print("Wi-Fi hotspot: "); Serial.print(AP_SSID); Serial.print("  IP: "); Serial.println(WiFi.softAPIP());
  showMenu();
}

void loop() {
  server.handleClient();
  if (Serial.available()) {
    char c = Serial.read();
    if (c == '1') runFull();
    else if (c == '2') { stepECDH(); }
    else if (c == '3') stepAuth();
    else if (c == '4') stepEncrypt();
    else if (c == '5') stepTamper();
    else if (c == '6') stepReplay();
    else if (c == '7') stepFuzzy();
    else if (c == 'm') showMenu();
  }
}