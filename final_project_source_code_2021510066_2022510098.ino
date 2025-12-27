#include <Arduino.h>
#include "DHT.h"
#include <stdint.h>
#include <string.h>
#include <WiFi.h>
#include <HTTPClient.h>

// ============================================================
//  Benchmark: XTEA / SPECK / SIMON / PRESENT (CTR mode)
//  Platform : ESP32 Dev Module (Arduino IDE)
//  Sensor   : DHT22 (temperature + humidity)
//  Output   : CSV lines for Excel / Python
//  Extra    : Send encrypted payload to server via HTTP POST (JSON)
// ============================================================

// ------------------------- WiFi / Server ---------------------
static const char* WIFI_SSID  = "berennet";
static const char* WIFI_PASS  = "12345678";

// Example: "http://192.168.1.50:5000/data"
static const char* SERVER_URL = "http://10.30.180.224:8080/data";

// Set false if you only want benchmark output (no network)
static const bool SEND_TO_SERVER = true;

// ------------------------- Algorithm IDs ---------------------
enum AlgoId { ALG_XTEA, ALG_SPECK, ALG_SIMON, ALG_PRESENT };

// Forward declarations
static const char* algo_name(AlgoId a);
static void run_bench_csv(AlgoId algo, const uint8_t* plaintext, size_t len);
static bool send_ciphertext_json(AlgoId algo,
                                 uint32_t ts_ms, float tempC, float humPct,
                                 const uint8_t* ciphertext, size_t ct_len,
                                 uint32_t nonce32);

// ------------------------- Hardware --------------------------
#define DHTPIN 4
#define DHTTYPE DHT22
DHT dht(DHTPIN, DHTTYPE);

// ------------------------- Experiment Settings ---------------
static const uint32_t SAMPLE_INTERVAL_MS = 5000;
static const size_t   PLAINTEXT_LEN      = 32;
static const size_t   PAYLOAD_LEN        = 31;     // plaintext bytes used (exclude null terminator)
static const int      BENCH_ITERS        = 500;    // iterations per algorithm
static const uint32_t NONCE32            = 0xA1B2C3D4;

// ------------------------- Helpers ---------------------------
static inline uint32_t ROR32(uint32_t x, uint32_t r) { return (x >> r) | (x << (32 - r)); }
static inline uint32_t ROL32(uint32_t x, uint32_t r) { return (x << r) | (x >> (32 - r)); }

static inline uint64_t ctr_input_block_u64(uint32_t nonce32, uint32_t counter32) {
  return ((uint64_t)nonce32 << 32) | (uint64_t)counter32;
}

// Convert bytes to hex string (no spaces)
static void bytes_to_hex(const uint8_t* in, size_t len, char* out, size_t out_cap) {
  static const char* HEX_CHARS = "0123456789ABCDEF";
  size_t need = len * 2 + 1;
  if (out_cap < need) {
    if (out_cap > 0) out[0] = '\0';
    return;
  }
  for (size_t i = 0; i < len; i++) {
    out[i * 2]     = HEX_CHARS[(in[i] >> 4) & 0xF];
    out[i * 2 + 1] = HEX_CHARS[in[i] & 0xF];
  }
  out[len * 2] = '\0';
}


static void wifi_connect_blocking() {
  if (!SEND_TO_SERVER) return;

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(250);
  }

  if (WiFi.status() == WL_CONNECTED) {
    // Keep CSV clean: diagnostics as comment lines starting with '#'
    Serial.print("# WiFi connected, IP=");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("# WiFi connect failed (will retry later)");
  }
}

static void wifi_ensure_connected() {
  if (!SEND_TO_SERVER) return;
  if (WiFi.status() == WL_CONNECTED) return;
  wifi_connect_blocking();
}

// ============================================================
//  ALGO 1: XTEA (64-bit block, 128-bit key) - CTR wrapper
// ============================================================
static void xtea_encrypt_block(uint32_t v[2], const uint32_t k[4]) {
  uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
  for (int i = 0; i < 32; i++) {
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    sum += delta;
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
  }
  v[0] = v0; v[1] = v1;
}

static void xtea_ctr(uint8_t *data, size_t len, const uint32_t key[4], uint32_t nonce32) {
  uint32_t counter = 0;
  uint8_t ks[8];

  while (len > 0) {
    uint64_t in64 = ctr_input_block_u64(nonce32, counter);
    uint32_t block[2];
    memcpy(block, &in64, 8);

    xtea_encrypt_block(block, key);
    memcpy(ks, block, 8);

    size_t chunk = (len < 8) ? len : 8;
    for (size_t i = 0; i < chunk; i++) data[i] ^= ks[i];

    data += chunk;
    len -= chunk;
    counter++;
  }
}

// ============================================================
//  ALGO 2: SPECK64/128 - CTR wrapper
// ============================================================
static void speck_encrypt_block(uint32_t v[2], const uint32_t key[4]) {
  uint32_t x = v[0], y = v[1];
  uint32_t a = key[0], b = key[1], c = key[2], d = key[3];
  uint32_t rk = a;

  for (int i = 0; i < 27; i++) {
    x = (ROR32(x, 7) + y) ^ rk;
    y = ROL32(y, 2) ^ x;

    a = (ROR32(a, 8) + b) ^ (uint32_t)i;
    b = ROL32(b, 3) ^ a;
    rk = a;
  }

  v[0] = x; v[1] = y;
}

static void speck_ctr(uint8_t *data, size_t len, const uint32_t key[4], uint32_t nonce32) {
  uint32_t counter = 0;
  uint8_t ks[8];

  while (len > 0) {
    uint64_t in64 = ctr_input_block_u64(nonce32, counter);
    uint32_t block[2];
    memcpy(block, &in64, 8);

    speck_encrypt_block(block, key);
    memcpy(ks, block, 8);

    size_t chunk = (len < 8) ? len : 8;
    for (size_t i = 0; i < chunk; i++) data[i] ^= ks[i];

    data += chunk;
    len -= chunk;
    counter++;
  }
}

// ============================================================
//  ALGO 3: SIMON64/128 - CTR wrapper
// ============================================================
static const uint8_t SIMON_Z3[62] = {
  1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,1,1,0,0,1,0,0,1,0,1,0,0,0,
  0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,1,1,1,1,0,1,0,0,1,0,1,0,1,1,0
};

static inline uint32_t simon_f(uint32_t x) {
  return (ROL32(x, 1) & ROL32(x, 8)) ^ ROL32(x, 2);
}

static void simon_expand_key_64_128(uint32_t rk[44], const uint32_t key[4]) {
  rk[0] = key[0]; rk[1] = key[1]; rk[2] = key[2]; rk[3] = key[3];
  const uint32_t c = 0xfffffffcU;

  for (int i = 4; i < 44; i++) {
    uint32_t tmp = ROR32(rk[i-1], 3);
    tmp ^= rk[i-3];
    tmp ^= ROR32(tmp, 1);
    uint32_t z = (uint32_t)SIMON_Z3[(i-4) % 62];
    rk[i] = c ^ z ^ rk[i-4] ^ tmp;
  }
}

static void simon_encrypt_block(uint32_t v[2], const uint32_t rk[44]) {
  uint32_t x = v[0], y = v[1];
  for (int i = 0; i < 44; i++) {
    uint32_t tmp = x;
    x = y ^ simon_f(x) ^ rk[i];
    y = tmp;
  }
  v[0] = x; v[1] = y;
}

static void simon_ctr(uint8_t *data, size_t len, const uint32_t key[4], uint32_t nonce32) {
  uint32_t counter = 0;
  uint8_t ks[8];
  uint32_t rk[44];

  simon_expand_key_64_128(rk, key);

  while (len > 0) {
    uint64_t in64 = ctr_input_block_u64(nonce32, counter);
    uint32_t block[2];
    memcpy(block, &in64, 8);

    simon_encrypt_block(block, rk);
    memcpy(ks, block, 8);

    size_t chunk = (len < 8) ? len : 8;
    for (size_t i = 0; i < chunk; i++) data[i] ^= ks[i];

    data += chunk;
    len -= chunk;
    counter++;
  }
}

// ============================================================
//  ALGO 4: PRESENT80 (64-bit block, 80-bit key) - CTR wrapper
// ============================================================
static const uint8_t PRESENT_SBOX[16] = {
  0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2
};

static uint64_t present_pLayer(uint64_t s) {
  uint64_t p = 0;
  for (int i = 0; i < 63; i++) {
    int pos = (i * 16) % 63;
    p |= ((s >> i) & 1ULL) << pos;
  }
  p |= (s & (1ULL << 63));
  return p;
}

static uint64_t present_sBoxLayer(uint64_t s) {
  uint64_t out = 0;
  for (int i = 0; i < 16; i++) {
    uint8_t nib = (s >> (i * 4)) & 0xF;
    out |= (uint64_t)PRESENT_SBOX[nib] << (i * 4);
  }
  return out;
}

static void present_generate_roundkeys(uint64_t rk[32], const uint8_t key80[10]) {
  uint8_t K[10];
  memcpy(K, key80, 10);

  for (int round = 1; round <= 32; round++) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) r = (r << 8) | K[i];
    rk[round - 1] = r;

    uint8_t tmp[10];
    memcpy(tmp, K, 10);
    uint8_t out[10] = {0};

    // Rotate left by 61 bits: (bit + 19) % 80 (equivalent)
    for (int bit = 0; bit < 80; bit++) {
      int src = (bit + 19) % 80;
      uint8_t b = (tmp[src / 8] >> (7 - (src % 8))) & 1;
      out[bit / 8] |= b << (7 - (bit % 8));
    }
    memcpy(K, out, 10);

    // Apply S-box to the leftmost 4 bits
    uint8_t topNib = (K[0] >> 4) & 0xF;
    topNib = PRESENT_SBOX[topNib];
    K[0] = (K[0] & 0x0F) | (topNib << 4);

    // XOR round counter into key bits
    uint8_t rc = (uint8_t)round & 0x1F;
    K[7] ^= (rc >> 1);
    K[8] ^= (rc << 7);
  }
}

static void present_encrypt_block(uint8_t block8[8], const uint8_t key80[10]) {
  uint64_t state = 0;
  for (int i = 0; i < 8; i++) state = (state << 8) | block8[i];

  uint64_t rk[32];
  present_generate_roundkeys(rk, key80);

  for (int round = 1; round <= 31; round++) {
    state ^= rk[round - 1];
    state = present_sBoxLayer(state);
    state = present_pLayer(state);
  }
  state ^= rk[31];

  for (int i = 7; i >= 0; i--) {
    block8[i] = (uint8_t)(state & 0xFF);
    state >>= 8;
  }
}

static void present_ctr(uint8_t *data, size_t len, const uint8_t key80[10], uint32_t nonce32) {
  uint32_t counter = 0;
  uint8_t ks[8];

  while (len > 0) {
    uint64_t in64 = ctr_input_block_u64(nonce32, counter);
    memcpy(ks, &in64, 8);

    present_encrypt_block(ks, key80);

    size_t chunk = (len < 8) ? len : 8;
    for (size_t i = 0; i < chunk; i++) data[i] ^= ks[i];

    data += chunk;
    len -= chunk;
    counter++;
  }
}

// ============================================================
//  CSV Printing + Benchmark Wrapper
// ============================================================
static const char* algo_name(AlgoId a) {
  switch (a) {
    case ALG_XTEA:    return "XTEA_CTR";
    case ALG_SPECK:   return "SPECK64_128_CTR";
    case ALG_SIMON:   return "SIMON64_128_CTR";
    case ALG_PRESENT: return "PRESENT80_CTR";
    default:          return "UNKNOWN";
  }
}

// Print one CSV line for one algorithm benchmark run
// Columns:
// ts_ms,tempC,humPct,algo,pt_len,iters,total_us,avg_us,KBps,heap_before,heap_after,heap_delta
static void run_bench_csv(AlgoId algo, const uint8_t* plaintext, size_t len) {
  static const uint32_t KEY128_WORDS[4] = { 0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF };
  static const uint8_t  KEY80_BYTES[10] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99 };

  uint32_t heap_before = ESP.getFreeHeap();
  uint32_t t1 = micros();

  for (int i = 0; i < BENCH_ITERS; i++) {
    uint8_t buf[PLAINTEXT_LEN];
    memcpy(buf, plaintext, len);

    switch (algo) {
      case ALG_XTEA:    xtea_ctr(buf, len, KEY128_WORDS, NONCE32); break;
      case ALG_SPECK:   speck_ctr(buf, len, KEY128_WORDS, NONCE32); break;
      case ALG_SIMON:   simon_ctr(buf, len, KEY128_WORDS, NONCE32); break;
      case ALG_PRESENT: present_ctr(buf, len, KEY80_BYTES, NONCE32); break;
    }
  }

  uint32_t t2 = micros();
  uint32_t heap_after = ESP.getFreeHeap();

  uint32_t total_us = t2 - t1;
  float avg_us = (float)total_us / (float)BENCH_ITERS;

  // Throughput in KB/s (KiB/s)
  float KBps = ((float)len * (float)BENCH_ITERS) / ((float)total_us / 1e6f) / 1024.0f;

  int32_t heap_delta = (int32_t)heap_after - (int32_t)heap_before;

  Serial.print(algo_name(algo)); Serial.print(",");
  Serial.print(len); Serial.print(",");
  Serial.print(BENCH_ITERS); Serial.print(",");
  Serial.print(total_us); Serial.print(",");
  Serial.print(avg_us, 2); Serial.print(",");
  Serial.print(KBps, 2); Serial.print(",");
  Serial.print(heap_before); Serial.print(",");
  Serial.print(heap_after); Serial.print(",");
  Serial.println(heap_delta);
}

// Encrypt ONCE (not benchmark) and send ciphertext to server
static bool encrypt_once_and_send(AlgoId algo,
                                 uint32_t ts_ms, float tempC, float humPct,
                                 const uint8_t* plaintext, size_t len)
{
  if (!SEND_TO_SERVER) return true;
  wifi_ensure_connected();
  if (WiFi.status() != WL_CONNECTED) return false;

  static const uint32_t KEY128_WORDS[4] = { 0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF };
  static const uint8_t  KEY80_BYTES[10] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99 };

  uint8_t ct[PLAINTEXT_LEN];
  memcpy(ct, plaintext, len);

  switch (algo) {
    case ALG_XTEA:    xtea_ctr(ct, len, KEY128_WORDS, NONCE32); break;
    case ALG_SPECK:   speck_ctr(ct, len, KEY128_WORDS, NONCE32); break;
    case ALG_SIMON:   simon_ctr(ct, len, KEY128_WORDS, NONCE32); break;
    case ALG_PRESENT: present_ctr(ct, len, KEY80_BYTES, NONCE32); break;
  }

  return send_ciphertext_json(algo, ts_ms, tempC, humPct, ct, len, NONCE32);
}

// POST JSON to server. Keeps CSV clean: only prints comments on error.
static bool send_ciphertext_json(AlgoId algo,
                                 uint32_t ts_ms, float tempC, float humPct,
                                 const uint8_t* ciphertext, size_t ct_len,
                                 uint32_t nonce32)
{
  // Hex string (2*len + 1)
  char ct_hex[PLAINTEXT_LEN * 2 + 1];
  bytes_to_hex(ciphertext, ct_len, ct_hex, sizeof(ct_hex));

  // JSON body
  // Keep it small; server can parse easily.
  String body;
  body.reserve(200 + ct_len * 2);
  body += "{";
  body += "\"ts_ms\":"; body += String(ts_ms);
  body += ",\"tempC\":"; body += String(tempC, 2);
  body += ",\"humPct\":"; body += String(humPct, 2);
  body += ",\"algo\":\""; body += algo_name(algo); body += "\"";
  body += ",\"pt_len\":"; body += String(ct_len);
  body += ",\"nonce32\":\""; body += String(nonce32, HEX); body += "\"";
  body += ",\"ct_hex\":\""; body += ct_hex; body += "\"";
  body += "}";

  HTTPClient http;
  http.begin(SERVER_URL);
  http.addHeader("Content-Type", "application/json");

  int code = http.POST((uint8_t*)body.c_str(), body.length());
  http.end();

  if (code <= 0) {
    Serial.print("# HTTP POST failed, algo=");
    Serial.print(algo_name(algo));
    Serial.print(", err=");
    Serial.println(code);
    return false;
  }
  return (code >= 200 && code < 300);
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  dht.begin();
  delay(2000);

  // Connect WiFi (optional)
  wifi_connect_blocking();

  // CSV header
  Serial.println("ts_ms,tempC,humPct,algo,pt_len,iters,total_us,avg_us,KBps,heap_before,heap_after,heap_delta");
}

void loop() {
  static uint32_t last_ms = 0;
  uint32_t now = millis();
  if (now - last_ms < SAMPLE_INTERVAL_MS) return;
  last_ms = now;

  // Read sensor
  float h = dht.readHumidity();
  float t = dht.readTemperature();

  if (isnan(h) || isnan(t)) {
    Serial.print(now);
    Serial.println(",NA,NA,SENSOR_FAIL,0,0,0,0,0,0,0,0");
    delay(1000);
    return;
  }

  // Build fixed-length plaintext (for fairness)
  char plaintext[PLAINTEXT_LEN];
  int written = snprintf(plaintext, sizeof(plaintext), "ts=%lu,t=%.2f,h=%.2f",
                         (unsigned long)now, t, h);
  if (written < 0) written = 0;
  for (size_t i = (size_t)written; i < PLAINTEXT_LEN - 1; i++) plaintext[i] = ' ';
  plaintext[PLAINTEXT_LEN - 1] = '\0';

  // Helper: print common CSV prefix
  auto print_prefix = [&](float tempC, float humPct) {
    Serial.print(now); Serial.print(",");
    Serial.print(tempC, 2); Serial.print(",");
    Serial.print(humPct, 2); Serial.print(",");
  };

  // 1) Benchmark CSV lines (unchanged format)
  print_prefix(t, h); run_bench_csv(ALG_XTEA,    (const uint8_t*)plaintext, PAYLOAD_LEN);
  print_prefix(t, h); run_bench_csv(ALG_SPECK,   (const uint8_t*)plaintext, PAYLOAD_LEN);
  print_prefix(t, h); run_bench_csv(ALG_SIMON,   (const uint8_t*)plaintext, PAYLOAD_LEN);
  print_prefix(t, h); run_bench_csv(ALG_PRESENT, (const uint8_t*)plaintext, PAYLOAD_LEN);

  // 2) Send encrypted payloads to server (one ciphertext per algo per sample)
  //    (No extra output unless error; errors begin with '#')
  encrypt_once_and_send(ALG_XTEA,    now, t, h, (const uint8_t*)plaintext, PAYLOAD_LEN);
  encrypt_once_and_send(ALG_SPECK,   now, t, h, (const uint8_t*)plaintext, PAYLOAD_LEN);
  encrypt_once_and_send(ALG_SIMON,   now, t, h, (const uint8_t*)plaintext, PAYLOAD_LEN);
  encrypt_once_and_send(ALG_PRESENT, now, t, h, (const uint8_t*)plaintext, PAYLOAD_LEN);
}