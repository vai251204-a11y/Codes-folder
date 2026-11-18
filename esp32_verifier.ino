#include <WiFi.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <ESP32Servo.h>
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/version.h"

const char* WIFI_SSID   = "Vibhav07";
const char* WIFI_PASS   = "Vibhav07";
const char* MQTT_SERVER = "10.255.31.219";
const uint16_t MQTT_PORT = 1883;
const char* CLIENT_ID   = "esp32-node1";

const char* TOPIC_MSG = "/drone/channel";
const char* TOPIC_SIG = "/drone/channel_sig";

const uint8_t PUBLIC_KEY[65] = {0x04, 0x3e, 0x9c, 0x9a, 0x84, 0x7d, 0x03, 0x5b, 0xc3, 0x4e, 0x3b, 0x21, 0x13, 0x53, 0x49, 0xfd, 0x18, 0x88, 0x41, 0x44, 0x66, 0x89, 0x4b, 0xe8, 0xd5, 0xe5, 0x5c, 0x99, 0x2e, 0xf9, 0xfb, 0xa6, 0xf9, 0x68, 0xd6, 0x6f, 0xa3, 0xbe, 0xd8, 0x71, 0xfd, 0xa9, 0x50, 0x38, 0xdc, 0x94, 0xbb, 0xc5, 0x30, 0xde, 0x4f, 0x4d, 0xe5, 0x89, 0xaf, 0xa8, 0x66, 0xc5, 0x5d, 0x6f, 0xe4, 0xf6, 0xa1, 0xd1, 0x7f};

const char* TOKENS[100] = {
  "a9345fe6b5a59a4c", "548f691ca13a60cb", "cc90823bc1cd1383", "fe47fe853d1f9b1c",
  "d12ea84d291b4d28", "272d23baf8a3763e", "5dc8193059664051", "4e4b74273d63a202",
  "fa57d55a3e4753bb", "545074a314c57fbf", "7a2dd56852fe27d8", "266b73e4b31b2d0f",
  "a8dd2eec7f06f1e7", "e16f487247e52de7", "2d085295f2e40697", "5183753a80b5dd74",
  "9adf4ce3fc2ba79e", "97e96501f862864d", "e78c09dc39a387af", "6d939974280d14ba",
  "44c7d423896e11e3", "94b228e5832e99e4", "150fb1c413fe1698", "fcc1a0d5192d857b",
  "041a53a0578239b7", "27b3244bec090994", "a99d0b92a1ab9a68", "175b92916a0fa8dc",
  "526658c62c5b1c1c", "95280c9d5c523efc", "18685b9eeae299e1", "0f10b9d96009078b",
  "e99282976e18d07f", "37941948143cdd78", "41360483148eb361", "ed152a1da99bc709",
  "b9110a66f8c91b85", "123d939e7fbf4253", "ef8eec6ff1145863", "ada41c7e2e1e52b1",
  "271ed1ae9b0e24de", "a721a157faa29898", "8107640f58bc57cb", "d72604e8d57f3ff6",
  "0e9b576a29e4eb61", "dab79ad8e6aa8073", "52b5480019188ef9", "163c8e7cfeea1359",
  "75cf6cd44730480e", "ccc96e31be1f9130", "8c156b84f0c729d8", "53167656bd7aa228",
  "80719d9daa5c4c9d", "39d4642ebe4bf1b7", "f674fe4e292e0f5d", "a8c1f729f7cdc8ff",
  "6fb6054f46bb8bff", "8b159da752e4cec1", "d0884e2b37bc43fc", "10c782daebcf2b6f",
  "1847eede516f6fc5", "fb5ae5649073efc2", "aab94df67d209e09", "26d0759d57edc817",
  "a649a5f9ea98965a", "991574713229017e", "e49d812eb0c07f01", "7f04f6ece52d0659",
  "c76ebcf7f1ec0cf5", "1971443f991eb256", "c3d4fa9dded0c8db", "b300a9fec69c3ea5",
  "fe69d0b2f07faa4d", "b83f4ca3f2c69e7c", "26342e3d8890772e", "0b5638a53af007f4",
  "16c295f98ad83d4f", "58f51b4a9ab96a2a", "423af1867632a0aa", "2de351a0e0126d6a",
  "fdfb352a68382144", "cf6ad731e384e14b", "7413a1baa9cf1d81", "b43faa6c20320595",
  "08be1ef841dc52ce", "e2ac974441c187a2", "9102aeb9cfeb658e", "25902fc74d8fb43a",
  "d4573d644f5bc87d", "b9e9a27283d39e52", "1285b74d3f241661", "3d0009aa7fb470ea",
  "092ba9d7d25bcbad", "f3262fb0a2e1f1c9", "56ee85ad813ce542", "4aeab325a89766f2",
  "5255629cf1983faf", "895eae06538b8652", "5075f9022fd11128", "17299a8bf6fc23df"
};
const int NUM_TOKENS = 100;
const int LOOKAHEAD = 3;

const int SDA_PIN = 21;
const int SCL_PIN = 22;
const int SERVO_PIN = 13;
const uint8_t LCD_ADDRESS = 0x27;

WiFiClient espClient;
PubSubClient client(espClient);
LiquidCrystal_I2C lcd(LCD_ADDRESS, 16, 2);
Servo servo;

char msgBuf[48] = "";
char sigBuf[160] = "";
volatile bool haveMessage = false;
volatile bool readyToVerify = false;
int tokenIdx = 0;

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
bool hexToSig(const char* hex, unsigned int len, uint8_t* out) {
  if (len != 128) return false;
  for (int i = 0; i < 64; i++) {
    int hi = hexVal(hex[2*i]), lo = hexVal(hex[2*i+1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (hi << 4) | lo;
  }
  return true;
}

bool verifyString(const String& s, const uint8_t* sig64) {
  uint8_t hash[32];
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
#if defined(MBEDTLS_VERSION_MAJOR) && MBEDTLS_VERSION_MAJOR >= 3
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha, (const uint8_t*)s.c_str(), s.length());
  mbedtls_sha256_finish(&sha, hash);
#else
  mbedtls_sha256_starts_ret(&sha, 0);
  mbedtls_sha256_update_ret(&sha, (const uint8_t*)s.c_str(), s.length());
  mbedtls_sha256_finish_ret(&sha, hash);
#endif
  mbedtls_sha256_free(&sha);

  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi r, ss;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&ss);

  bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0
         && mbedtls_ecp_point_read_binary(&grp, &Q, PUBLIC_KEY, 65) == 0
         && mbedtls_mpi_read_binary(&r, sig64, 32) == 0
         && mbedtls_mpi_read_binary(&ss, sig64 + 32, 32) == 0
         && mbedtls_ecdsa_verify(&grp, hash, 32, &Q, &r, &ss) == 0;

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&ss);
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

void showOnLcd(const char* line1, const String& line2) {
  lcd.clear();
  lcd.setCursor(0, 0); lcd.print(line1);
  lcd.setCursor(0, 1); lcd.print(line2.substring(0, 16));
}

void doVerify() {
  String command = String(msgBuf);
  uint8_t sig[64];
  if (!hexToSig(sigBuf, strlen(sigBuf), sig)) {
    Serial.println("REJECTED: bad signature format");
    showOnLcd("REJECTED", "bad sig fmt");
    return;
  }

  int matched = -1;
  for (int k = 0; k <= LOOKAHEAD; k++) {
    int j = (tokenIdx + k) % NUM_TOKENS;
    String signedString = command + "|" + TOKENS[j];
    if (verifyString(signedString, sig)) { matched = j; break; }
  }

  if (matched >= 0) {
    tokenIdx = (matched + 1) % NUM_TOKENS;
    Serial.printf("ACCEPTED: %s (token %d)\n", command.c_str(), matched);
    showOnLcd("ACCEPTED", command);
    bool isNumber = command.length() > 0 && command.length() <= 3;
    for (unsigned int i = 0; i < command.length(); i++)
      if (!isdigit(command[i])) isNumber = false;
    int angle = command.toInt();
    if (isNumber && angle <= 180) { servo.write(angle); Serial.printf("servo -> %d\n", angle); }
  } else {
    Serial.printf("REJECTED: %s\n", command.c_str());
    showOnLcd("REJECTED", command);
  }
}

void callback(char* topic, byte* payload, unsigned int length) {
  if (strcmp(topic, TOPIC_MSG) == 0) {
    unsigned int n = length < sizeof(msgBuf) - 1 ? length : sizeof(msgBuf) - 1;
    memcpy(msgBuf, payload, n); msgBuf[n] = '\0';
    haveMessage = true;
  } else if (strcmp(topic, TOPIC_SIG) == 0) {
    unsigned int n = length < sizeof(sigBuf) - 1 ? length : sizeof(sigBuf) - 1;
    memcpy(sigBuf, payload, n); sigBuf[n] = '\0';
    if (haveMessage) { readyToVerify = true; haveMessage = false; }
  }
}

void setupWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.print("\nIP: "); Serial.println(WiFi.localIP());
}

void reconnect() {
  while (!client.connected()) {
    if (client.connect(CLIENT_ID)) {
      client.subscribe(TOPIC_MSG, 1);
      client.subscribe(TOPIC_SIG, 1);
      showOnLcd("Waiting for", "command...");
    } else { showOnLcd("MQTT failed", "retrying..."); delay(5000); }
  }
}

void setup() {
  Serial.begin(115200);
  Wire.begin(SDA_PIN, SCL_PIN);
  lcd.init(); lcd.backlight();
  showOnLcd("Drone link", "starting...");
  servo.attach(SERVO_PIN, 500, 2400);
  servo.write(0);
  setupWifi();
  client.setServer(MQTT_SERVER, MQTT_PORT);
  client.setBufferSize(512);
  client.setCallback(callback);
}

void loop() {
  if (!client.connected()) reconnect();
  client.loop();
  if (readyToVerify) {
    readyToVerify = false;
    doVerify();
  }
}
