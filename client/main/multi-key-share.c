/* OTA example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
//#include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "protocol_examples_common.h"
#include "errno.h"
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_sleep.h"

#include <string.h>

#include <mbedtls/ecdh.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/pk.h"
#include <mbedtls/ctr_drbg.h>

#include <sys/param.h>
#include "freertos/event_groups.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "addr_from_stdin.h"

#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

#define BUFFSIZE 1012
#define HASH_LEN 32 /* SHA-256 digest length */
#define HOST_IP_ADDR "192.168.144.48"
#define PORT 20001
#define MULTICAST_TTL 1
#define MULTICAST_IPV4_ADDR "232.10.11.12"

#define uS_TO_S_FACTOR 1000000  /* Conversion factor for micro seconds to seconds */
#define TIME_TO_SLEEP  13        /* Time ESP32 will go to sleep (in seconds) */

const char ant_key[]				= "key update start\n";
const char ant_key_done[]			= "key update done\n";

const char ant_dec[]				= "DEC start\n";
const char ant_dec_done[]			= "DEC done\n";

const char ant_SHA[]				= "SHA start\n";
const char ant_SHA_done[]			= "SHA done\n";

const char ant_HMAC[]				= "HMAC start\n";
const char ant_HMAC_done[]			= "HMAC done\n";

const char ant_mull_add[]				= "Mull add start\n";
const char ant_mull_add_done[]			= "Mull add done\n";



static const char *TAG = "ESP32_8";
/*an ota data write buffer ready to write to the flash*/
static char ota_write_data[BUFFSIZE + 1] = { 0 };

#define mac_offset 0
#define mac_length 32
#define session_id_offset 32
#define session_id_length 16
#define auth_offset 48
#define auth_length 32
#define Rnew1_offset 80
#define Rnew_length 32
#define Rnew2_offset 112
#define deviceCount_offset 144
#define deviceCount_length 1
#define xprime_offset 145
#define xprime_length 32


//Device key parts:
const uint8_t pub_x[] = {0xEE,0x8A,0x1F,0x7B,0x47,0x20,0x3A,0x41,0x7B,0x6A,0xC2,0x99,0xD0,0x94,0xDA,0x91,0x72,0xEE,0xD8,0xD7,0x4B,0xD0,0xE0,0x8D,0x45,0xE0,0x1C,0xAE,0x54,0x79,0x06,0x6C};
const uint8_t pub_y[] = {0x50,0xEC,0x2E,0xE9,0x66,0x45,0x34,0x0A,0x4B,0xFD,0x59,0x4C,0xD0,0x03,0x20,0xCF,0x10,0x62,0x5F,0x47,0x81,0xB3,0xB8,0x4B,0x05,0xEC,0x91,0x96,0xE3,0xAF,0x8B,0xC4};
const uint8_t privKeyBin[] = {0x0C,0x80,0xF3,0xC6,0xB1,0x5D,0xE1,0x02,0x4C,0x5E,0xFA,0xB9,0xEC,0xE8,0x0C,0x39,0x51,0x00,0xD8,0xBC,0xEC,0xA3,0x6E,0x02,0x87,0x91,0x46,0xA1,0x38,0xB6,0xF0,0x72};

//Server key parts:
const uint8_t server_pubKey_x[] = {0x24,0xDB,0xCC,0x31,0x19,0x5B,0x40,0xA4,0x49,0xA6,0xFD,0x36,0xE6,0x02,0x9E,0xAC,0x1C,0x06,0x62,0x64,0xE8,0xB3,0x61,0x5E,0x70,0x19,0x83,0x93,0x31,0x88,0x4A,0x32};
const uint8_t server_pubKey_y[] = {0x93,0x0D,0x40,0x8D,0xB4,0x8A,0xD8,0x59,0x9E,0x4B,0xE9,0xA6,0x12,0xD5,0x3E,0x56,0x78,0xAB,0x3B,0xDF,0x75,0xE3,0x5C,0xDD,0x36,0x9B,0xB6,0xA6,0x39,0xBC,0xDF,0xEF};
const uint8_t server_privKeyBin[] = {0xB9,0x85,0x74,0xF2,0x11,0x4A,0xEB,0xA4,0x35,0x7E,0x3C,0x2B,0x1C,0xBF,0x94,0x7F,0x55,0xBB,0xF2,0xBD,0x78,0x51,0x0E,0xF3,0x0A,0xD5,0x47,0x07,0xB5,0x5F,0x2D,0x7E};

static char Mac[mac_length] = {0xFF};
static char Session_id[session_id_length] = {0};
static char Auth[auth_length] = {0};
unsigned static char Rnew1[Rnew_length] = {0};
unsigned static char Rnew2[Rnew_length] = {0};
static char deviceCount[deviceCount_length] = {0};

char *key_star = "gv4rrcQoL3PWZG8V";

const char *device_id = "202106128789";

extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

#define OTA_URL_SIZE 256

static void __attribute__((noreturn)) task_fatal_error(void)
{
    ESP_LOGE(TAG, "Exiting task due to fatal error...");
    (void)vTaskDelete(NULL);

    while (1) {
        ;
    }
}

void uart_init()
{
	uart_config_t uart_config = {
		.baud_rate = 115200,
		.data_bits = UART_DATA_8_BITS,
		.parity = UART_PARITY_DISABLE,
		.stop_bits = UART_STOP_BITS_1,
		.flow_ctrl = UART_HW_FLOWCTRL_DISABLE
	};
	// Configure UART parameters
	ESP_ERROR_CHECK(uart_param_config(UART_NUM_0, &uart_config));
	ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, 1, 3, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
	ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, 256, 0, 0, NULL, 0));

	gpio_config_t io_conf = {
		.pin_bit_mask	= (1ULL << 4),
		.mode			= GPIO_MODE_OUTPUT,
		.pull_up_en		= 0,
		.pull_down_en	= 1,
		.intr_type		= GPIO_PIN_INTR_DISABLE
	};

	gpio_config(&io_conf);
}

void uart_send(const char *data, size_t len)
{
#ifdef CONFIG_SQ_UART_DBG
	ESP_LOGI(TAG, "[%s] - Sending %d bytes of data: %s", __FUNCTION__, len, data);
#endif

	/* Turn on output switch for Otii, and transmit an array of bytes for annotation.
	 * Wait until TX buffer is empty, preventing bogus data to be sent.
	 */
	ESP_ERROR_CHECK(uart_wait_tx_done(UART_NUM_0, 1000));
	gpio_set_level(4, 1);
	int res = uart_write_bytes(UART_NUM_0, data, len);
	/* Again, wait until finished before turning off the output. */
	ESP_ERROR_CHECK(uart_wait_tx_done(UART_NUM_0, 1000));
	gpio_set_level(4, 0);

#ifdef CONFIG_SQ_UART_DBG
	if (res >= 0) {
		ESP_LOGI(TAG, "[%s] - Sent %d bytes of data", __FUNCTION__, res);
	} else {
		ESP_LOGI(TAG, "[%s] - Parameter error", __FUNCTION__);
	}
#endif
}

static mbedtls_ecp_point cecies_p(mbedtls_ecp_point R)
{

    int ret = 1;
    mbedtls_ecp_group ecp_group;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi dj;
    mbedtls_mpi pr;
    mbedtls_mpi n;
    mbedtls_ecp_point P1;
    mbedtls_ecp_point QA;
    mbedtls_ecp_point S;
    mbedtls_ecp_point_init(&S);
    mbedtls_ecp_group_init(&ecp_group);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&dj);
    mbedtls_mpi_init(&pr);
    mbedtls_mpi_init(&n);
    //mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P1);
    mbedtls_ecp_point_init(&QA);

    //uint8_t P1_bytes[32] = { 0x00 };
    //size_t P1_bytes_length = 0;
    //ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    const char *pers = "CSR";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen( pers ));
    ret = mbedtls_ecp_group_load(&ecp_group,  MBEDTLS_ECP_DP_SECP256K1);
    //if (ret == 0){
    //  ESP_LOGI(TAG, "group load successfully");
    //}
    

    const uint8_t n_new[] = {0x01};

    //ret = mbedtls_ecp_point_read_binary(&ecp_group, &P1,  pubKeyBin, sizeof(pubKeyBin));
    ret = mbedtls_mpi_read_binary(&P1.X,  pub_x, 32);
    ret = mbedtls_mpi_read_binary(&P1.Y,  pub_y, 32);
    ret = mbedtls_mpi_read_binary(&pr, privKeyBin, 32);
    //ret = mbedtls_ecp_gen_keypair(&ecp_group, &dj, &QA, mbedtls_ctr_drbg_random, &ctr_drbg);
    ret = mbedtls_mpi_read_binary(&QA.X,  server_pubKey_x, 32);
    ret = mbedtls_mpi_read_binary(&QA.Y,  server_pubKey_y, 32);
    ret = mbedtls_mpi_read_binary(&dj, server_privKeyBin, 32);

    ret = mbedtls_mpi_read_binary(&n, n_new, 1);

    ret = mbedtls_mpi_lset(&P1.Z, 1);
    ret = mbedtls_mpi_lset(&QA.Z, 1);
    //ESP_LOGI(TAG, "size of X: %d", sizeof(pub_y));
    //ret = mbedtls_mpi_write_binary(&QA.X, P1_bytes, 32);
    //for (int i = 0; i < sizeof(P1_bytes); i++) {

    //    ESP_LOGI(TAG, "X is: %02X",P1_bytes[i]);
    //}

    //ret = mbedtls_mpi_write_binary(&QA.Y, P1_bytes, 32);
    //for (int i = 0; i < sizeof(P1_bytes); i++) {

    //    ESP_LOGI(TAG, "Y is: %02X",P1_bytes[i]);
    //}

    //ret = mbedtls_mpi_write_binary(&dj, P1_bytes, 32);
    //for (int i = 0; i < sizeof(P1_bytes); i++) {

    //    ESP_LOGI(TAG, "pr is: %02X",P1_bytes[i]);
    //}

    //ret = mbedtls_ecp_check_privkey(&ecp_group, &dj);
    //if (ret == 0)
    //{
    //    ESP_LOGI(TAG, "check private key successfully");
    //}
    ret = mbedtls_ecp_check_pubkey(&ecp_group, &QA);
    if (ret == 0){
      ESP_LOGI(TAG, "Check public key successfully");
    }
  
    //uart_send(ant_mull_add, sizeof(ant_mull_add));
    ret = mbedtls_ecp_muladd(&ecp_group, &S, &pr, &QA, &n, &R);
    //uart_send(ant_mull_add_done, sizeof(ant_mull_add_done));

    if (ret == 0){
        ESP_LOGI(TAG, "mull add was successful");
    }

    
    

    //ret = mbedtls_mpi_write_binary(&S.Y, P1_bytes, 32);
    //for (int i = 0; i < sizeof(P1_bytes); i++) {

      //  ESP_LOGI(TAG, "S Y is: %02X",P1_bytes[i]);
    //}

    return S;
  }

static void print_sha256 (const uint8_t *image_hash, const char *label)
{
    char hash_print[HASH_LEN * 2 + 1];
    hash_print[HASH_LEN * 2] = 0;
    for (int i = 0; i < HASH_LEN; ++i) {
        sprintf(&hash_print[i * 2], "%02x", image_hash[i]);
    }
    ESP_LOGI(TAG, "%s: %s", label, hash_print);
}

static void hmac_256(const char *payload, int payloadLength, char *output)
{

    unsigned char hmacResult[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    const size_t keyLength = strlen(key_star);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key_star, keyLength);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)payload, payloadLength);
    mbedtls_md_hmac_finish(&ctx, hmacResult);
    mbedtls_md_free(&ctx);

    memcpy(output, (char *)hmacResult, 32);

    //ESP_LOG_BUFFER_HEX("HMAC_256", hmacResult, 32);

}

static void hash_256(const char *payload, int payloadLength, char *output)
{
    unsigned char shaResult[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;


    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char *) payload, payloadLength);
    mbedtls_md_finish(&ctx, shaResult);
    mbedtls_md_free(&ctx);

    memcpy(output, (char *)shaResult, 32);

    //ESP_LOG_BUFFER_HEX("HASH_256", shaResult, 32);

}

static void decrypt_symmetric(unsigned char *input, char *iv, unsigned char *output, int len)
{
    mbedtls_gcm_context aes;
    mbedtls_gcm_init( &aes );
    //mbedtls_gcm_setkey( &aes, MBEDTLS_CIPHER_ID_AES , (const unsigned char*) KSW, strlen(KSW) * 8);
    //mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const unsigned char*)iv, strlen(iv), NULL, 0);
    //mbedtls_gcm_update(&aes,len,(const unsigned char*)input, output);
    //mbedtls_gcm_free( &aes );

    //ESP_LOG_BUFFER_HEX("decrypt is", output, 16);

}




static int socket_add_ipv4_multicast_group(int sock, bool assign_source_if)
{
    struct ip_mreq imreq = { 0 };
    struct in_addr iaddr = { 0 };
    int err = 0;
    // Configure source interface
#if LISTEN_ALL_IF
    imreq.imr_interface.s_addr = IPADDR_ANY;
#else
    esp_netif_ip_info_t ip_info = { 0 };
    err = esp_netif_get_ip_info(get_example_netif(), &ip_info);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get IP address info. Error 0x%x", err);
        goto err;
    }
    inet_addr_from_ip4addr(&iaddr, &ip_info.ip);
#endif // LISTEN_ALL_IF
    // Configure multicast address to listen to
    err = inet_aton(MULTICAST_IPV4_ADDR, &imreq.imr_multiaddr.s_addr);
    if (err != 1) {
        ESP_LOGE(TAG, "Configured IPV4 multicast address '%s' is invalid.", MULTICAST_IPV4_ADDR);
        // Errors in the return value have to be negative
        err = -1;
        goto err;
    }
    ESP_LOGI(TAG, "Configured IPV4 Multicast address %s", inet_ntoa(imreq.imr_multiaddr.s_addr));
    if (!IP_MULTICAST(ntohl(imreq.imr_multiaddr.s_addr))) {
        ESP_LOGW(TAG, "Configured IPV4 multicast address '%s' is not a valid multicast address. This will probably not work.", MULTICAST_IPV4_ADDR);
    }

    if (assign_source_if) {
        // Assign the IPv4 multicast source interface, via its IP
        // (only necessary if this socket is IPV4 only)
        err = setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &iaddr,
                         sizeof(struct in_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Failed to set IP_MULTICAST_IF. Error %d", errno);
            goto err;
        }
    }

    err = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &imreq, sizeof(struct ip_mreq));
    if (err < 0) {
        ESP_LOGE(TAG, "Failed to set IP_ADD_MEMBERSHIP. Error %d", errno);
        goto err;
    }

 err:
    return err;
}

static void infinite_loop(void)
{
    int i = 0;
    ESP_LOGI(TAG, "When a new firmware is available on the server, press the reset button to download it");
    while(1) {
        ESP_LOGI(TAG, "Waiting for a new firmware ... %d", ++i);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

static void ota_example_task(void *pvParameter)
{
    uart_init();
    //esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    //esp_ota_handle_t update_handle = 0 ;
    const esp_partition_t *update_partition = NULL;

    ESP_LOGI(TAG, "Starting key update");

    //const esp_partition_t *configured = esp_ota_get_boot_partition();
    //const esp_partition_t *running = esp_ota_get_running_partition();

    //if (configured != running) {
    //    ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
    //             configured->address, running->address);
    //    ESP_LOGW(TAG, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    //}
    //ESP_LOGI(TAG, "Running partition type %d subtype %d (offset 0x%08x)",
    //         running->type, running->subtype, running->address);

    /*esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_FIRMWARE_UPG_URL,
        .cert_pem = (char *)server_cert_pem_start,
        .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
    };*/

#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL_FROM_STDIN
    char url_buf[OTA_URL_SIZE];
    if (strcmp(config.url, "FROM_STDIN") == 0) {
        example_configure_stdin_stdout();
        fgets(url_buf, OTA_URL_SIZE, stdin);
        int len = strlen(url_buf);
        url_buf[len - 1] = '\0';
        config.url = url_buf;
    } else {
        ESP_LOGE(TAG, "Configuration mismatch: wrong firmware upgrade image url");
        abort();
    }
#endif

#ifdef CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK
    config.skip_cert_common_name_check = true;
#endif


    //Unicast socket
    char host_ip[] = HOST_IP_ADDR;
    int addr_family = 0;
    int ip_protocol = 0;

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(host_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    addr_family = AF_INET;
    ip_protocol = IPPROTO_IP;

    int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        task_fatal_error();
    }
    //ESP_LOGI(TAG, "Socket created, sending to %s:%d", HOST_IP_ADDR, PORT);
    //Unicast socket

    //Multicast socket
    struct sockaddr_in saddr = { 0 };
    int sockmulti = -1;
    int errm = 0;

    sockmulti = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sockmulti < 0) {
        ESP_LOGE(TAG, "Failed to create socket. Error %d", errno);
        task_fatal_error();
    }
    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(PORT);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    errm = bind(sockmulti, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    if (errm < 0) {
        ESP_LOGE(TAG, "Failed to bind socket. Error %d", errno);
        task_fatal_error();
    }
    uint8_t ttl = MULTICAST_TTL;
    setsockopt(sockmulti, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(uint8_t));
    if (errm < 0) {
        ESP_LOGE(TAG, "Failed to set IP_MULTICAST_TTL. Error %d", errno);
        task_fatal_error();

    }
    errm = socket_add_ipv4_multicast_group(sockmulti, true);
    if (errm < 0) {
        task_fatal_error();
    }
    //Multicast socket

    //esp_http_client_handle_t client = esp_http_client_init(&config);
    //if (client == NULL) {
    //    ESP_LOGE(TAG, "Failed to initialise HTTP connection");
    //    task_fatal_error();
    //}
    /*err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);*/


    update_partition = esp_ota_get_next_update_partition(NULL);
    //ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
    //         update_partition->subtype, update_partition->address);
    assert(update_partition != NULL);

    int binary_file_length = 0;
    /*deal with all receive packet*/

    /* Payload maker */
    const char udp_payload[] = {"ESP32_8: alive"};
    /* Payload maker */

    int erro = sendto(sock, udp_payload, strlen(udp_payload), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (erro < 0)
    {
        ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
    }
    ESP_LOGI(TAG, "Message sent");

    char data_respose[32] = { 0 };
    struct sockaddr_in source_addr_uni; // Large enough for both IPv4 or IPv6
    socklen_t socklenuni = sizeof(source_addr_uni);
    int response = recvfrom(sock, data_respose, 32, 0, (struct sockaddr *)&source_addr_uni, &socklenuni);
    //ESP_LOGI(TAG, "Get response from sock uni");

    const char exp_response[] = {"NewKey"};

    if (response < 0)
    {
        ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
        task_fatal_error();
    }
    // Data received
    else
    {
        //ESP_LOGI(TAG, "Received %d bytes from %s:", response, host_ip);
        if (memcmp(data_respose, exp_response, strlen(exp_response)) != 0)
        {
            sleep(20);
        }
    }
    
    bool retransmit = false;
    while (1) {
        //int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        //UDP read
        struct sockaddr_in source_addr; //Large enough for both IPv4 or IPv6
        socklen_t socklen = sizeof(source_addr);
        int data_read = 0;
        uart_send(ant_key, sizeof(ant_key));
        if (retransmit)
        {

            data_read = recvfrom(sock, ota_write_data, BUFFSIZE , 0, (struct sockaddr *)&source_addr, &socklen);
            ESP_LOGI(TAG, "Data retrasmit");
            ESP_LOGI(TAG, "Data read %d", data_read);

        }else
        {
            data_read = recvfrom(sockmulti, ota_write_data, BUFFSIZE , 0, (struct sockaddr *)&source_addr, &socklen);
            
        }


        // Error occurred during receiving
        if (data_read < 0)
        {
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            task_fatal_error();
        }
        // Data received
        else
        {
            //ota_write_data[data_read] = 0; // Null-terminate whatever we received and treat like a string
            //ESP_LOGI(TAG, "Received %d bytes from %s:", data_read, host_ip);
            //ESP_LOG_BUFFER_HEX(TAG,ota_write_data,BUFFSIZE);

        }


        //end udp read
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: data read error");
            //http_cleanup(client);
            task_fatal_error();
        } else if (data_read > 0) {
            //ESP_LOGI(TAG, "Read data is: %s", ota_write_data);

            memcpy(Mac, ota_write_data + mac_offset, mac_length);
            //ESP_LOG_BUFFER_HEX("mac is: ", Mac, 32);
            memcpy(Session_id, ota_write_data + session_id_offset, session_id_length);
            memcpy(Auth, ota_write_data + auth_offset, auth_length);
            //ESP_LOG_BUFFER_HEX("auth is: ", Auth, 32);
            memcpy(Rnew1, ota_write_data + Rnew1_offset, Rnew_length);
            //ESP_LOG_BUFFER_HEX("Rnew1 is: ", Rnew1, 32);
            memcpy(Rnew2, ota_write_data + Rnew2_offset, Rnew_length);
            memcpy(deviceCount, ota_write_data + deviceCount_offset, deviceCount_length);

            uint8_t dc = (uint8_t)deviceCount[0];
            //ESP_LOGI(TAG, "dc int is %d", dc);
            /*const char **xprime = malloc(dc);
            
            for(int i = 0; i < dc; i++){
               xprime[i] = malloc(xprime_length);}
*/

            //const char xprime[5][32] = {};
            const char** xprime = (const char**)malloc(dc * sizeof(const char*));
                for (int i = 0; i < dc; i++)
                    xprime[i] = (const char*)malloc(xprime_length * sizeof(const char));

            char *mac_to_calculate = malloc(session_id_length + auth_length + (Rnew_length*2) + (xprime_length*dc)+1);


            for( int a = 0; a < dc; a = a + 1 ){
                  memcpy(xprime[a], ota_write_data + xprime_offset + (a*xprime_length), xprime_length);
                  ESP_LOG_BUFFER_HEX("xprime is: ", xprime[a], 32);
            }

            

            //ESP_LOGI(TAG, "For of xprime was ok");
            memcpy(mac_to_calculate, ota_write_data + session_id_offset, session_id_length + auth_length + Rnew_length*2 + xprime_length*dc+1);
            //ESP_LOG_BUFFER_HEX("mac to calculate is: ", mac_to_calculate, session_id_length + auth_length + Rnew_length*2 + xprime_length*dc+1);
            char hmac[32]= {0};
            mbedtls_ecp_point R;
            mbedtls_ecp_point S;
            mbedtls_ecp_point_init(&S);
            mbedtls_ecp_point_init(&R);
            mbedtls_ecp_group ecp_group;
            mbedtls_ecp_group_init(&ecp_group);
            int rr = mbedtls_ecp_group_load(&ecp_group,  MBEDTLS_ECP_DP_SECP256K1);
            //rr = mbedtls_ecp_point_read_binary(&ecp_group, &R,  Rnew, sizeof(Rnew));
            rr = mbedtls_mpi_read_binary(&R.X,  Rnew1, Rnew_length);
            rr = mbedtls_mpi_read_binary(&R.Y,  Rnew2, Rnew_length);
            rr = mbedtls_mpi_lset(&R.Z, 1);

            hmac_256(mac_to_calculate, session_id_length + auth_length + Rnew_length*2 + xprime_length*dc +1 , hmac);
            ESP_LOG_BUFFER_HEX("hmac is: ", hmac, 32);
            int err = 1; 

            if (memcmp( hmac , Mac,32) == 0 )
            {

                ESP_LOGI(TAG, "MAC checking is passed");

                S = cecies_p(R);
                char xor[32] = {0};
                int device_number  = 0;
                uint8_t Sx_bytes[32] = { 0x00 };
                uint8_t Sy_bytes[32] = { 0x00 };
                //size_t P1_bytes_length = 0;
                rr = mbedtls_mpi_write_binary(&S.X, Sx_bytes, 32);
                rr = mbedtls_mpi_write_binary(&S.Y, Sy_bytes, 32);

                uint8_t Rx_bytes[32] = { 0x00 };
                uint8_t Ry_bytes[32] = { 0x00 };
                //size_t P1_bytes_length = 0;
                rr = mbedtls_mpi_write_binary(&R.X, Rx_bytes, 32);
                rr = mbedtls_mpi_write_binary(&R.Y, Ry_bytes, 32);

                //ESP_LOG_BUFFER_HEX("Rx  is: ", Rx_bytes, 32);
                //ESP_LOG_BUFFER_HEX("Ry  is: ", Ry_bytes, 32);
                //ESP_LOG_BUFFER_HEX("Sx  is: ", Sx_bytes, 32);
                //ESP_LOG_BUFFER_HEX("Sy  is: ", Sy_bytes, 32);

                for(int i = 0; i < xprime_length; i++){
                    xor[i] = xprime[device_number][i]^Sx_bytes[i]^Sy_bytes[i];}

                //ESP_LOG_BUFFER_HEX("xor is: ", xor, 32);
                char key[32] = {0};
                hash_256(xor , 32 , key);
                //ESP_LOG_BUFFER_HEX("key is: ", key, 32);

                char *result = malloc(sizeof(key)+Rnew_length*2+dc*xprime_length);
                memcpy(result, key, sizeof(key));
                memcpy(result+sizeof(key), Rx_bytes, sizeof(Rx_bytes));
                memcpy(result+sizeof(key)+sizeof(Rx_bytes), Ry_bytes, sizeof(Ry_bytes));
                for(int i = 0; i < dc; i++){
                    if( i == 0){
                        memcpy(result+sizeof(key)+sizeof(Rx_bytes)+sizeof(Ry_bytes), xprime[i], xprime_length);}

                    else{
                        memcpy(result+sizeof(key)+sizeof(Rx_bytes)+sizeof(Ry_bytes)+(32*i), xprime[i], xprime_length);
                    }
                    }
            
                //ESP_LOG_BUFFER_HEX("result is: ", result, sizeof(key)+Rnew_length*2+dc*xprime_length);

                char hash[32] = {0};
                char ack[32] = {0};
                hash_256(result , 96+32*dc , hash);
                ESP_LOG_BUFFER_HEX("hash is: ", hash, 32);
                if (memcmp( hash , Auth,32) == 0 ){
                    ESP_LOGI(TAG, "Hash checking is passed");
                    char *ack_hash = malloc(session_id_length+Rnew_length*2);
                    memcpy(ack_hash, Session_id, session_id_length);
                    memcpy(ack_hash+session_id_length, pub_x, sizeof(pub_x));
                    memcpy(ack_hash+session_id_length+sizeof(pub_x), pub_y, sizeof(pub_y));
                    hash_256(ack_hash , session_id_length+Rnew_length*2 , ack);
                    char ack_total[44] = {0};
                    memcpy(ack_total, ack, 32);
                    memcpy(ack_total+32, device_id, 12);
                    //ESP_LOG_BUFFER_HEX("ack total is: ", ack_total, 44);
                    //sleep(1);
                    err = sendto(sock, ack_total, 44, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                    uart_send(ant_key_done, sizeof(ant_key_done));
                    
                    if (err < 0)
                    {
                        ESP_LOGE(TAG, "Error occurred during sending ack: errno %d", errno);
                        break;
                    }
                    else{
                       ESP_LOGI(TAG, "Ack was sent successfully"); 
                    }
                     //send ack
                   }
                   //uart_send(ant_SHA, sizeof(ant_SHA));

                    //hash_256(ota_write_data, session_id_length + auth_length + Rnew_length , hash);
                    //uart_send(ant_SHA_done, sizeof(ant_SHA_done));

                    //uart_send(ant_dec_done, sizeof(ant_dec_done));

                    //write key in memory

                     //err = esp_ota_write(update_handle, (const void *)output, enc_length);
                if (err != ESP_OK)
                     {
                         //http_cleanup(client);
                         task_fatal_error();
                     }
                     binary_file_length += data_read;
                     ESP_LOGD(TAG, "Written image length %d", binary_file_length);


            }
            else if (data_read == 0)
            {
                /*
            * As esp_http_client_read never returns negative error code, we rely on
            * `errno` to check for underlying transport connectivity closure if any
            */
                if (errno == ECONNRESET || errno == ENOTCONN)
                {
                    ESP_LOGE(TAG, "Connection closed, errno = %d", errno);
                    break;
                }
                /*if (esp_http_client_is_complete_data_received(client) == true)
                {
                    ESP_LOGI(TAG, "Connection closed");
                    break;
                }*/
            }


        }
    }

    //ESP_LOGI(TAG, "Prepare to restart system!");
    uart_send(ant_key_done, sizeof(ant_key_done));
    //esp_restart();

    return ;
}

static bool diagnostic(void)
{
    gpio_config_t io_conf;
    io_conf.intr_type    = GPIO_INTR_DISABLE;
    io_conf.mode         = GPIO_MODE_INPUT;
    io_conf.pin_bit_mask = (1ULL << CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en   = GPIO_PULLUP_ENABLE;
    gpio_config(&io_conf);

    ESP_LOGI(TAG, "Diagnostics (5 sec)...");
    vTaskDelay(5000 / portTICK_PERIOD_MS);

    bool diagnostic_is_ok = gpio_get_level(CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);

    gpio_reset_pin(CONFIG_EXAMPLE_GPIO_DIAGNOSTIC);
    return diagnostic_is_ok;
}

void app_main(void)
{

    uint8_t sha_256[HASH_LEN] = { 0 };
    esp_partition_t partition;

    // get sha256 digest for the partition table
    partition.address   = ESP_PARTITION_TABLE_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_MAX_LEN;
    partition.type      = ESP_PARTITION_TYPE_DATA;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for the partition table: ");

    // get sha256 digest for bootloader
    partition.address   = ESP_BOOTLOADER_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_OFFSET;
    partition.type      = ESP_PARTITION_TYPE_APP;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for bootloader: ");

    // get sha256 digest for running partition
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    print_sha256(sha_256, "SHA-256 for current firmware: ");

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            // run diagnostic function ...
            bool diagnostic_is_ok = diagnostic();
            if (diagnostic_is_ok) {
                ESP_LOGI(TAG, "Diagnostics completed successfully! Continuing execution ...");
                esp_ota_mark_app_valid_cancel_rollback();
            } else {
                ESP_LOGE(TAG, "Diagnostics failed! Start rollback to the previous version ...");
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
        }
    }

    // Initialize NVS.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

#if CONFIG_EXAMPLE_CONNECT_WIFI
    /* Ensure to disable any WiFi power save mode, this allows best throughput
     * and hence timings for overall OTA operation.
     */
    esp_wifi_set_ps(WIFI_PS_NONE);
#endif // CONFIG_EXAMPLE_CONNECT_WIFI

    xTaskCreate(&ota_example_task, "ota_example_task", 8192, NULL, 5, NULL);
}
