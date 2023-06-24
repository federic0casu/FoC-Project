#define RECIPIENT_SIZE	32

#define REQUEST_PACKET_SIZE sizeof(uint16_t) + sizeof(uint8_t[RECIPIENT_SIZE]) + sizeof(uint32_t)

#define CODE_BALANCE_REQUEST  	0x01
#define CODE_TRANSFER_REQUEST 	0x02
#define CODE_LIST_REQUEST    	0x03

#define CODE_BALANCE_RESPONSE	0x04
#define CODE_TRANSFER_RESPONSE 	0x05
#define CODE_LIST_RESPONSE_1 	0x06
#define CODE_LIST_RESPONSE_2 	0x07

#define BALANCE_RESPONSE_SIZE	8
#define LIST_RESPONSE_1_SIZE	sizeof(uint16_t) + sizeof(uint8_t[RECIPIENT_SIZE]) + sizeof(uint32_t) + sizeof(uint32_t)
#define LIST_RESPONSE_2_SIZE	sizeof(uint16_t) + sizeof(uint8_t[RECIPIENT_SIZE]) + sizeof(uint32_t) + sizeof(uint32_t)

#define DECRYPTED_SIGNATURE_SIZE 256
