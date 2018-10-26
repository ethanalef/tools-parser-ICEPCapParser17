#pragma once

#define	PAYLOAD_POSN					54

#define PAYLOAD_START_CHAR				START_CHAR
#define _PAYLOAD_START_CHAR				{ 0x04, 0x20, 0x00, 0x00, 0x00 }
#define PAYLOAD_NUM_START_CHAR			5
const unsigned char START_CHAR[PAYLOAD_NUM_START_CHAR] = _PAYLOAD_START_CHAR;

#define PAYLOAD_END_CHAR				END_CHAR
#define _PAYLOAD_END_CHAR				{ 0x03 }
#define PAYLOAD_NUM_END_CHAR			1
const unsigned char END_CHAR[PAYLOAD_NUM_END_CHAR] = _PAYLOAD_END_CHAR;

