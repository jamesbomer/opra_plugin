/* packet-gryphon.c
 *
 * Routines for OPRA protocol packet disassembly
 * By J. Bomer starting from the gryphon decoder
 * by Steve Limkemann <stevelim@dgtech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include <math.h>
#include <string.h>
#include <assert.h>

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-opra.h"

void proto_register_opra(void);
void proto_reg_handoff_opra(void);

static int dissect_opra(tvbuff_t *, packet_info *, proto_tree *, void*);
static int dissect_opra_message_category_C(tvbuff_t *, int, packet_info *, proto_tree *, void*);
static int dissect_opra_message_category_a(tvbuff_t *, int, packet_info *, proto_tree *, void*);
static int dissect_opra_message_category_d(tvbuff_t *, int, packet_info *, proto_tree *, void*);
static int dissect_opra_message_category_k(tvbuff_t *, int, packet_info *, proto_tree *, void*);
static int dissect_opra_message_category_q(tvbuff_t *, int, packet_info *, proto_tree *, void*);
static int dissect_opra_quote_appendage(tvbuff_t *, int, packet_info *, proto_tree *, void*, uint32_t);

/*port ranges for OPRA UDP dissemination*/
#define OPRA_UDP_PORT_MIN 54321
#define OPRA_UDP_PORT_MAX 54321

/*block header size and message header size are fixed. Message sizes vary.*/
#define OPRA_BLOCK_HEADER_SIZE 21
#define OPRA_MESSAGE_HEADER_SIZE 12

static int proto_opra;
static int ett_opra;
static int ett_opra_message_header;

/*expert fields*/
static expert_field hf_opra_exp_block_length_error;

/*block header and trailer fields*/
static int hf_opra_version;
static int hf_opra_block_size;
static int hf_opra_data_feed_indicator;
static int hf_opra_retransmission_indicator;
static int hf_opra_session_indicator;
static int hf_opra_block_sequence_number;
static int hf_opra_messages_in_block;
static int hf_opra_block_timestamp;
static int hf_opra_block_checksum;
static int hf_opra_block_pad_byte;

/*message header fields*/
static int hf_opra_msg_hdr_participant_id;
static int hf_opra_msg_hdr_message_category;
static int hf_opra_msg_hdr_message_type;
static int hf_opra_msg_hdr_message_indicator;
static int hf_opra_msg_hdr_transaction_id;
static int hf_opra_msg_hdr_participant_reference_number;

/*fields for specific message types follow:*/
/*administrative*/
static int hf_opra_msg_cat_C_data_length;
static int hf_opra_msg_cat_C_data;

/*control messages are message header only.*/

/*last sale*/
static int hf_opra_msg_cat_a_security_symbol;
static int hf_opra_msg_cat_a_reserved1;
static int hf_opra_msg_cat_a_expiration_block;
static int hf_opra_msg_cat_a_strike_price_denominator_code;
static int hf_opra_msg_cat_a_strike_price;
static int hf_opra_msg_cat_a_volume;
static int hf_opra_msg_cat_a_premium_price_denominator_code;
static int hf_opra_msg_cat_a_premium_price;
static int hf_opra_msg_cat_a_trade_identifier;
static int hf_opra_msg_cat_a_reserved2;

/*open interest*/
static int hf_opra_msg_cat_d_security_symbol;
static int hf_opra_msg_cat_d_reserved;
static int hf_opra_msg_cat_d_expiration_block;
static int hf_opra_msg_cat_d_strike_price_denominator_code;
static int hf_opra_msg_cat_d_strike_price;
static int hf_opra_msg_cat_d_volume;

/*long quote*/
static int hf_opra_msg_cat_k_security_symbol;
static int hf_opra_msg_cat_k_reserved;
static int hf_opra_msg_cat_k_expiration_block;
static int hf_opra_msg_cat_k_strike_price_denominator_code;
static int hf_opra_msg_cat_k_strike_price;
static int hf_opra_msg_cat_k_premium_price_denominator_code;
static int hf_opra_msg_cat_k_bid_price;
static int hf_opra_msg_cat_k_bid_size;
static int hf_opra_msg_cat_k_offer_price;
static int hf_opra_msg_cat_k_offer_size;

/*short quote*/
static int hf_opra_msg_cat_q_security_symbol;
static int hf_opra_msg_cat_q_expiration_block;
static int hf_opra_msg_cat_q_strike_price;
static int hf_opra_msg_cat_q_bid_price;
static int hf_opra_msg_cat_q_bid_size;
static int hf_opra_msg_cat_q_offer_price;
static int hf_opra_msg_cat_q_offer_size;

/*bid/offer appendages*/
static int hf_opra_msg_bid_appendage_participant_id;
static int hf_opra_msg_bid_appendage_denominator_code;
static int hf_opra_msg_bid_appendage_price;
static int hf_opra_msg_bid_appendage_size;

static int hf_opra_msg_offer_appendage_participant_id;
static int hf_opra_msg_offer_appendage_denominator_code;
static int hf_opra_msg_offer_appendage_price;
static int hf_opra_msg_offer_appendage_size;

/*friendly display names for simple enum fields*/
static const value_string hf_opra_data_feed_indicators[] = {
    {'O', "OPRA"},
    { 0, NULL}
};

static const value_string hf_opra_retransmission_indicators[] = {
    {' ', "Normal"},
    {'V', "Retransmitted"},
    { 0, NULL}
};

static const value_string hf_opra_session_indicators[] = {
    { 0, "Normal"},
    {'X', "Pre-market Extended"}
};

static const value_string hf_opra_participant_ids[] = {
    {'A', "AMEX"},
    {'B', "BOX"},
    {'C', "CBOE"},
    {'D', "EMERALD"},
    {'E', "EDGX"},
    {'H', "GEMX"},
    {'I', "ISE"},
    {'J', "MRX"},
    {'M', "MIAX"},
    {'N', "NYSE"},
    {'O', "OPRA"},
    {'P', "PEARL"},
    {'Q', "MIAX"},
    {'T', "BX"},
    {'W', "C2"},
    {'X', "PHLX"},
    {'Z', "BATS"},
    { 0, NULL}
};

static const value_string hf_opra_message_categories[] = {
    {'a', "Equity and Index Last Sale"},
    {'d', "Open Interest"},
    {'f', "Equity and Index End of Day Summary"},
    {'k', "Equity and Index Long Quote"},
    {'q', "Equity and Index Short Quote"},
    {'C', "Administrative"},
    {'H', "Control"},
    {'Y', "Underlying Value"},
    { 0, NULL}
};

/*Decoding of message type depends on message category.
  Some types have both a short and long description, combine those into one string for display.*/
#define OPRA_MESSAGE_TYPES_DISPLAY_STRING(w, x, y) {w, x " : " y},

/*administrative*/
#define OPRA_MSG_CAT_C_TYPES(D) \
    D(' ', "", "Administrative")
static const value_string hf_opra_msg_cat_C_types[] = {
    OPRA_MSG_CAT_C_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*control*/
#define OPRA_MSG_CAT_H_TYPES(D) \
    D('C', "", "Start of Day") \
    D('E', "", "Start of Summary") \
    D('F', "", "End of Summary") \
    D('J', "", "End of Day") \
    D('K', "", "Reset Block Sequence Number") \
    D('L', "", "Start of Open Interest") \
    D('M', "", "End of Open Interest") \
    D('N', "", "Line Integrity") \
    D('P', "", "Disaster Recovery Data Center Activation")
static const value_string hf_opra_msg_cat_H_types[] = {
    OPRA_MSG_CAT_H_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*Underlying Value*/
#define OPRA_MSG_CAT_Y_TYPES(D) \
    D(' ', "", "Index based on Last Sale") \
    D('I', "", "Index based on Bid and Offer")
static const value_string hf_opra_msg_cat_Y_types[] = {
    OPRA_MSG_CAT_Y_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*last sale*/
#define OPRA_MSG_CAT_a_TYPES(D) \
    D('A', "CANC", "Previously reported (except last or opening) now to be cancelled") \
    D('B', "OSEQ", "Reported late and out of sequence") \
    D('C', "CNCL", "Last reported and is now cancelled") \
    D('D', "LATE", "Reported late, but in correct sequence") \
    D('E', "CNCO", "First report of day, now to be cancelled") \
    D('F', "OPEN", "Late report of opening trade, and is out of sequence") \
    D('G', "CNOL", "Only report for day, now to be cancelled") \
    D('H', "OPNL", "Late report of opening trade, but in correct sequence") \
    D('I', "AUTO", "Executed electronically") \
    D('J', "REOP", "Reopening after halt") \
    D('S', "ISOI", "Execution of Intermarket Sweep Order") \
    D('a', "SLAN", "Single Leg Auction, non ISO") \
    D('b', "SLAI", "Single Leg Auction, ISO") \
    D('c', "SLCN", "Single Leg Cross, non ISO") \
    D('d', "SLCI", "Single Leg Cross, ISO") \
    D('e', "SLFT", "Single Leg Floor Trade") \
    D('f', "MLET", "Multi Leg Auto-Electronic Trade") \
    D('g', "MLAT", "Multi Leg Auction") \
    D('h', "MLCT", "Multi Leg Cross") \
    D('i', "MLFT", "Multi Leg Floor Trade") \
    D('j', "MESL", "Multi Leg Auto-Electronic Trade against single leg(s)") \
    D('k', "TLAT", "Stock Options Auction") \
    D('l', "MASL", "Multi Leg Auction against single leg(s)") \
    D('m', "MFSL", "Multi Leg Floor Trade against single leg(s)") \
    D('n', "TLET", "Stock Options Auto-Electronic Trade") \
    D('o', "TLCT", "Stock Options Cross") \
    D('p', "TLFT", "Stock Options Floor Trade") \
    D('q', "TESL", "Stock Options Auto-Electronic Trade against single leg(s)") \
    D('r', "TASL", "Stock Options Auction against single leg(s)") \
    D('s', "TFSL", "Stock Options Floor Trade against single leg(s)") \
    D('t', "CBMO", "Multi Leg Floor Trade of Proprietary Products") \
    D('u', "MCTP", "Multilateral Compression Trade of Proprietary Products") \
    D('v', "EXHT", "Extended Hours Trade")

static const value_string hf_opra_msg_cat_a_types[] = {
    OPRA_MSG_CAT_a_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*open interest*/
#define OPRA_MSG_CAT_d_TYPES(D) \
    D(' ', "", "Open Interest")

static const value_string hf_opra_msg_cat_d_types[] = {
    OPRA_MSG_CAT_d_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*open interest*/
#define OPRA_MSG_CAT_f_TYPES(D) \
    D(' ', "", "Equity and Index End of Day Summary")

static const value_string hf_opra_msg_cat_f_types[] = {
    OPRA_MSG_CAT_f_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*long quote*/
#define OPRA_MSG_CAT_k_TYPES(D) \
    D(' ', "", "Regular Trading") \
    D('F', "", "Non-Firm Quote") \
    D('I', "", "Indicative Value") \
    D('R', "", "Rotation") \
    D('T', "", "Trading Halted") \
    D('A', "", "Eligible for Automatic Execution") \
    D('B', "", "Bid Contains Customer Trading Interest") \
    D('O', "", "Offer Contains Customer Trading Interest") \
    D('C', "", "Both Bid and Offer Contain Customer Trading Interest") \
    D('X', "", "Offer Side of Quote Not Firm; Bid Side Firm") \
    D('Y', "", "Bid Side of Quote Not Firm; Offer Side Firm")

static const value_string hf_opra_msg_cat_k_types[] = {
    OPRA_MSG_CAT_k_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*short quote, currently same as long quote*/
#define OPRA_MSG_CAT_q_TYPES(D) \
    D(' ', "", "Regular Trading") \
    D('F', "", "Non-Firm Quote") \
    D('I', "", "Indicative Value") \
    D('R', "", "Rotation") \
    D('T', "", "Trading Halted") \
    D('A', "", "Eligible for Automatic Execution") \
    D('B', "", "Bid Contains Customer Trading Interest") \
    D('O', "", "Offer Contains Customer Trading Interest") \
    D('C', "", "Both Bid and Offer Contain Customer Trading Interest") \
    D('X', "", "Offer Side of Quote Not Firm; Bid Side Firm") \
    D('Y', "", "Bid Side of Quote Not Firm; Offer Side Firm")

static const value_string hf_opra_msg_cat_q_types[] = {
    OPRA_MSG_CAT_q_TYPES(OPRA_MESSAGE_TYPES_DISPLAY_STRING)
    { 0, NULL}
};

/*associate category with permitted message types*/
typedef struct _hf_opra_msg_cat_to_types_detail {
    char category;
    const value_string *message_types;
} hf_opra_msg_cat_to_types_detail;

static const hf_opra_msg_cat_to_types_detail hf_opra_msg_cat_to_types[] = {
    {.category = 'C', .message_types = hf_opra_msg_cat_C_types},
    {'H', hf_opra_msg_cat_H_types},
    {'Y', hf_opra_msg_cat_Y_types},
    {'a', hf_opra_msg_cat_a_types},
    {'d', hf_opra_msg_cat_d_types},
    {'f', hf_opra_msg_cat_f_types},
    {'k', hf_opra_msg_cat_k_types},
    {'q', hf_opra_msg_cat_q_types},
    { 0, NULL}
};

static const hf_opra_msg_cat_to_types_detail *FindTypesForCategory(char category)
{
    const hf_opra_msg_cat_to_types_detail *p = hf_opra_msg_cat_to_types;
    assert(NULL != p);

    while (0 != p->category){
        if (category == p->category)
            return p;

        /*advance to next array entry*/
        p++;
    }

    return NULL;
}

/*get appropriate description for message type, depending on message category*/
static const char* GetMessageTypeDescription(uint32_t message_category, uint8_t message_type)
{
    /*get the map detail for this category*/
    const hf_opra_msg_cat_to_types_detail *pMessageTypes = FindTypesForCategory(message_category);
    if (NULL == pMessageTypes)
        return "cat not found";

    /*look at each types entry until we find one that matches our type, or return "not found"*/
    return val_to_str(message_type, pMessageTypes->message_types, "type not found");
}

/*Message Indicator decoding for short and long quote types*/
static const value_string hf_opra_message_indicators[] = {
    {'A', "No Best Bid Change, No Best Offer Change"},
    {'B', "No Best Bid Change, Quote Contains Best Offer"},
    {'C', "No Best Bid Change, Best Offer Appendage"},
    {'D', "No Best Bid Change, No Best Offer"},

    {'E', "Quote Contains Best Bid, No Best Offer Change"},
    {'F', "Quote Contains Best Bid, Quote Contains Best Offer"},
    {'G', "Quote Contains Best Bid, Best Offer Appendage"},
    {'H', "Quote Contains Best Bid, No Best Offer"},

    {'I', "No Best Bid, No Best Offer Change"},
    {'J', "No Best Bid, Quote Contains Best Offer"},
    {'K', "No Best Bid, Best Offer Appendage"},
    {'L', "No Best Bid, No Best Offer"},

    {'M', "Best Bid Appendage, No Best Offer Change"},
    {'N', "Best Bid Appendage, Quote Contains Best Offer"},
    {'O', "Best Bid Appendage, Best Offer Appendage"},
    {'P', "Best Bid Appendage, No Best Offer"},

    {' ', "Unused"},
    { 0, NULL}
};

/*these Message Indicator values indicate the presence of quote appendages*/
static const char *hf_opra_msg_indicator_best_offer_appendages _U_ = "CGKO";
static const char *hf_opra_msg_indicator_best_bid_appendages _U_ = "MNOP";

/*fixed point denominator codes used by the spec.  Various uses for these.*/
#define OPRA_DENOMINATOR_CODE_LIST(D) \
    D('A', _1dps, "(%d) %d.%01d", "1 DPS") \
    D('B', _2dps, "(%d) %d.%02d", "2 DPS") \
    D('C', _3dps, "(%d) %d.%03d", "3 DPS") \
    D('D', _4dps, "(%d) %d.%04d", "4 DPS") \
    D('E', _5dps, "(%d) %d.%05d", "5 DPS") \
    D('F', _6dps, "(%d) %d.%06d", "6 DPS") \
    D('G', _7dps, "(%d) %d.%07d", "7 DPS") \
    D('H', _8dps, "(%d) %d.%08d", "8 DPS") \
    D('I', _0dps, "(%d) %d", "0 DPS")

/*define the denom codes in an enum*/
#define OPRA_DENOMINATOR_CODE_ENUM_ENTRY(w, x, y, z) x = w,
typedef enum _denom_code {
    OPRA_DENOMINATOR_CODE_LIST(OPRA_DENOMINATOR_CODE_ENUM_ENTRY)
} denom_code;

/*value_string array for display of the denom code*/
#define OPRA_DENOMINATOR_CODE_DISPLAY_STRING_ENTRY(w, x, y, z) { x, z },
static const value_string hf_opra_denominator_codes[] = {
    OPRA_DENOMINATOR_CODE_LIST(OPRA_DENOMINATOR_CODE_DISPLAY_STRING_ENTRY)
    {0, NULL}
};

/*value_string array for formatting prices depending on denom code*/
#define OPRA_DENOMINATOR_CODE_FORMAT_STRING_ENTRY(w, x, y, z) { x, y },
static const value_string denom_code_format_strings[] = {
    OPRA_DENOMINATOR_CODE_LIST(OPRA_DENOMINATOR_CODE_FORMAT_STRING_ENTRY)
    {0, NULL}
};

//TODO - check upcasting of char into uint32_t if I'm doing that anywhere - char might be signed on some systems.

/*Price formatting utility functions*/
static void DisplayPrice(char *pBuff, uint32_t value, denom_code code)
{
    if (NULL == pBuff)
        return;

    const char *fmt = val_to_str(code, denom_code_format_strings, "bad denom_code");

    /*make use of the ascending ascii values for denom code, 0dps is the exception*/
    uint32_t divisor;
    if (_0dps == code) {divisor = 1;}
        else {divisor = pow(10, ((uint8_t) (code - _1dps) + 1));}

    const uint32_t whole_part = value / divisor;
    const uint32_t fraction_part = value % divisor;

    int size = snprintf(pBuff, ITEM_LABEL_LENGTH, fmt, value, whole_part, fraction_part);

    if (size > ITEM_LABEL_LENGTH) {snprintf(pBuff, ITEM_LABEL_LENGTH, "xxxx");}

    return;
}

/*Helper functions for use with BASE_CUSTOM fields*/
static void DisplayShortQuoteStrikePrice(char *pBuff, uint32_t value)
{
    /*per spec is implied 1 decimal place*/
    return DisplayPrice(pBuff, value, _1dps);
}

static void DisplayShortQuotePrice(char *pBuff, uint32_t value)
{
    /*per spec is implied 2 decimal places*/
    return DisplayPrice(pBuff, value, _2dps);
}

static void DisplayShortQuoteSize(char * pBuff, uint32_t value)
{
    /*per spec is implied whole number*/
    return DisplayPrice(pBuff, value, _0dps);
}

/*registration*/
void proto_register_opra(void)
{
    /*set up expert error reporting*/
    expert_module_t* expert_opra;
    static ei_register_info ei[] = {
        {
            &hf_opra_exp_block_length_error,
            { "opra.block_length_error",
            PI_DEBUG, PI_WARN,
            "block length length doesn't match buffer bytes", EXPFILL}
        }
    };

    /*field definitions*/
    static hf_register_info hf[] = {
        /*Block Header*/
        {
            &hf_opra_version,
            {   "OPRA Version", "opra.version",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_block_size,
            {   "OPRA Block Size", "opra.block_size",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_data_feed_indicator,
            {   "OPRA Data Feed Indicator", "opra.data_feed_indicator",
                /*only INTx and UINTx are permitted non-null 'strings' values, see README.dissector.
                  But char should be OK, it's an unsigned 8 bit integer in wireshark, and it displays more usefully by showing the ASCII rather than the hex value*/
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_data_feed_indicators), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_retransmission_indicator,
            {   "OPRA Retransmission Indicator", "opra.retransmission_indicator",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_retransmission_indicators), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_session_indicator,
            /*can't be decoded as CHAR as it might be 0x00*/
            {   "OPRA Session Indicator", "opra.session_indicator",
                FT_UINT8, BASE_HEX,
                VALS(hf_opra_session_indicators), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_block_sequence_number,
            {   "OPRA Block Sequence Number", "opra.block_sequence_number",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_messages_in_block,
            {   "OPRA Messages in Block", "opra.messages_in_block",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_block_timestamp,
            {   "OPRA Block Timestamp", "opra.block_timestamp",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_block_checksum,
            {   "OPRA Block Checksum", "opra.block_checksum",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_block_pad_byte,
            {   "OPRA Block Pad Byte", "opra.block_pad_byte",
                FT_UINT16, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        /*Message Header*/
        {   &hf_opra_msg_hdr_participant_id,
            {   "Participant ID", "opra.msg_hdr.participant_id",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_participant_ids), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_hdr_message_category,
            {   "Message Category", "opra.msg_hdr.message_category",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_message_categories), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_hdr_message_type,
            {   "Message Type", "opra.msg_hdr.message_type",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_hdr_message_indicator,
            {   "Message Indicator", "opra.msg_hdr.message_indicator",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_hdr_transaction_id,
            {   "Transaction ID", "opra.msg_hdr.transaction_id",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_hdr_participant_reference_number,
            {   "Reference Number", "opra.msg_hdr.reference_number",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },






        /*administrative*/
        {
            &hf_opra_msg_cat_C_data_length,
            {   "Data Length", "opra.msg_cat_C.data_length",
                FT_UINT16, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            /*The combination of FT_CHAR, BASE_HEX works to display the character instead of a hex code.  Dissect using ENC_BIG_ENDIAN for consistency.*/
            &hf_opra_msg_cat_C_data,
            {   "Data", "opra.msg_cat_C.data",
                FT_CHAR, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },

        /*control message has no fields, only header info*/

        /*last sale*/
        {
            &hf_opra_msg_cat_a_security_symbol,
            {   "Security Symbol", "opra.msg_cat_a.security_symbol",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_reserved1,
            {   "Reserved", "opra.msg_cat_a.reserved1",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_expiration_block,
            {   "Expiration Block", "opra.msg_cat_a.expiration_block",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_strike_price_denominator_code,
            {   "Strike Price Denominator Code", "opra.msg_cat_a.strike_price_denominator_code",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_denominator_codes), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_strike_price,
            {   "Strike Price", "opra.msg_cat_a.strike_price",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_volume,
            {   "Volume", "opra.msg_cat_a.volume",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_premium_price_denominator_code,
            {   "Premium Price Denominator Code", "opra.msg_cat_a.premium_price_denominator_code",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_denominator_codes), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_premium_price,
            {   "Premium Price", "opra.msg_cat_a.premium_price",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_trade_identifier,
            {   "Trade Identifier", "opra.msg_cat_a.trade_identifier",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_reserved2,
            {   "Reserved", "opra.msg_cat_a.reserved2",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },

        /*open interest*/
        {
            &hf_opra_msg_cat_d_security_symbol,
            {   "Security Symbol", "opra.msg_cat_d.security_symbol",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_d_reserved,
            {   "Reserved", "opra.msg_cat_d.reserved",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_d_expiration_block,
            {   "Expiration Block", "opra.msg_cat_d.expiration_block",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_d_strike_price_denominator_code,
            {   "Strike Price Denominator Code", "opra.msg_cat_d.strike_price_denominator_code",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_denominator_codes), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_d_strike_price,
            {   "Strike Price", "opra.msg_cat_d.strike_price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_d_volume,
            {   "Volume", "opra.msg_cat_d.volume",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },







        /*Long Quote Message*/
        {
            &hf_opra_msg_cat_k_security_symbol,
            {   "Security Symbol", "opra.msg_cat_k.security_symbol",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_reserved,
            {   "Reserved", "opra.msg_cat_k.reserved",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_expiration_block,
            {   "Expiration Block", "opra.msg_cat_k.expiration_block",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_strike_price_denominator_code,
            {   "Strike Price Denominator Code", "opra.msg_cat_k.strike_price_denominator_code",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_denominator_codes), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_strike_price,
            {   "Strike Price", "opra.msg_cat_k.strike_price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_premium_price_denominator_code,
            {   "Premium Price Denominator Code", "opra.msg_cat_k.premium_price_denominator_code",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_denominator_codes), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_bid_price,
            {   "Bid Price", "opra.msg_cat_k.bid_price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_bid_size,
            {   "Bid Size", "opra.msg_cat_k.bid_size",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_offer_price,
            {   "Offer Price", "opra.msg_cat_k.offer_price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_k_offer_size,
            {   "Offer Size", "opra.msg_cat_q.offer_size",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },

        /*Short Quote Message*/
        {
            &hf_opra_msg_cat_q_security_symbol,
            {   "Security Symbol", "opra.msg_cat_q.security_symbol",
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_q_expiration_block,
            {   "Expiration Block", "opra.msg_cat_q.expiration_block",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_q_strike_price,
            {   "Strike Price", "opra.msg_cat_q.strike_price",
                FT_UINT16, BASE_CUSTOM,
                &DisplayShortQuoteStrikePrice, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_q_bid_price,
            {   "Bid Price", "opra.msg_cat_q.bid_price",
                FT_UINT16, BASE_CUSTOM,
                &DisplayShortQuotePrice, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_q_bid_size,
            {   "Bid Size", "opra.msg_cat_q.bid_size",
                FT_UINT16, BASE_CUSTOM,
                &DisplayShortQuoteSize, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_q_offer_price,
            {   "Offer Price", "opra.msg_cat_q.offer_price",
                FT_UINT16, BASE_CUSTOM,
                &DisplayShortQuotePrice, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_q_offer_size,
            {   "Offer Size", "opra.msg_cat_q.offer_size",
                FT_UINT16, BASE_CUSTOM,
                &DisplayShortQuoteSize, 0x0,
                NULL, HFILL }
        },
        /*Quote Appendages*/
        {
            &hf_opra_msg_bid_appendage_participant_id,
            {   "Bid Appendage Participant ID", "opra.msg_bid_appendage.participant_id",
                FT_CHAR, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_bid_appendage_denominator_code,
            {   "Bid Appendage Denominator Code", "opra.msg_bid_appendage.denominator_code",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_denominator_codes), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_bid_appendage_price,
            {   "Bid Appendage Price", "opra.msg_bid_appendage.price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_bid_appendage_size,
            {   "Bid Appendage Size", "opra.msg_bid_appendage.size",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_offer_appendage_participant_id,
            {   "Offer Appendage Participant Id", "opra.msg_offer_appendage.participant_id",
                FT_CHAR, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_offer_appendage_denominator_code,
            {   "Offer Appendage Denominator Code", "opra.msg_offer_appendage.denominator_code",
                FT_CHAR, BASE_HEX,
                VALS(hf_opra_denominator_codes), 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_offer_appendage_price,
            {   "Offer Appendage Price", "opra.msg_offer_appendage.price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_offer_appendage_size,
            {   "Offer Appendage Size", "opra.msg_offer_appendage.size",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
    };

    /*protocol subtree array*/
    static int *ett[] = {
        &ett_opra,
        &ett_opra_message_header
    };

    proto_opra = proto_register_protocol("OPRA protocol", "OPRA", "opra");
    proto_register_field_array(proto_opra, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_opra = expert_register_protocol(proto_opra);
    expert_register_field_array(expert_opra, ei, array_length(ei));
}

void proto_reg_handoff_opra(void)
{
    static dissector_handle_t opra_handle;
    static range_t range = {1, {{OPRA_UDP_PORT_MIN, OPRA_UDP_PORT_MAX}}};

    opra_handle = create_dissector_handle(dissect_opra, proto_opra);
    dissector_add_uint_range("udp.port", &range, opra_handle);
}

static int dissect_opra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    /*set protocol column*/
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OPRA");

    /*clear info column*/
    col_clear(pinfo->cinfo, COL_INFO);

    /*0, -1 means we consume all the remaining tvb*/
    proto_item *ti = proto_tree_add_item(tree, proto_opra, tvb, 0, -1, ENC_NA);

    /*add the opra protocol tree*/
    proto_tree *opra_tree = proto_item_add_subtree(ti, ett_opra);

    /*first item in the tree is the version number*/
    int offset = 0;
    int len = 1;
    proto_tree_add_item(opra_tree, hf_opra_version, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*block size*/
    len = 2;
    proto_tree_add_item(opra_tree, hf_opra_block_size, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*data feed indicator*/
    len = 1;
    proto_tree_add_item(opra_tree, hf_opra_data_feed_indicator, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*retransmission indicator*/
    len = 1;
    proto_tree_add_item(opra_tree, hf_opra_retransmission_indicator, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*session indicator*/
    /*either contains an ASCII character or 0x00, treat as hex number*/
    len = 1;
    proto_tree_add_item(opra_tree, hf_opra_session_indicator, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*block sequence number*/
    len = 4;
    proto_tree_add_item(opra_tree, hf_opra_block_sequence_number, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*messages in block*/
    len = 1;

    /*function returns a uint32_t, though our field is actually 1 byte*/
    uint32_t message_count;
    proto_tree_add_item_ret_uint(opra_tree, hf_opra_messages_in_block, tvb, offset, len, ENC_BIG_ENDIAN, &message_count);
    offset += len;

    /*block timestamp*/
    len = 8;
    nstime_t timestamp;
    int endoff, err;
    proto_tree_add_time_item(opra_tree, hf_opra_block_timestamp, tvb, offset, len, ENC_TIME_SECS_NSECS, &timestamp, &endoff, &err);
    offset += len;

    /*block checksum*/
    len = 2;
    ti = proto_tree_add_item(opra_tree, hf_opra_block_checksum, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*now process the messages, one by one*/
    for (uint32_t i = 0; i < message_count; i++)
    {
        proto_tree *message_tree = proto_tree_add_subtree(opra_tree, tvb, offset, OPRA_MESSAGE_HEADER_SIZE, ett_opra_message_header, NULL, "Message Header");

        len = 1;
        uint32_t participant_id;
        proto_tree_add_item_ret_uint(message_tree, hf_opra_msg_hdr_participant_id, tvb, offset, len, ENC_BIG_ENDIAN, &participant_id);
        offset += len;

        len = 1;
        /*message category is a uint8_t containing a single char, per the spec*/
        uint32_t message_category;
        proto_tree_add_item_ret_uint(message_tree, hf_opra_msg_hdr_message_category, tvb, offset, len, ENC_BIG_ENDIAN, &message_category);
        offset += len;

        len = 1;
        //proto_tree_add_item(message_tree, hf_opra_msg_hdr_message_type, tvb, offset, len, ENC_BIG_ENDIAN);
        uint8_t message_type = tvb_get_uint8(tvb, offset);
        const char *description = GetMessageTypeDescription(message_category, message_type);
        proto_tree_add_string_format_value(message_tree, hf_opra_msg_hdr_message_type, tvb, offset, 1, description,
            "(%c), (%c), %s", message_category, message_type, description);
        offset += len;

        len = 1;
        uint32_t message_indicator = tvb_get_uint8(tvb, offset);
        if ((message_category == 'q') || (message_category == 'k')){
            const char *str = val_to_str(message_indicator, hf_opra_message_indicators, "unknown indicator");
            proto_tree_add_string(message_tree, hf_opra_msg_hdr_message_indicator, tvb, offset, len, str);
        } else {
            if (message_indicator == ' ') {
                proto_tree_add_string(message_tree, hf_opra_msg_hdr_message_indicator, tvb, offset, len, "N/A");
            } else {
                proto_tree_add_string(message_tree, hf_opra_msg_hdr_message_indicator, tvb, offset, len, "invalid");
            }
        }
        offset += len;

        len = 4;
        proto_tree_add_item(message_tree, hf_opra_msg_hdr_transaction_id, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;

        len = 4;
        proto_tree_add_item(message_tree, hf_opra_msg_hdr_participant_reference_number, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;

        switch(message_category)
        {
            case 'C':{
                offset = dissect_opra_message_category_C(tvb, offset, pinfo, message_tree, data);
                break;
            }
            case 'H':{
                /*nothing further to do*/
                break;
            }
            case 'a':{
                offset = dissect_opra_message_category_a(tvb, offset, pinfo, message_tree, data);
                break;
            }
            case 'd':{
                offset = dissect_opra_message_category_d(tvb, offset, pinfo, message_tree, data);
                break;
            }
            case 'k':{
                offset = dissect_opra_message_category_k(tvb, offset, pinfo, message_tree, data);
                offset = dissect_opra_quote_appendage(tvb, offset, pinfo, message_tree, data, message_indicator);
                break;
            }
            case 'q':{
                offset = dissect_opra_message_category_q(tvb, offset, pinfo, message_tree, data);
                offset = dissect_opra_quote_appendage(tvb, offset, pinfo, message_tree, data, message_indicator);
                break;
            }
            default:{
                /*unrecognized message category, have to skip the remainder of the block as we don't can't determine message length*/
                //return tvb_captured_length(tvb);
                return offset;
                break;
            }
        }
    }
    //if block was an odd number of bytes, there will be a block pad byte here
    if (0 != offset % 2){
        len = 1;
        proto_tree_add_item(opra_tree, hf_opra_block_pad_byte, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;
    }

    int sz = tvb_reported_length(tvb);
    if (0 != (sz - offset)){
        expert_add_info(pinfo, ti, &hf_opra_exp_block_length_error);
    }

    //return tvb_captured_length(tvb);
    return offset;
}

static int dissect_opra_message_category_C(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int len = 2;
    uint32_t data_length;
    proto_tree_add_item_ret_uint(tree, hf_opra_msg_cat_C_data_length, tvb, offset, len, ENC_BIG_ENDIAN, &data_length);
    offset += len;

    if (0 < data_length){
        len = (int) data_length;
        proto_tree_add_item(tree, hf_opra_msg_cat_C_data_length, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;
    }

    /*return the new offset*/
    return offset;
}


static int dissect_opra_message_category_a(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int len = 5;
    proto_tree_add_item(tree, hf_opra_msg_cat_a_security_symbol, tvb, offset, len, ENC_NA | ENC_ASCII);
    offset += len;

    len = 1;
    proto_tree_add_item(tree, hf_opra_msg_cat_a_reserved1, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 3;
    proto_tree_add_item(tree, hf_opra_msg_cat_a_expiration_block, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 1;
    uint32_t denominator;
    proto_tree_add_item_ret_uint(tree, hf_opra_msg_cat_a_strike_price_denominator_code, tvb, offset, len, ENC_BIG_ENDIAN, &denominator);
    offset += len;

    len = 4;
    uint32_t price = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);

    static char tmp_buffer[ITEM_LABEL_LENGTH];
    DisplayPrice(tmp_buffer, price, denominator);
    proto_tree_add_string(tree, hf_opra_msg_cat_a_strike_price, tvb, offset, len, tmp_buffer);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_a_volume, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 1;
    proto_tree_add_item_ret_uint(tree, hf_opra_msg_cat_a_premium_price_denominator_code, tvb, offset, len, ENC_BIG_ENDIAN, &denominator);
    offset += len;

    len = 4;
    price = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    DisplayPrice(tmp_buffer, price, denominator);
    proto_tree_add_string(tree, hf_opra_msg_cat_a_premium_price, tvb, offset, len, tmp_buffer);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_a_trade_identifier, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 1;
    proto_tree_add_item(tree, hf_opra_msg_cat_a_reserved2, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*return the new offset*/
    return offset;
}

static int dissect_opra_message_category_d(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int len = 5;
    proto_tree_add_item(tree, hf_opra_msg_cat_d_security_symbol, tvb, offset, len, ENC_NA | ENC_ASCII);
    offset += len;

    len = 1;
    proto_tree_add_item(tree, hf_opra_msg_cat_d_reserved, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 3;
    proto_tree_add_item(tree, hf_opra_msg_cat_d_expiration_block, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 1;
    proto_tree_add_item(tree, hf_opra_msg_cat_d_strike_price_denominator_code, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_d_strike_price, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_d_volume, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*return the new offset*/
    return offset;
}

static int dissect_opra_message_category_k(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int len = 5;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_security_symbol, tvb, offset, len, ENC_NA | ENC_ASCII);
    offset += len;

    len = 1;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_reserved, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 3;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_expiration_block, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 1;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_strike_price_denominator_code, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_strike_price, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 1;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_premium_price_denominator_code, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_bid_price, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_bid_size, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_offer_price, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_k_offer_size, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*return the new offset*/
    return offset;
}

static int dissect_opra_message_category_q(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
    int len = 4;
    proto_tree_add_item(tree, hf_opra_msg_cat_q_security_symbol, tvb, offset, len, ENC_NA | ENC_ASCII);
    offset += len;

    len = 3;
    proto_tree_add_item(tree, hf_opra_msg_cat_q_expiration_block, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 2;
    proto_tree_add_item(tree, hf_opra_msg_cat_q_strike_price, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 2;
    proto_tree_add_item(tree, hf_opra_msg_cat_q_bid_price, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 2;
    proto_tree_add_item(tree, hf_opra_msg_cat_q_bid_size, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 2;
    proto_tree_add_item(tree, hf_opra_msg_cat_q_offer_price, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    len = 2;
    proto_tree_add_item(tree, hf_opra_msg_cat_q_offer_size, tvb, offset, len, ENC_BIG_ENDIAN);
    offset += len;

    /*return the new offset*/
    return offset;
}

static int dissect_opra_quote_appendage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_, uint32_t message_indicator)
{
    /*check for bid and offer appendages*/
    bool bid_appendage = false;
    if (NULL != strchr(hf_opra_msg_indicator_best_bid_appendages, message_indicator))
        bid_appendage = true;

    bool offer_appendage = false;
    if (NULL != strchr(hf_opra_msg_indicator_best_offer_appendages, message_indicator))
        offer_appendage = true;

    if (bid_appendage){
        int len  = 1;
        proto_tree_add_item(tree, hf_opra_msg_bid_appendage_participant_id, tvb, offset, len, ENC_NA | ENC_ASCII);
        offset += len;

        len  = 1;
        proto_tree_add_item(tree, hf_opra_msg_bid_appendage_denominator_code, tvb, offset, len, ENC_NA | ENC_ASCII);
        offset += len;

        len  = 4;
        proto_tree_add_item(tree, hf_opra_msg_bid_appendage_price, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;

        len  = 4;
        proto_tree_add_item(tree, hf_opra_msg_bid_appendage_size, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;
    }

    if (offer_appendage){
        int len  = 1;
        proto_tree_add_item(tree, hf_opra_msg_offer_appendage_participant_id, tvb, offset, len, ENC_NA | ENC_ASCII);
        offset += len;

        len  = 1;
        proto_tree_add_item(tree, hf_opra_msg_offer_appendage_denominator_code, tvb, offset, len, ENC_NA | ENC_ASCII);
        offset += len;

        len  = 4;
        proto_tree_add_item(tree, hf_opra_msg_offer_appendage_price, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;

        len  = 4;
        proto_tree_add_item(tree, hf_opra_msg_offer_appendage_size, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;
    }

    /*return the new offset*/
    return offset;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
