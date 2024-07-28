/* packet-gryphon.c
 *
 * Updated routines for Gryphon protocol packet dissection
 * By Mark C. <markc@dgtech.com>
 * Copyright (C) 2018 DG Technologies, Inc. (Dearborn Group, Inc.) USA
 *
 * Routines for OPRA protocol packet disassembly
 * By J. Bomer based on the gryphon decoder
 * By Steve Limkemann <stevelim@dgtech.com>
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

#include "packet-opra.h"

void proto_register_opra(void);
void proto_reg_handoff_opra(void);

static int dissect_opra(tvbuff_t *, packet_info *, proto_tree *, void*);
static int dissect_opra_message_category_q(tvbuff_t *, int, packet_info *, proto_tree *, void*);
static int dissect_opra_message_category_k(tvbuff_t *, int, packet_info *, proto_tree *, void*);
static int dissect_opra_quote_appendage(tvbuff_t *, int, packet_info *, proto_tree *, void*, uint32_t);

/*port ranges for OPRA UDP dissemination*/
#define OPRA_UDP_PORT_MIN 45030
#define OPRA_UDP_PORT_MAX 45040

/*block header size and message header size are fixed. Message sizes vary.*/
#define OPRA_BLOCK_HEADER_SIZE 21
#define OPRA_MESSAGE_HEADER_SIZE 12

static int proto_opra;
static int ett_opra;
static int ett_opra_message_header;

/*block header fields*/
static int hf_opra_version;
static int hf_opra_block_size;
static int hf_opra_data_feed_indicator;
static int hf_opra_retransmission_indicator;
static int hf_opra_session_indicator;
static int hf_opra_block_sequence_number;
static int hf_opra_messages_in_block;
static int hf_opra_block_timestamp;
static int hf_opra_block_checksum;

/*message header fields*/
static int hf_opra_msg_hdr_participant_id;
static int hf_opra_msg_hdr_message_category;
static int hf_opra_msg_hdr_message_type;
static int hf_opra_msg_hdr_message_indicator;
static int hf_opra_msg_hdr_transaction_id;
static int hf_opra_msg_hdr_participant_reference_number;

/*fields for specific message types*/
/*short quote*/
static int hf_opra_msg_cat_q_security_symbol;
static int hf_opra_msg_cat_q_expiration_block;
static int hf_opra_msg_cat_q_strike_price;
static int hf_opra_msg_cat_q_bid_price;
static int hf_opra_msg_cat_q_bid_size;
static int hf_opra_msg_cat_q_offer_price;
static int hf_opra_msg_cat_q_offer_size;

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

/*fields for bid / offer appendages*/
static int hf_opra_msg_bid_appendage_participant_id;
static int hf_opra_msg_bid_appendage_denominator_code;
static int hf_opra_msg_bid_appendage_price;
static int hf_opra_msg_bid_appendage_size;

static int hf_opra_msg_offer_appendage_participant_id;
static int hf_opra_msg_offer_appendage_denominator_code;
static int hf_opra_msg_offer_appendage_price;
static int hf_opra_msg_offer_appendage_size;

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

/*friendly display names for enum or char fields*/
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

/*categories with their descriptions*/
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

/*for each message category, there is a list of message types with associated descriptions*/
/*short quote*/
static const value_string hf_opra_msg_cat_q_types[] = {
    {' ', "Regular Trading"},
    {'F', "Non-Firm Quote"},
    {'I', "Indicative Value"},
    {'R', "Rotation"},
    {'T', "Trading Halted"},
    {'A', "Eligible for Automatic Execution"},
    {'B', "Bid Contains Customer Trading Interest"},
    {'O', "Offer Contains Customer Trading Interest"},
    {'C', "Both Bid and Offer Contain Customer Trading Interest"},
    {'X', "Offer Side of Quote Not Firm; Bid Side Firm"},
    {'Y', "Bid Side of Quote Not Firm; Offer Side Firm"},
    { 0, NULL}
};

/*long quote, currently same as short quote*/
static const value_string hf_opra_msg_cat_k_types[] = {
    {' ', "Regular Trading"},
    {'F', "Non-Firm Quote"},
    {'I', "Indicative Value"},
    {'R', "Rotation"},
    {'T', "Trading Halted"},
    {'A', "Eligible for Automatic Execution"},
    {'B', "Bid Contains Customer Trading Interest"},
    {'O', "Offer Contains Customer Trading Interest"},
    {'C', "Both Bid and Offer Contain Customer Trading Interest"},
    {'X', "Offer Side of Quote Not Firm; Bid Side Firm"},
    {'Y', "Bid Side of Quote Not Firm; Offer Side Firm"},
    { 0, NULL}
};

/*last sale*/
static const value_string hf_opra_msg_cat_a_types[] = {
    {'A', "CANC"},
    {'B', "OSEQ"},
    {'C', "CNCL"},
    {'D', "LATE"},
    {'E', "CNCO"},
    {'F', "OPEN"},
    {'G', "CNOL"},
    {'H', "OPNL"},
    {'I', "AUTO"},
    {'J', "REOP"},
    {'S', "ISOI"},
    {'a', "SLAN"},
    {'b', "SLAI"},
    {'c', "SLCN"},
    {'d', "SLCI"},
    {'e', "SLFT"},
    {'f', "MLET"},
    {'g', "MLAT"},
    {'h', "MLCT"},
    {'i', "MLFT"},
    {'j', "MESL"},
    {'k', "TLAT"},
    {'l', "MASL"},
    {'m', "MFSL"},
    {'n', "TLET"},
    {'o', "TLCT"},
    {'p', "TLFT"},
    {'q', "TESL"},
    {'r', "TASL"},
    {'s', "TFSL"},
    {'t', "CBMO"},
    {'u', "MCTP"},
    {'v', "EXHT"},
    { 0, NULL}
};

/*Quote appendage Message Indicator values*/
static const char *hf_opra_msg_indicator_best_offer_appendages _U_ = "CGKO";
static const char *hf_opra_msg_indicator_best_bid_appendages _U_ = "MNPO";

/*map of category to permitted message types*/
typedef struct _hf_opra_msg_cat_to_types_detail {
    char category;
    const value_string *message_types;
} hf_opra_msg_cat_to_types_detail;

static const hf_opra_msg_cat_to_types_detail hf_opra_msg_cat_to_types[] = {
    {.category = 'k', .message_types = hf_opra_msg_cat_k_types},
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

static const char* GetMessageTypeDescription(uint32_t message_category, uint8_t message_type)
{
    /*get the map detail for this category*/
    const hf_opra_msg_cat_to_types_detail *pMessageTypes = FindTypesForCategory(message_category);
    if (NULL == pMessageTypes)
        return NULL;

    /*look at each types entry until we find one that matches our type, or return "not found"*/
    return val_to_str(message_type, pMessageTypes->message_types, "not found");
}

/*fixed point denominator codes used by the spec*/
typedef enum _denom_code {
    _1dps = 'A',
    _2dps = 'B',
    _3dps = 'C',
    _4dps = 'D',
    _5dps = 'E',
    _6dps = 'F',
    _7dps = 'G',
    _8dps = 'H',
    _0dps = 'I',
} denom_code;

static const denom_code denom_code_1dps _U_ = _1dps;
static const denom_code denom_code_2dps _U_ = _2dps;
static const denom_code denom_code_3dps _U_ = _3dps;
static const denom_code denom_code_4dps _U_ = _4dps;
static const denom_code denom_code_5dps _U_ = _5dps;
static const denom_code denom_code_6dps _U_ = _6dps;
static const denom_code denom_code_7dps _U_ = _7dps;
static const denom_code denom_code_8dps _U_ = _8dps;
static const denom_code denom_code_0dps _U_ = _0dps;

/*Price formatting utility functions*/
static void DisplayPrice(char *pBuff, uint32_t value, denom_code code)
{
    if (NULL == pBuff)
        return;

    /*make use of the ascending ascii values for denom code, 0dps is the exception*/
    uint32_t divisor;
    if (denom_code_0dps == code) {divisor = 1;}
        else {divisor = pow(10, ((uint8_t) (code - denom_code_1dps) + 1));}

    const char *fmt = "%d.%d (%d)";
    const uint32_t whole_part = value / divisor;
    const uint32_t fraction_part = value % divisor;

    int size = snprintf(pBuff, ITEM_LABEL_LENGTH, fmt, whole_part, fraction_part, value);

    if (size > ITEM_LABEL_LENGTH) {snprintf(pBuff, ITEM_LABEL_LENGTH, "xxxx");}

    return;
}

static void DisplayShortQuoteStrikePrice(char *pBuff, uint32_t value)
{
    /*per spec is implied 1 decimal place*/
    return DisplayPrice(pBuff, value, denom_code_1dps);
}

static void DisplayShortQuotePrice(char *pBuff, uint32_t value)
{
    /*per spec is implied 2 decimal places*/
    return DisplayPrice(pBuff, value, denom_code_2dps);
}

static void DisplayShortQuoteSize(char * pBuff, uint32_t value)
{
    /*per spec is implied whole number*/
    return DisplayPrice(pBuff, value, denom_code_0dps);
}

/*registration*/
void proto_register_opra(void)
{
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
            /*The combination of FT_CHAR, BASE_HEX works to display the 'A' instead of a hex code.  Dissect using ENC_BIG_ENDIAN for consistency.*/
            &hf_opra_msg_hdr_message_type,
            {   "Message Type", "opra.msg_hdr.message_type",
                /*FT_CHAR, BASE_HEX,*/
                FT_STRING, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_hdr_message_indicator,
            {   "Message Indicator", "opra.msg_hdr.message_indicator",
                FT_UINT8, BASE_HEX,
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
                NULL, 0x0,
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
                NULL, 0x0,
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
                NULL, 0x0,
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
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_offer_appendage_price,
            {   "Offer Appendage Price", "opra.msg_offer_appendage.price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
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
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_strike_price,
            {   "Strike Price", "opra.msg_cat_a.strike_price",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_volume,
            {   "Strike Price", "opra.msg_cat_a.volume",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_premium_price_denominator_code,
            {   "Premium Price Denominator Code", "opra.msg_cat_a.premium_price_denominator_code",
                FT_CHAR, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        {
            &hf_opra_msg_cat_a_premium_price,
            {   "Bid Price", "opra.msg_cat_a.premium_price",
                FT_UINT32, BASE_DEC,
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
    };


    /*protocol subtree array*/
    static int *ett[] = {
        &ett_opra,
        &ett_opra_message_header
    };

    proto_opra = proto_register_protocol("OPRA protocol", "OPRA", "opra");
    proto_register_field_array(proto_opra, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static int
dissect_opra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
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
    proto_tree_add_item(opra_tree, hf_opra_block_checksum, tvb, offset, len, ENC_BIG_ENDIAN);
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
        const char *pDescription = GetMessageTypeDescription(message_category, message_type);
        proto_tree_add_string_format_value(message_tree, hf_opra_msg_hdr_message_type, tvb, offset, 1, pDescription,
            "(%c), (%c), %s", message_category, message_type, pDescription);
        offset += len;

        len = 1;
        uint32_t message_indicator;
        proto_tree_add_item_ret_uint(message_tree, hf_opra_msg_hdr_message_indicator, tvb, offset, len, ENC_BIG_ENDIAN, &message_indicator);
        offset += len;

        len = 4;
        proto_tree_add_item(message_tree, hf_opra_msg_hdr_transaction_id, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;

        len = 4;
        proto_tree_add_item(message_tree, hf_opra_msg_hdr_participant_reference_number, tvb, offset, len, ENC_BIG_ENDIAN);
        offset += len;

        switch(message_category)
        {
            case 'q':{
                offset = dissect_opra_message_category_q(tvb, offset, pinfo, message_tree, data);
                offset = dissect_opra_quote_appendage(tvb, offset, pinfo, message_tree, data, message_indicator);
                break;
            }
            case 'k':{
                offset = dissect_opra_message_category_k(tvb, offset, pinfo, message_tree, data);
                offset = dissect_opra_quote_appendage(tvb, offset, pinfo, message_tree, data, message_indicator);
                break;
            }
            default:{
                /*unrecognized message category, have to skip the remainder of the block as we don't know the length of the message so can't recover*/
                return tvb_captured_length(tvb);
                break;
            }
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_opra_message_category_q(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
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

static int
dissect_opra_message_category_k(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
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

static int
dissect_opra_quote_appendage(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_, uint32_t message_indicator)
{
    /*check for bid and offer appendages*/
    bool bid_appendage = false;
    if (NULL != strchr(hf_opra_msg_indicator_best_bid_appendages, message_indicator))
        bid_appendage = true;

    bool offer_appendage = false;
    if (NULL != strchr(hf_opra_msg_indicator_best_offer_appendages, message_indicator))
        offer_appendage = true;

    /*might have either, both or none. If none, exit without modifying the offset.*/
    if (!bid_appendage && !offer_appendage)
        return offset;

    int len;
    if (bid_appendage){
        len  = 1;
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
        len  = 1;
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

void
proto_reg_handoff_opra(void)
{
    static dissector_handle_t opra_handle;
    static range_t range = {1, {{OPRA_UDP_PORT_MIN, OPRA_UDP_PORT_MAX}}};

    opra_handle = create_dissector_handle(dissect_opra, proto_opra);
    dissector_add_uint_range("udp.port", &range, opra_handle);
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
