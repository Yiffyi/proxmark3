#include "fmcos.h"
#include "iso14443a.h"

#include "string.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "protocols.h"
#include "dbprint.h"
#include "mifareutil.h"
#include "ticks.h"
#include "commonutil.h"

// Increased the buffer size to allow for more complex responses
// #define DYNAMIC_RESPONSE_BUFFER2_SIZE 512
// #define DYNAMIC_MODULATION_BUFFER2_SIZE 1536
// #define DYNAMIC_RESPONSE_BUFFER_SIZE 64
// #define DYNAMIC_MODULATION_BUFFER_SIZE 512

#define STATE_IDLE      0
#define STATE_READY     1
#define STATE_ACTIVE    2
#define STATE_ISO14443A 3

static uint16_t curDF = 0x3F00;
static uint16_t curEF = 0x0000;
static fmcos_ef *curFile = NULL;

static bool ef_checksum(const fmcos_ef* ef)
{
    uint16_t t = ef->checkSum;
    t ^= ef->iDF;
    t ^= ef->iEF;
    t ^= ef->szData;
    return t == 0;
}

void FMCOSEmlMemAdd(fmcos_ef *ef)
{
    if (!ef_checksum(ef)) {
        Dbprintf("ERROR: invalid checksum for incoming EF, iDF=%04X, iEF=%04X, szData=%d", ef->iDF, ef->iEF, ef->szData);
        reply_ng(CMD_HF_ISO14443A_FMCOS_EML_ADD, PM3_ESOFT, NULL, 0);
        return;
    }

    uint32_t offset = 0;
    uint8_t *mem = BigBuf_get_EM_addr();
    for (uint8_t i = 0; i < 250; i++) {
        fmcos_ef *t = (fmcos_ef*)(mem + offset);
        if (t->iDF != 0 && ef_checksum(t)) {
            offset += sizeof(fmcos_ef) + t->szData;
        } else {
            emlSet((uint8_t*)ef, offset, sizeof(fmcos_ef) + ef->szData);
            Dbprintf("SUCCESS: Placed %d bytes EF %04X/%04X to eml mem, offset=%d", sizeof(fmcos_ef) + ef->szData, ef->iDF, ef->iEF, offset);
            reply_ng(CMD_HF_ISO14443A_FMCOS_EML_ADD, PM3_SUCCESS, NULL, 0);
            return;
        }
    }

    Dbprintf("ERROR: too many items in eml mem");
    reply_ng(CMD_HF_ISO14443A_FMCOS_EML_ADD, PM3_ESOFT, NULL, 0);
    return;
}

fmcos_ef* FMCOSEmlGetFile(uint16_t iDF, uint16_t iEF)
{
    uint32_t offset = 0;
    uint8_t *mem = BigBuf_get_EM_addr();
    for (uint8_t i = 0; i < 250; i++) {
        fmcos_ef *t = (fmcos_ef*)(mem + offset);
        if (t->iDF != 0 && ef_checksum(t)) {
            if (t->iDF == iDF && t->iEF == iEF) {
                Dbprintf("SUCCESS: Retrieved %d bytes EF %04X/%04X from eml mem, offset=%d", t->szData, t->iDF, t->iEF, offset);
                return t;
            } else {
                offset += sizeof(fmcos_ef) + t->szData;
            }
        } else { // reached end of mem
            break;
        }
    }
    Dbprintf("ERROR: could not found EF %04X/%04X in eml mem", iDF, iEF);
    return NULL;
}

fmcos_ef* FMCOSEmlGetDFByName(uint8_t *name, uint8_t szName)
{
    uint32_t offset = 0;
    uint8_t *mem = BigBuf_get_EM_addr();
    for (uint8_t i = 0; i < 250; i++) {
        fmcos_ef *t = (fmcos_ef*)(mem + offset);
        if (t->iDF != 0 && ef_checksum(t)) {
            if (t->iEF == 0xFFFF && szName == t->szData && memcmp(name, t->bData, szName) == 0) {
                Dbprintf("SUCCESS: Found DF %04X from eml mem", t->iDF);
                return t;
            } else {
                offset += sizeof(fmcos_ef) + t->szData;
            }
        } else { // reached end of mem
            break;
        }
    }
    Dbprintf("ERROR: could not found requested DF in eml mem");
    return NULL;
}

void FMCOSEmlList(void)
{
    uint32_t offset = 0;
    uint8_t *mem = BigBuf_get_EM_addr();
    for (uint8_t i = 0; i < 250; i++) {
        fmcos_ef *t = (fmcos_ef*)(mem + offset);
        if (t->iDF != 0 && ef_checksum(t)) {
            Dbprintf("At offset=%d: EF %04X/%04X has %d bytes of data", offset, t->iDF, t->iEF, t->szData);
            offset += sizeof(fmcos_ef) + t->szData;
        } else { // reached end of mem
            Dbprintf("At offset=%d: invalid entry, iDF=%04X,iEF=%04X,szData=%d", offset, t->iDF, t->iEF, t->szData);
            break;
        }
    }
    return;
}


void GenerateFMCOSResponse(uint8_t *receivedCmd, int receivedCmdLen, fmcos_resp *resp)
{

    uint8_t sw1 = 0x90, sw2 = 0x00;
    switch (receivedCmd[3])
    { // APDU Class Byte
      // receivedCmd in this case is expecting to structured with a CID, then the APDU command for SelectFile
      // | IBlock (CID) | CID | APDU Command | CRC |

    case 0xA4:
    { // SELECT FILE
        // Select File AID uses the following format for GlobalPlatform
        //
        // | 00 | A4 | 04/00 | 00 | xx | AID | 00 |
        // xx in this case is len of the AID value in hex

        // aid len is found as a hex value in receivedCmd[6] (Index Starts at 0)
        int aidLen = receivedCmd[6];
        uint8_t *receivedAid = &receivedCmd[7];

        // Dbprintf("Received AID (%d):", aidLen);
        // Dbhexdump(aidLen, receivedAid, false);

        if (receivedCmd[4] == 0x00 && receivedCmd[5] == 0x00) // select by iDF or iEF
        {
            // if (aidLen == 2) {
            // }
            uint16_t wanted = (((uint16_t)receivedAid[0]) << 8) | receivedAid[1];
            // check EF under curDF
            fmcos_ef *file = FMCOSEmlGetFile(curDF, wanted);
            if (file) {
                // memcpy(resp->data + headerOffset, file->bData, file->szData);
                // resp->len = file->szData + headerOffset;
                sw1 = 0x90;
                sw2 = 0x00;
                curEF = file->iEF;
                curFile = file;
                goto addSW;
            }

            // check DF
            file = FMCOSEmlGetFile(wanted, 0x0000);
            if (file) {
                memcpy(resp->data + resp->len, file->bData, file->szData);
                resp->len += file->szData;
                curDF = file->iDF;
                curEF = 0x0000;
                curFile = NULL;
                goto ret;
            }
        }
        else if (receivedCmd[4] == 0x04 && receivedCmd[5] == 0x00)
        {
            // try to match name
            fmcos_ef *file = FMCOSEmlGetDFByName(receivedAid, aidLen);
            if (file) {
                memcpy(resp->data + resp->len, file->bData, file->szData);
                resp->len += file->szData;
                curDF = file->iDF;
                curEF = 0x0000;
                curFile = NULL;
                goto ret;
            }
        } else {
            // Incorrect P1 or P2
            sw1 = 0x6A; sw2 = 0x86;
            goto addSW;
        }
        // Any other SELECT FILE command will return with a Not Found
        sw1 = 0x6A; sw2 = 0x82;
        goto addSW;
    }
    break;
    case 0xB0:
    {
        // READ BINARY
        uint8_t p1 = receivedCmd[4], p2 = receivedCmd[5];
        uint16_t iEF = 0;
        uint16_t offset = 0;
        uint8_t le = receivedCmd[6];
        fmcos_ef *file = NULL;
        if ((p1 & 0xE0) == 0x80) {
            iEF = p1 & 0x1F;
            offset = p2;
        } else {
            iEF = curEF;
            offset = (p1 << 8) | p2;
        }

        if (iEF == curEF) {
            file = curFile;
        } else {
            file = FMCOSEmlGetFile(curDF, iEF);
        }

        if (file) {
            if (offset + le > file->szData - 2) { // too long
                sw1 = 0x6B; sw2 = 0x00;
                goto addSW;
            }

            memcpy(resp->data + resp->len, file->bData + offset, le);
            sw1 = 0x90;
            sw2 = 0x00;
            resp->len += le;
            goto addSW;
        } else {
            sw1 = 0x6A;
            sw2 = 0x82;
            goto addSW;
        }
    }
    break;
    }

addSW:
    resp->data[resp->len] = sw1;
    resp->data[resp->len+1] = sw2;
    resp->len += 2;
    // Any other non-listed command
    // Respond Not Found
ret:
    return;
}

bool PrepareDynamicResponse(uint8_t *receivedCmd, int receivedCmdLen, fmcos_resp *resp)
{

    // clear old dynamic responses
    resp->len = 0;
    bool selected = true;

    // Check for ISO 14443A-4 compliant commands, look at left nibble
    switch (receivedCmd[0])
    {
    case 0x02:
    case 0x03:
    { // IBlock (command no CID)
        resp->data[0] = receivedCmd[0];
        // resp->data[1] = 0x90;
        // resp->data[2] = 0x00;
        resp->len = 1;
        GenerateFMCOSResponse(receivedCmd, receivedCmdLen, resp);
    }
    break;
    case 0x0B:
    case 0x0A:
    { // IBlock (command CID)
        resp->data[0] = receivedCmd[0];
        resp->data[1] = receivedCmd[1];
        // resp->data[2] = 0x90;
        // resp->data[3] = 0x00;
        resp->len = 2;
        GenerateFMCOSResponse(receivedCmd, receivedCmdLen, resp);
    }
    break;

    case 0x1A:
    case 0x1B:
    { // Chaining command
        resp->data[0] = 0xaa | ((receivedCmd[0]) & 1);
        resp->len = 2;
    }
    break;

    case 0xAA:
    case 0xBB:
    {
        resp->data[0] = receivedCmd[0] ^ 0x11;
        resp->len = 2;
    }
    break;

    case 0xBA:
    { // ping / pong
        resp->data[0] = 0xAB;
        resp->data[1] = 0x00;
        resp->len = 2;
    }
    break;

    case 0xCA:
    case 0xC2:
    { // Readers sends deselect command
        resp->data[0] = 0xCA;
        resp->data[1] = 0x00;
        resp->len = 2;
        selected = false;
    }
    break;

    default:
    {
        if (g_dbglevel >= DBG_DEBUG)
        {
            Dbprintf("Received unknown command (len=%d):", receivedCmdLen);
            Dbhexdump(receivedCmdLen, receivedCmd, false);
        }
        // Do not respond
        resp->len = 0;
        // order = ORDER_NONE; // back to work state
    }
    break;
    }


    if (resp->len > 0)
    {
        // Copy the CID from the reader query???
        // resp->data[1] = receivedCmd[1];

        // Add CRC bytes, always used in ISO 14443A-4 compliant cards
        AddCrc14A(resp->data, resp->len);
        resp->len += 2;

        // if (prepare_tag_modulation(resp, DYNAMIC_MODULATION_BUFFER2_SIZE) == false)
        // {
        //     if (g_dbglevel >= DBG_DEBUG)
        //         DbpString("Error preparing tag response");
        // }
    }

    return selected;
}

void SimulateFMCOSTag(uint8_t *uid, uint8_t *iRATs, size_t irats_len)
{
    tag_response_info_t *responses;
    uint32_t cuid = 0;
    uint32_t counters[3] = {0x00, 0x00, 0x00};
    uint8_t tearings[3] = {0xbd, 0xbd, 0xbd};
    uint8_t pages = 0;

    // command buffers
    int receivedCmdLen = 0;
    uint8_t receivedCmd[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = {0x00};

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    fmcos_resp dynamicResp = {
        .len = 0,
        .data = BigBuf_calloc(FMCOS_RESPONSE_BUFFER_SIZE)
    };

    uint8_t tagType = 4;
    uint16_t flags = 0;
    FLAG_SET_UID_IN_DATA(flags, 4);
    flags |= FLAG_RATS_IN_DATA;
    if (SimulateIso14443aInit(tagType, flags, uid, iRATs, irats_len, &responses, &cuid, counters, tearings, &pages) == false)
    {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_MIFARE_SIMULATE, PM3_EINIT, NULL, 0);
        return;
    }

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
    iso14a_set_timeout(201400); // 106 * 19ms default *100?

    clear_trace();
    set_tracing(true);
    LED_A_ON();

    int retval = 0;
    int cmdsRecvd = 0;
    bool finished = false;
    int state = STATE_IDLE, next_state = STATE_IDLE;


    uint32_t nonce = 0;
    // uint8_t cardAUTHSC = 0;
    // uint8_t cardAUTHKEY = 0xff;  // no authentication
    while (finished == false)
    {
        // BUTTON_PRESS check done in GetIso14443aCommandFromReader
        WDT_HIT();
        tag_response_info_t *p_response = NULL;
        dynamicResp.len = 0;

        // Clean receive command buffer
        if (GetIso14443aCommandFromReader(receivedCmd, sizeof(receivedCmd), receivedCmdPar, &receivedCmdLen) == false)
        {
            Dbprintf("Emulator stopped. Trace length: %d ", BigBuf_get_traceLen());
            retval = PM3_EOPABORTED;
            break;
        }

        // looks like its automatically logged
        // tUart14a *Uart = GetUart14a();
        // LogTrace(receivedCmd, Uart->len, Uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, Uart->parity, true);

        switch (state)
        {
        case STATE_IDLE:
            if (receivedCmd[0] == ISO14443A_CMD_REQA && receivedCmdLen == 1)
            {
                p_response = &responses[RESP_INDEX_ATQA];
            }
            else if (receivedCmd[0] == ISO14443A_CMD_WUPA && receivedCmdLen == 1)
            { // Received a WAKEUP
                p_response = &responses[RESP_INDEX_ATQA];
            }

            if (p_response) {
                next_state = STATE_READY;
            } else {
                next_state = STATE_IDLE;
            }
            break;
        case STATE_READY:
            if (receivedCmd[1] == 0x20) { // ANTICOLL
                if (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmdLen == 2)
                { // Received request for UID (cascade 1)
                    p_response = &responses[RESP_INDEX_UIDC1];
                }
                else if (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmdLen == 2)
                { // Received request for UID (cascade 2)
                    p_response = &responses[RESP_INDEX_UIDC2];
                }
                else if (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && receivedCmdLen == 2)
                { // Received request for UID (cascade 3)
                    p_response = &responses[RESP_INDEX_UIDC3];
                }

                if (p_response) {
                    next_state = STATE_READY;
                } else {
                    next_state = STATE_IDLE;
                }
            } else if (receivedCmd[1] == 0x70) { // SELECT
                if (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmdLen == 9)
                { // Received a SELECT (cascade 1)
                    p_response = &responses[RESP_INDEX_SAKC1];
                }
                else if (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmdLen == 9)
                { // Received a SELECT (cascade 2)
                    p_response = &responses[RESP_INDEX_SAKC2];
                }
                else if (receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3 && receivedCmdLen == 9)
                { // Received a SELECT (cascade 3)
                    p_response = &responses[RESP_INDEX_SAKC3];
                }

                if (p_response) {
                    next_state = STATE_ACTIVE;
                } else {
                    next_state = STATE_IDLE;
                }
            } else {
                next_state = STATE_IDLE;
            }

            break;
        case STATE_ACTIVE:
            if (receivedCmd[0] == ISO14443A_CMD_HALT && receivedCmdLen == 4)
            {   // Received a HALT
                p_response = NULL;
                next_state = STATE_IDLE;
            }
            else if (receivedCmd[0] == ISO14443A_CMD_RATS && receivedCmdLen == 4)
            { // Received a RATS request
                p_response = &responses[RESP_INDEX_RATS];
                next_state = STATE_ISO14443A;
            } else {
                next_state = STATE_ACTIVE;
            }

            if ((receivedCmd[0] == MIFARE_AUTH_KEYA || receivedCmd[0] == MIFARE_AUTH_KEYB) && receivedCmdLen == 4) {    // Received an authentication request
                // cardAUTHKEY = receivedCmd[0] - 0x60;
                // cardAUTHSC = receivedCmd[1] / 4; // received block num

                // incease nonce at AUTH requests. this is time consuming.
                nonce = prng_successor(GetTickCount(), 32);
                num_to_bytes(nonce, 4, dynamicResp.data);
                dynamicResp.len = 4;

                p_response = NULL;
                // order = ORDER_AUTH;
            }
            break;
        case STATE_ISO14443A:
            next_state = STATE_ISO14443A;
            if (receivedCmd[0] == ISO14443A_CMD_PPS)
            {
                p_response = &responses[RESP_INDEX_PPS];
            }
            else
            {
                if (PrepareDynamicResponse(receivedCmd, receivedCmdLen, &dynamicResp)) {
                    next_state = STATE_ISO14443A;
                } else {
                    next_state = STATE_IDLE;
                }
                p_response = NULL;
            }
            break;
        default:
            break;
        }

        cmdsRecvd++;

        // Send response
        if (dynamicResp.len > 0) {
            EmSendCmd(dynamicResp.data, dynamicResp.len);
        } else if (p_response) {
            EmSendPrecompiledCmd(p_response);
        }

        state = next_state;
    }

    switch_off();

    set_tracing(false);
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_EXTENDED)
    {
        //        Dbprintf("-[ Wake ups after halt  [%d]", happened);
        //        Dbprintf("-[ Messages after halt  [%d]", happened2);
        Dbprintf("-[ Num of received cmd  [%d]", cmdsRecvd);
    }

    reply_ng(CMD_HF_ISO14443A_FMCOS_SIMULATE, retval, NULL, 0);
}