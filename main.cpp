#include <iostream>
#include <cstdint>
#include <cinttypes>
#include <cfloat>
#include <climits>
#include <cstddef>
#include <string>
#include <cstdio>

using namespace std;

#define NOT_VALID  -1

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86))
#include <intrin.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <x86intrin.h>
#endif

//=============================================================================================================================================================================
// Byte swap
//=============================================================================================================================================================================
#if defined(_MSC_VER)
static inline uint16_t xSwapBytes16(uint16_t Value) { return _byteswap_ushort(Value); }
static inline  int16_t xSwapBytes16( int16_t Value) { return _byteswap_ushort(Value); }
static inline uint32_t xSwapBytes32(uint32_t Value) { return _byteswap_ulong (Value); }
static inline  int32_t xSwapBytes32( int32_t Value) { return _byteswap_ulong (Value); }
static inline uint64_t xSwapBytes64(uint64_t Value) { return _byteswap_uint64(Value); }
static inline  int64_t xSwapBytes64( int64_t Value) { return _byteswap_uint64(Value); }
#elif defined (__GNUC__)
static inline uint16_t xSwapBytes16(uint16_t Value) { return __builtin_bswap16(Value); }
static inline  int16_t xSwapBytes16( int16_t Value) { return __builtin_bswap16(Value); }
static inline uint32_t xSwapBytes32(uint32_t Value) { return __builtin_bswap32(Value); }
static inline  int32_t xSwapBytes32( int32_t Value) { return __builtin_bswap32(Value); }
static inline uint64_t xSwapBytes64(uint64_t Value) { return __builtin_bswap64(Value); }
static inline  int64_t xSwapBytes64( int64_t Value) { return __builtin_bswap64(Value); }
#else
#error Unrecognized compiler
#endif

//=============================================================================================================================================================================

class xTS
{
public:
    static constexpr uint32_t TS_PacketLength = 188;
    static constexpr uint32_t TS_HeaderLength = 4;

    static constexpr uint32_t PES_HeaderLength = 6;

    static constexpr uint32_t BaseClockFrequency_Hz         =    90000; //Hz
    static constexpr uint32_t ExtendedClockFrequency_Hz     = 27000000; //Hz
    static constexpr uint32_t BaseClockFrequency_kHz        =       90; //kHz
    static constexpr uint32_t ExtendedClockFrequency_kHz    =    27000; //kHz
    static constexpr uint32_t BaseToExtendedClockMultiplier =      300;
};

//=============================================================================================================================================================================

class xTS_PacketHeader
{
public:
    enum class ePID : uint16_t
    {
        PAT  = 0x0000,
        CAT  = 0x0001,
        TSDT = 0x0002,
        IPMT = 0x0003,
        NIT  = 0x0010, //DVB specific PID
        SDT  = 0x0011, //DVB specific PID
        NuLL = 0x1FFF,
    };

protected:
    uint8_t SB;
    bool E;
    bool S;
    bool T;
    uint16_t PID;
    uint8_t TSC;
    uint8_t AF;
    uint8_t CC;

public:
    void     Reset() {SB = 0; E = 0; S = 0; T = 0; PID = 0; TSC = 0; AF = 0; CC = 0;}

    int32_t  Parse(const uint8_t* Input) {
        SB = Input [0];
        E = (Input [1] & 0b10000000);
        S = (Input [1] & 0b01000000);
        T = (Input [1] & 0b00100000);
        PID = ((((uint16_t) Input [1] & 0b00011111) << 8) | ((uint16_t) Input [2]));
        TSC = (Input [3] & 0b11000000) >> 6;
        AF = (Input [3] & 0b00110000) >> 4;
        CC = (Input [3] & 0b00001111);
        return 0;
    }

    void    Print() const {
        printf(" TS: SB=%2d E=%d S=%d P=%d PID=%4d TSC=%d AF=%d CC=%2d",
               SB, E, S, T, PID, TSC, AF, CC);
    }

public:
    uint8_t getSb() const {
        return SB;
    }

    bool getE() const {
        return E;
    }

    bool getS() const {
        return S;
    }

    bool isT() const {
        return T;
    }

    uint16_t getPid() const {
        return PID;
    }

    uint8_t getTsc() const {
        return TSC;
    }

    uint8_t getAfc() const {
        return AF;
    }

    uint8_t getCc() const {
        return CC;
    }

public:
    //TODO
    bool     hasAdaptationField() const { if (AF == 2 or AF == 3) return 1;
                                            else return 0;}
    bool     hasPayload        () const { if (AF == 1 or AF == 3) return 1;
                                            else return 0;}

};

//=============================================================================================================================================================================

class xTS_AdaptationField {

protected:
    uint8_t AFL;
    bool DC;
    bool RA;
    bool SPI;
    bool PR;
    bool OR;
    bool SPF;
    bool TP;
    bool EX;
    uint64_t program_clock_reference_base;
    uint8_t PCRreserved;
    uint16_t program_clock_reference_extension;
    uint64_t original_program_clock_reference_base;
    uint8_t OPCRreserved;
    uint16_t original_program_clock_reference_extension;
    uint8_t stuffing_byte;


public:
    void Reset () { AFL = 0; DC = 0; RA = 0; SPI = 0; PR = 0; OR = 0; SPF = 0; TP = 0; EX = 0; }

    int32_t Parse (const uint8_t* Input, uint8_t AdaptationFieldControl) {
        if (AdaptationFieldControl == 2 || AdaptationFieldControl == 3) {
            AFL = Input[4] + 1;
            stuffing_byte = AFL;
            if (AFL > 1) {
                DC = (Input[5] & 0b10000000);
                RA = (Input[5] & 0b01000000);
                SPI = (Input[5] & 0b00100000);
                PR = (Input[5] & 0b00010000);
                OR = (Input[5] & 0b00001000);
                SPF = (Input[5] & 0b00000100);
                TP = (Input[5] & 0b00000010);
                EX = (Input[5] & 0b00000001);
                stuffing_byte -= 2;
                if (PR) {
                    program_clock_reference_base = (((uint64_t) Input[6]) << 25 | ((uint64_t) Input[7]) << 17 |
                                                    ((uint64_t) Input[8]) << 9 | ((uint64_t) Input[9]) << 1 |
                                                    ((uint64_t) Input[10]) >> 7);
                    PCRreserved = Input[10] & 0b01111110;
                    program_clock_reference_extension =
                            ((uint16_t) Input[10] & 0b00000001) << 8 | ((uint16_t) Input[11]);
                    stuffing_byte -= 6;
                }
                if (OR) {
                    original_program_clock_reference_base = (((uint64_t) Input[12]) << 25 | ((uint64_t) Input[13]) << 17 |
                                                             ((uint64_t) Input[14]) << 9 | ((uint64_t) Input[15]) << 1 |
                                                             ((uint64_t) Input[16]) >> 7);
                    OPCRreserved = Input[16] & 0b01111110;
                    original_program_clock_reference_extension =
                            ((uint16_t) Input[16] & 0b00000001) << 8 | ((uint16_t) Input[17]);
                    stuffing_byte -= 6;
                }
                if (SPF) stuffing_byte -= 1;
                if (TP) stuffing_byte -= 1;
                if (EX) {
                    stuffing_byte -= 2;
                    if (Input[21] & 0b10000000) stuffing_byte -= 2;
                    if (Input[21] & 0b01000000) stuffing_byte -= 3;
                    if (Input[21] & 0b00100000) stuffing_byte -= 1;
                }
            }
        }
        else if (AdaptationFieldControl == 1) {AFL = 0;}
        return 0;
    }

    void Print () const {
        printf (" AF: AFL=%3d DC=%d RA=%d SP=%d PR=%d OR=%d SP=%d TP=%d EX=%d Stuffing=%d",
        AFL - 1, DC, RA, SPI, PR, OR, SPF, TP, EX, stuffing_byte);
    }

    uint32_t getNumBytes() const { return AFL; }
};

//=============================================================================================================================================================================
class xPES_PacketHeader {
public:
    enum eStreamId : uint8_t {
        eStreamId_program_stream_map = 0xBC,
        eStreamId_padding_stream = 0xBE,
        eStreamId_private_stream_2 = 0xBF,
        eStreamId_ECM = 0xF0,
        eStreamId_EMM = 0xF1,
        eStreamId_program_stream_directory = 0xFF,
        eStreamId_DSMCC_stream = 0xF2,
        eStreamId_ITUT_H222_1_type_E = 0xF8,
    };

protected:
    uint32_t m_PacketStartCodePrefix;
    uint8_t m_StreamId;
    uint16_t m_PacketLength;
    uint8_t PES_Scrambling_Control;
    bool PES_Priority;
    bool Data_Alignment_Indicator;
    bool Copyright;
    bool Original_Or_Copy;
    uint8_t PTS_DTS_Flags;
    bool ESCR_Flag;
    bool ES_Rate_Flag;
    bool DSM_Trick_Mode_Flag;
    bool Additional_Copy_Info_Flag;
    bool PES_CRC_Flag;
    bool PES_Extension_Flag;
    uint8_t PES_Header_Data_Length;

public:
    void Reset () {
        m_PacketStartCodePrefix = 0;
        m_StreamId = 0;
        m_PacketLength = 0;
        PES_Scrambling_Control = 0;
        PES_Priority = false;
        Data_Alignment_Indicator = false;
        Copyright = false;
        Original_Or_Copy = false;
        PTS_DTS_Flags = 0;
        ESCR_Flag = false;
        ES_Rate_Flag = false;
        DSM_Trick_Mode_Flag = false;
        Additional_Copy_Info_Flag = false;
        PES_CRC_Flag = false;
        PES_Extension_Flag = false;
        PES_Header_Data_Length = xTS::PES_HeaderLength;
    }

    int32_t Parse(const uint8_t *Input, uint8_t Shift = 0) {
        m_PacketStartCodePrefix = ((uint32_t) (Input[Shift]) << 16 | (uint32_t) (Input[Shift + 1]) << 8 |
                                   (uint32_t) (Input[Shift + 2]));
        m_StreamId = Input[Shift + 3];
        m_PacketLength = (uint16_t) Input[Shift + 4] << 8 | (uint16_t) Input[Shift + 5];
        if ((Input[Shift + 6] & 0b11000000) == 128) {
            if (m_StreamId != eStreamId::eStreamId_program_stream_map
                && m_StreamId != eStreamId::eStreamId_padding_stream
                && m_StreamId != eStreamId::eStreamId_private_stream_2
                && m_StreamId != eStreamId::eStreamId_ECM
                && m_StreamId != eStreamId::eStreamId_EMM
                && m_StreamId != eStreamId::eStreamId_program_stream_directory
                && m_StreamId != eStreamId::eStreamId_DSMCC_stream
                && m_StreamId != eStreamId::eStreamId_ITUT_H222_1_type_E) {

                PES_Scrambling_Control = (Input [Shift + 6] & 0b00110000) >> 4;
                PES_Priority = (Input[Shift + 6] & 0b0001000);
                Data_Alignment_Indicator = (Input[Shift + 6] & 0b00000100);
                Copyright = (Input[Shift + 6] & 0b00000010);
                Original_Or_Copy = (Input[Shift + 6] & 0b00000001);
                PTS_DTS_Flags = (Input[Shift + 7] & 0b11000000) >> 6;
                ESCR_Flag = (Input[Shift + 7] & 0b00100000);
                ES_Rate_Flag = (Input[Shift + 7] & 0b00010000);
                DSM_Trick_Mode_Flag = (Input[Shift + 7] & 0b00001000);
                Additional_Copy_Info_Flag = (Input[Shift + 7] & 0b00000100);
                PES_CRC_Flag = (Input[Shift + 7] & 0b00000010);
                PES_Extension_Flag = (Input[Shift + 7] & 0b00000001);
                PES_Header_Data_Length += Input[Shift + 8] + 3;
            }
            return Shift + PES_Header_Data_Length;
        }
        return Shift + xTS::PES_HeaderLength;
    }

    void Print () const {
        printf (" PES: PSCP=%1d SID=%3d L=%4d",
                m_PacketStartCodePrefix, m_StreamId, m_PacketLength);
    }

    uint32_t getMPacketStartCodePrefix() const {
        return m_PacketStartCodePrefix;
    }

    uint8_t getMStreamId() const {
        return m_StreamId;
    }

    uint16_t getMPacketLength() const {
        return m_PacketLength + xTS::PES_HeaderLength;
    }

    uint8_t getPesHeaderDataLength() const {
        return PES_Header_Data_Length;
    }

};
//=============================================================================================================================================================================

class xPES_Assembler {
public:
    enum class eResult : int32_t {
        UnexpectedPID = 1,
        StreamPacketLost,
        AssemblingStarted,
        AssemblingContinue,
        AssemblingFinished,
    };

protected:
    //setup
    int32_t m_PID;
    FILE *file2 = nullptr;
    //buffer
    uint8_t *m_Buffer = nullptr;
    uint32_t m_BufferSize;
    uint8_t m_pesOffset;
    uint32_t m_DataOffset;
    //operation
    uint8_t m_LastContinuityCounter;
    bool m_Started = false;
    xPES_PacketHeader m_PESH;

public:
    xPES_Assembler() {};

    ~xPES_Assembler() {};

    void Init(int32_t PID) {
        m_PID = PID;
        if (m_PID == 136) file2 = fopen("/home/kuba/CLionProjects/TS_parser/cmake-build-debug/PID136.mp2", "wb");
    };

    eResult AbsorbPacket(const uint8_t *TransportStreamPacket, const xTS_PacketHeader *PacketHeader,
                         const xTS_AdaptationField *AdaptationField) {
        if (PacketHeader->getPid() == m_PID) {
            if (PacketHeader->getS()) {
                if (m_Started) {
                    m_Started = false;
                    fwrite(m_Buffer, m_BufferSize, 1, file2);
                    printf(" Finished, Len=%4d ", m_BufferSize);
                }

                if (!m_Started) {
                    m_Started = true;
                    xBufferReset();
                    m_pesOffset = m_PESH.Parse(TransportStreamPacket,
                                               xTS::TS_HeaderLength + AdaptationField->getNumBytes());
                    m_BufferSize = m_PESH.getMPacketLength() - m_PESH.getPesHeaderDataLength();
                    xBufferAppend(TransportStreamPacket, m_pesOffset);
                    return eResult::AssemblingStarted;
                }
            } else {
                if (PacketHeader->hasPayload()) {
                    xBufferAppend(TransportStreamPacket, xTS::TS_HeaderLength + AdaptationField->getNumBytes());
                    m_LastContinuityCounter++;
                }

                return eResult::AssemblingContinue;
            }
        } else return eResult::UnexpectedPID;

        return eResult::AssemblingStarted;
    };

    void PrintPESH() const { m_PESH.Print(); }
    int32_t getNumPacketBytes() const { return m_BufferSize; }
    uint8_t *getBuffer() const { return m_Buffer; }
    FILE *isfile() const { return file2; }

protected:
    void xBufferReset() {
        m_LastContinuityCounter = 0;
        m_BufferSize = 0;
        m_DataOffset = 0;
        delete[] m_Buffer;
        m_Buffer = nullptr;
        m_pesOffset = 0;
        m_DataOffset = 0;

        m_PESH.Reset();
    };

    void xBufferAppend(const uint8_t *Data, int32_t Size) {
        if (m_PID == 136) {
            if (m_Buffer == nullptr) {
                m_DataOffset += xTS::TS_PacketLength - Size;
                m_Buffer = new uint8_t[m_BufferSize];
                int j = 0;
                for (uint8_t i = Size; i < xTS::TS_PacketLength; i++) {
                    m_Buffer [j++] = Data [i];
                }
                return;
            } else {
                for (uint8_t i = Size; i < xTS::TS_PacketLength; i++) {
                    m_Buffer[m_DataOffset++] = Data[i];
                }
                return;
            }
        }
    }
};
//=============================================================================================================================================================================
int main( int argc, char *argv[ ], char *envp[ ])
{
    // TODO - open file
    FILE * file = fopen( "/home/kuba/CLionProjects/TS_parser/cmake-build-debug/example_new.ts", "rb" );
    if( !file ) {
        printf("Nieprawidłowy odczyt pliku!");
    }

    uint8_t TS_PacketBuffer [188];
    size_t number;
    xPES_Assembler PES_Assembler;
    PES_Assembler.Init(136);
    xTS_PacketHeader    TS_PacketHeader;
    xTS_AdaptationField TS_AdaptationField;
    xPES_PacketHeader PES_Packet_Header;
    int32_t TS_PacketId = 0;
    xPES_Assembler::eResult Result;

    while(!feof(file))
    {
        number = fread(TS_PacketBuffer, 1, 188, file);
        if (number != 188) {
            break;
        }
        TS_PacketHeader.Reset();
        TS_PacketHeader.Parse(TS_PacketBuffer);

        if (TS_PacketHeader.getSb() == 71 and TS_PacketHeader.getPid() == 136) {
            printf("%010d ", TS_PacketId);
            TS_PacketHeader.Print();
            TS_AdaptationField.Reset();

            if (TS_PacketHeader.hasAdaptationField()) {
                TS_AdaptationField.Parse(TS_PacketBuffer, TS_PacketHeader.getAfc());
                TS_AdaptationField.Print();
            }

           Result = PES_Assembler.AbsorbPacket(TS_PacketBuffer, &TS_PacketHeader,
                                                                        &TS_AdaptationField);
            switch (Result) {
                case xPES_Assembler::eResult::StreamPacketLost  : printf(" PcktLost"); break;
                case xPES_Assembler::eResult::AssemblingStarted :printf(" Started,");PES_Assembler.PrintPESH();break;
                case xPES_Assembler::eResult::AssemblingContinue:printf(" Continue");break;
                case xPES_Assembler::eResult::AssemblingFinished:printf(" Finished, Len=%4d", PES_Assembler.getNumPacketBytes()); break;
                default: break;
            }
            printf("\n");
        }
        TS_PacketId++;
    }
    if(PES_Assembler.isfile()){
        fwrite(PES_Assembler.getBuffer(), PES_Assembler.getNumPacketBytes(), 1, PES_Assembler.isfile());
        fclose(PES_Assembler.isfile());
    }
    fclose(file);
}