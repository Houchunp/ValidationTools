#include "stdafx.h"
#include "Tpm12.h"
#include "Tpm20.h"

#pragma comment(lib, "Tbs.lib")

void logResult(TBS_RESULT result, const char* msg)
{
    if ( result != TBS_SUCCESS )
    {
        std::cout << msg << " Error code: " << result << std::endl;
    }
}

struct ContextDeleter
{
    void operator() (void* c)
    {
        if ( c != nullptr )
        {
            TBS_RESULT result = Tbsip_Context_Close((TBS_HCONTEXT)c);
            logResult(result, "Cannot close context.");
        }
    }
};

inline uint16_t SwapEndian(uint16_t val)
{
    return (val << 8) | (val >> 8);
}

inline uint32_t SwapEndian(uint32_t val)
{
    return (val << 24) | ((val << 8) & 0x00ff0000) |
        ((val >> 8) & 0x0000ff00) | (val >> 24);
}

template <typename N>
class BE_uint
{
public:
    BE_uint()
        : m_value(0)
    {}

    BE_uint(N value)
        : m_value(SwapEndian(value))
    {}

    BE_uint<N>& operator= (N value) { m_value = SwapEndian(value); return *this; }

    operator N () const { return SwapEndian(m_value); }

    N be_value() const { return m_value; }
    N le_value() const { return SwapEndian(m_value); }

private:
    N m_value;
};
UINT16
SwapBytes16(
    UINT16                    Value
)
{
    return (UINT16)((Value << 8) | (Value >> 8));
}


UINT32
SwapBytes32(
    UINT32                    Value
)
{
    UINT32  LowerBytes;
    UINT32  HigherBytes;

    LowerBytes = (UINT32)SwapBytes16((UINT16)Value);
    HigherBytes = (UINT32)SwapBytes16((UINT16)(Value >> 16));
    return (LowerBytes << 16 | HigherBytes);
}
VOID
InternalDumpData(
    IN UINT8* Data,
    IN UINT64  Size
)
{
    UINT32  Index;
    for (Index = 0; Index < Size; Index++) {
        printf( "%02x", Data[Index]);
    }
}

int main()
{
    TBS_RESULT result;

    TBS_HCONTEXT hContext;
    // TBS_CONTEXT_PARAMS contextParams;
    TBS_CONTEXT_PARAMS2 contextParams2;
    //contextParams.version = TBS_CONTEXT_VERSION_ONE;
    contextParams2.version = TBS_CONTEXT_VERSION_TWO;
    contextParams2.includeTpm20 = 0x1;
    result = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&contextParams2, &hContext);
    logResult(result, "Cannot create context.");
    if (result != TBS_SUCCESS)
    {
        return -1;
    }

    std::unique_ptr<void, ContextDeleter> guardContext(hContext);

#pragma pack(push,1)
    typedef struct {
        TPM2_COMMAND_HEADER       Header;
        TPML_PCR_SELECTION        PcrSelectionIn;
    } TPM2_PCR_READ_COMMAND;

    typedef struct {
        TPM2_RESPONSE_HEADER      Header;
        UINT32                    PcrUpdateCounter;
        TPML_PCR_SELECTION        PcrSelectionOut;
        TPML_DIGEST               PcrValues;
    } TPM2_PCR_READ_RESPONSE;
#pragma pack(pop)
    for (int PcrIndex = 0; PcrIndex < 24; ++PcrIndex) {
        TPML_PCR_SELECTION        PcrSelectionIn;
        TPML_PCR_SELECTION        *PcrSelectionInPtr;
        UINT32                    PcrUpdateCounter;
        TPML_PCR_SELECTION        PcrSelectionOut;
        TPM2_PCR_READ_COMMAND             SendBuffer;
        TPM2_PCR_READ_RESPONSE            RecvBuffer;
        UINT32                            SendBufferSize;
        UINT32                            RecvBufferSize;
        TPML_DIGEST                       PcrValues;
        TPML_DIGEST* PcrValuesPtr{};
        TPML_DIGEST* PcrValuesOut;

        UINT32                            Index;
        TPM2B_DIGEST* Digests;
        ZeroMemory(&PcrValues, sizeof(PcrValues));
        ZeroMemory(&PcrSelectionIn, sizeof(PcrSelectionIn));
        ZeroMemory(&PcrSelectionOut, sizeof(PcrSelectionOut));
        PcrValuesPtr = &PcrValues;
        PcrUpdateCounter = 0;
        PcrSelectionIn.count = 1;
        PcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA256;
        PcrSelectionIn.pcrSelections[0].sizeofSelect = PCR_SELECT_MAX;
        PcrSelectionIn.pcrSelections[0].pcrSelect[PcrIndex / 8] = (1 << (PcrIndex % 8));
        PcrSelectionInPtr = &PcrSelectionIn;
        SendBuffer.PcrSelectionIn.count = SwapBytes32(PcrSelectionInPtr->count);
        SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
        SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_PCR_Read);
        for (Index = 0; Index < PcrSelectionInPtr->count; Index++) {
            SendBuffer.PcrSelectionIn.pcrSelections[Index].hash = SwapBytes16(PcrSelectionInPtr->pcrSelections[Index].hash);
            SendBuffer.PcrSelectionIn.pcrSelections[Index].sizeofSelect = PcrSelectionInPtr->pcrSelections[Index].sizeofSelect;
            memcpy(&SendBuffer.PcrSelectionIn.pcrSelections[Index].pcrSelect, &PcrSelectionInPtr->pcrSelections[Index].pcrSelect, SendBuffer.PcrSelectionIn.pcrSelections[Index].sizeofSelect);
        }
        SendBufferSize = sizeof(SendBuffer.Header) + sizeof(SendBuffer.PcrSelectionIn.count) + sizeof(SendBuffer.PcrSelectionIn.pcrSelections[0]) * PcrSelectionIn.count;
        SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
        RecvBufferSize = sizeof(RecvBuffer);

        result = Tbsip_Submit_Command(hContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
            (PCBYTE)&SendBuffer, SendBufferSize,
            (PBYTE)&RecvBuffer, &RecvBufferSize);
        logResult(result, std::string(std::string("Error reading PCR register #") + std::to_string(PcrIndex)).c_str());
        PcrSelectionOut.count = SwapBytes32(RecvBuffer.PcrSelectionOut.count);
        for (Index = 0; Index < PcrSelectionOut.count; Index++) {
            PcrSelectionOut.pcrSelections[Index].hash = SwapBytes16(RecvBuffer.PcrSelectionOut.pcrSelections[Index].hash);
            PcrSelectionOut.pcrSelections[Index].sizeofSelect = RecvBuffer.PcrSelectionOut.pcrSelections[Index].sizeofSelect;
            memcpy(&PcrSelectionOut.pcrSelections[Index].pcrSelect, &RecvBuffer.PcrSelectionOut.pcrSelections[Index].pcrSelect, PcrSelectionOut.pcrSelections[Index].sizeofSelect);
        }

        //
        // PcrValues
        //
        PcrValuesOut = (TPML_DIGEST*)((UINT8*)&RecvBuffer + sizeof(TPM2_RESPONSE_HEADER) + sizeof(RecvBuffer.PcrUpdateCounter) + sizeof(RecvBuffer.PcrSelectionOut.count) + sizeof(RecvBuffer.PcrSelectionOut.pcrSelections[0]) * PcrSelectionOut.count);
        PcrValuesPtr->count = SwapBytes32(PcrValuesOut->count);

        Digests = PcrValuesOut->digests;
        for (Index = 0; Index < PcrValuesPtr->count; Index++) {
            PcrValuesPtr->digests[Index].size = SwapBytes16(Digests->size);
            memcpy(&PcrValuesPtr->digests[Index].buffer, &Digests->buffer, PcrValuesPtr->digests[Index].size);
            Digests = (TPM2B_DIGEST*)((UINT8*)Digests + sizeof(Digests->size) + PcrValuesPtr->digests[Index].size);
        }

        for (Index = 0; Index < PcrValues.count; Index++) {
            printf("PCR[%d] (Hash:0x%x): ", PcrIndex, 0xB);
            InternalDumpData((UINT8*)&PcrValues.digests[Index].buffer, PcrValues.digests[Index].size);
            printf("\n");
        }
    }      
}

