#include <iostream>

#include <inttypes.h>
#include <Windows.h>

#include <jni.h>
#include <Zydis/Zydis.h>

DWORD_PTR FindAttachListenerInit(HMODULE jvm_handle)
{

    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(jvm_handle);
    auto signature = reinterpret_cast<PDWORD>(reinterpret_cast<PCHAR>(jvm_handle) + dos_header->e_lfanew);
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(signature);

    PIMAGE_SECTION_HEADER section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PCHAR>(nt_headers) + sizeof(*nt_headers));
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++)
    {
        if (std::memcmp(section_header->Name, ".text", 5) != 0)
        {
            continue;
        }

        auto read_offset_base = reinterpret_cast<DWORD_PTR>(jvm_handle) + section_header->PointerToRawData;
        auto raw_data = reinterpret_cast<PCHAR>(jvm_handle) + section_header->PointerToRawData;
        auto raw_data_size = section_header->SizeOfRawData;

        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

        ZydisFormatter formatter;
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

        ZydisDecoderContext context;
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZyanStatus status;
        ZyanUSize read_offset = 0;

        bool searching_func = true;
        ZyanU64 func_address;
        while ((status = ZydisDecoderDecodeInstruction(&decoder, &context,
                                                       raw_data + read_offset, raw_data_size - read_offset,
                                                       &instruction)) != ZYDIS_STATUS_NO_MORE_DATA)
        {
            const ZyanU64 runtime_address = read_offset_base + read_offset;

            if (!ZYAN_SUCCESS(status))
            {
                read_offset++;
                continue;
            }
            if (searching_func && instruction.mnemonic != ZYDIS_MNEMONIC_INT3)
            {
                searching_func = false;
                func_address = runtime_address;
            }

            if (instruction.meta.category == ZYDIS_CATEGORY_RET)
            {
                searching_func = true;
            }

            bool found_mov = false;
            ZyanU64 result_address;
            if ((instruction.meta.category == ZYDIS_CATEGORY_DATAXFER || instruction.mnemonic == ZYDIS_MNEMONIC_LEA) &&
                ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &context, &instruction, operands, instruction.operand_count_visible)))
            {
                for (int i = 0; i < instruction.operand_count_visible; i++)
                {
                    auto operand = operands[i];
                    if (operand.actions != ZYDIS_OPERAND_ACTION_READ && instruction.mnemonic != ZYDIS_MNEMONIC_LEA)
                    {
                        continue;
                    }

                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operand, runtime_address, &result_address)))
                    {
                        found_mov = true;
                        break;
                    }
                }
            }
            if (found_mov && result_address + 16 - reinterpret_cast<DWORD_PTR>(jvm_handle) < nt_headers->OptionalHeader.SizeOfImage)
            {
                auto result_value = reinterpret_cast<PCHAR>(result_address);
                if (std::memcmp(result_value, "Attach Listener", 16) == 0)
                {
                    char text[96];
                    ZydisFormatterFormatInstruction(&formatter, &instruction,
                                                    operands, instruction.operand_count_visible, text,
                                                    sizeof(text), runtime_address, ZYAN_NULL);
                    printf("Found instruction %016" PRIX64 "  %s in function at %016" PRIX64 "\n", runtime_address, text, func_address);

                    return func_address;
                }
            }

            read_offset += instruction.length;
        }
    }
    return NULL;
}

void Load(const HMODULE hModule)
{
    JavaVM *vm;
    jsize vm_count;
    JNI_GetCreatedJavaVMs(&vm, 1, &vm_count);
    if (vm_count == 0)
    {
        std::cerr << "Couldn't find Java VM!" << std::endl;
        FreeLibraryAndExitThread(hModule, 0);
    }

    JNIEnv *env;

    jint status;
    JavaVMAttachArgs args{};
    args.version = JNI_VERSION_1_6;
    if ((status = vm->AttachCurrentThread(reinterpret_cast<void **>(&env), &args)) != JNI_OK)
    {
        std::cerr << "Failed to attach current thread: " << status << std::endl;
        FreeLibraryAndExitThread(hModule, 0);
    }

    HMODULE jvm_handle = GetModuleHandle("jvm");
    std::cout << "Got jvm handle: " << jvm_handle << std::endl;

    DWORD_PTR attach_listener_init_ptr = FindAttachListenerInit(jvm_handle);
    if (attach_listener_init_ptr == NULL)
    {
        std::cerr << "Couldn't find pointer to AttachListener::init()" << std::endl;
        vm->DetachCurrentThread();
        FreeLibraryAndExitThread(hModule, 0);
    }

    std::cout << "Calling AttachListener::init() at " << std::hex << attach_listener_init_ptr << std::endl;

    auto attach_listener_init = reinterpret_cast<void (*)()>(attach_listener_init_ptr);
    attach_listener_init();
    std::cout << "Initialized Attach Listener" << std::endl;

    vm->DetachCurrentThread();
    FreeLibraryAndExitThread(hModule, 0);
}

BOOL WINAPI DllMain(
    HMODULE hinstDLL,   // handle to DLL module
    DWORD fdwReason,    // reason for calling function
    LPVOID lpvReserved) // reserved
{
    if (fdwReason != DLL_PROCESS_ATTACH)
    {
        return TRUE;
    }

    const HANDLE handle = CreateThread(nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(Load), hinstDLL,
                                       0, nullptr);
    if (handle != nullptr)
    {
        CloseHandle(handle);
    }
    return TRUE;
}
