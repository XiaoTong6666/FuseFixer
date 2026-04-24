#pragma once

#include <elf.h>
#include <link.h>
#include <sys/mman.h>

extern "C" {
#include "../third_party/xz-embedded/linux_xz.h"
}

#include "state.hpp"

namespace fusehide {

inline constexpr std::string_view kIsAppAccessiblePathSymbols[] = {
    "_ZN13mediaprovider4fuseL22is_app_accessible_pathEP4fuseRKNSt6__ndk112basic_stringIcNS3_11char_"
    "traitsIcEENS3_9allocatorIcEEEEj",
    "_ZN13mediaprovider4fuseL22is_app_accessible_pathEP4fuseRKNSt3__112basic_stringIcNS3_11char_"
    "traitsIcEENS3_9allocatorIcEEEEj",
};

inline constexpr std::string_view kIsPackageOwnedPathSymbols[] = {
    "_ZL21is_package_owned_pathRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_"
    "9allocatorIcEEEES7_",
    "_ZL21is_package_owned_pathRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_",
};

inline constexpr std::string_view kContainsMountSymbols[] = {
    "_ZN13mediaprovider4fuse13containsMountERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_"
    "9allocatorIcEEEE",
    "_ZN13mediaprovider4fuse13containsMountERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_"
    "9allocatorIcEEEE",
};

inline constexpr std::string_view kIsBpfBackingPathSymbols[] = {
    "_ZL19is_bpf_backing_pathRKNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
    "_ZL19is_bpf_backing_pathRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE",
};

inline constexpr std::string_view kShouldNotCacheSymbols[] = {
    "_ZN13mediaprovider4fuse4fuse14ShouldNotCacheERKNSt6__ndk112basic_stringIcNS3_11char_"
    "traitsIcEENS3_9allocatorIcEEEE",
    "_ZN13mediaprovider4fuse4fuse14ShouldNotCacheERKNSt6__ndk112basic_stringIcNS2_11char_"
    "traitsIcEENS2_9allocatorIcEEEE",
    "_ZN13mediaprovider4fuse4fuse14ShouldNotCacheERKNSt3__112basic_stringIcNS2_11char_"
    "traitsIcEENS2_9allocatorIcEEEE",
    "ShouldNotCache",
};

inline constexpr std::string_view kStrcasecmpSymbol = "strcasecmp";

inline constexpr std::string_view kEqualsIgnoreCaseSymbols[] = {
    "_ZN7android4base16EqualsIgnoreCaseENSt6__ndk117basic_string_viewIcNS1_11char_traitsIcEEEES5_",
    "_ZN7android4base16EqualsIgnoreCaseENSt3__117basic_string_viewIcNS1_11char_traitsIcEEEES5_",
};

inline constexpr std::string_view kDoReaddirCommonSymbols[] = {
    "do_readdir_common",
};

inline constexpr std::string_view kGetDirectoryEntriesSymbols[] = {
    "_ZN13mediaprovider4fuse20MediaProviderWrapper19GetDirectoryEntriesEjRKNSt6__ndk112basic_"
    "stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEP3DIR",
};

inline constexpr std::string_view kAddDirectoryEntriesFromLowerFsSymbols[] = {
    "_ZN13mediaprovider4fuse30addDirectoryEntriesFromLowerFsEP3DIRPFbRK6direntEPNSt6__"
    "ndk16vectorINS8_10shared_ptrINS0_14DirectoryEntryEEENS8_9allocatorISC_EEEE",
};

inline constexpr std::string_view kPfLookupSymbols[] = {
    "_ZN13mediaprovider4fuseL9pf_lookupEP8fuse_reqmPKc",
};

inline constexpr std::string_view kPfLookupPostfilterSymbols[] = {
    "_ZN13mediaprovider4fuseL20pf_lookup_postfilterEP8fuse_reqmjPKcP14fuse_entry_outP18fuse_"
    "entry_bpf_out",
};

inline constexpr std::string_view kPfGetattrSymbols[] = {
    "_ZN13mediaprovider4fuseL10pf_getattrEP8fuse_reqmP14fuse_file_info",
};

inline constexpr std::string_view kPfMkdirSymbols[] = {
    "_ZN13mediaprovider4fuseL8pf_mkdirEP8fuse_reqmPKcj",
};

inline constexpr std::string_view kPfMknodSymbols[] = {
    "_ZN13mediaprovider4fuseL8pf_mknodEP8fuse_reqmPKcjm",
};

inline constexpr std::string_view kPfUnlinkSymbols[] = {
    "_ZN13mediaprovider4fuseL9pf_unlinkEP8fuse_reqmPKc",
};

inline constexpr std::string_view kPfRmdirSymbols[] = {
    "_ZN13mediaprovider4fuseL8pf_rmdirEP8fuse_reqmPKc",
};

inline constexpr std::string_view kPfRenameSymbols[] = {
    "_ZN13mediaprovider4fuseL9pf_renameEP8fuse_reqmPKcmS4_j",
};

inline constexpr std::string_view kPfCreateSymbols[] = {
    "_ZN13mediaprovider4fuseL9pf_createEP8fuse_reqmPKcjP14fuse_file_info",
};

inline constexpr std::string_view kPfReaddirSymbols[] = {
    "_ZN13mediaprovider4fuseL10pf_readdirEP8fuse_reqmmP14fuse_file_info",
};

inline constexpr std::string_view kPfReaddirPostfilterSymbols[] = {
    "_ZN13mediaprovider4fuseL21pf_readdir_postfilterEP8fuse_reqmjPKcPKvP14fuse_file_info",
};

inline constexpr std::string_view kPfReaddirplusSymbols[] = {
    "_ZN13mediaprovider4fuseL14pf_readdirplusEP8fuse_reqmmP14fuse_file_info",
};

#if defined(__LP64__)
using ElfHeader = Elf64_Ehdr;
using ElfSection = Elf64_Shdr;
using ElfSymbol = Elf64_Sym;
using ElfProgramHeader = Elf64_Phdr;
using ElfDynamic = Elf64_Dyn;
using ElfRelocationWithAddend = Elf64_Rela;
using ElfRelocationNoAddend = Elf64_Rel;
#else
using ElfHeader = Elf32_Ehdr;
using ElfSection = Elf32_Shdr;
using ElfSymbol = Elf32_Sym;
using ElfProgramHeader = Elf32_Phdr;
using ElfDynamic = Elf32_Dyn;
using ElfRelocationWithAddend = Elf32_Rel;
using ElfRelocationNoAddend = Elf32_Rel;
#endif

struct ModuleInfo {
    uintptr_t base = 0;
    std::string path;
    const ElfProgramHeader* phdrs = nullptr;
    uint16_t phnum = 0;
};

struct MappedFile {
    void* mapping = MAP_FAILED;
    size_t mappingSize = 0;
    const std::byte* data = nullptr;
    size_t size = 0;
    std::shared_ptr<std::vector<std::byte>> owned;

    MappedFile() = default;
    MappedFile(void* mapping_, size_t mappingSize_, const std::byte* data_, size_t size_)
        : mapping(mapping_), mappingSize(mappingSize_), data(data_), size(size_) {
    }
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    MappedFile(MappedFile&& other) noexcept
        : mapping(other.mapping),
          mappingSize(other.mappingSize),
          data(other.data),
          size(other.size),
          owned(std::move(other.owned)) {
        other.mapping = MAP_FAILED;
        other.mappingSize = 0;
        other.data = nullptr;
        other.size = 0;
    }

    MappedFile& operator=(MappedFile&& other) noexcept {
        if (this == &other) {
            return *this;
        }
        if (mapping != MAP_FAILED) {
            munmap(mapping, mappingSize);
        }
        mapping = other.mapping;
        mappingSize = other.mappingSize;
        data = other.data;
        size = other.size;
        owned = std::move(other.owned);
        other.mapping = MAP_FAILED;
        other.mappingSize = 0;
        other.data = nullptr;
        other.size = 0;
        return *this;
    }

    ~MappedFile() {
        if (mapping != MAP_FAILED) {
            munmap(mapping, mappingSize);
        }
    }

    const std::byte* bytes() const {
        return data;
    }
};

inline constexpr uint32_t kMaxGnuDebugdataOutputBytes = 16 * 1024 * 1024;
inline constexpr uint32_t kMaxGnuDebugdataDictBytes = 16 * 1024 * 1024;

struct DynamicInfo {
    uintptr_t symtab = 0;
    uintptr_t strtab = 0;
    uintptr_t hash = 0;
    uintptr_t gnuHash = 0;
    uintptr_t jmprel = 0;
    size_t pltrelSize = 0;
    uintptr_t rela = 0;
    size_t relaSize = 0;
    uintptr_t rel = 0;
    size_t relSize = 0;
    size_t syment = sizeof(ElfSymbol);
    bool usesRela =
#if defined(__LP64__)
        true;
#else
        false;
#endif
};

struct RuntimeDynamicInfo {
    const ElfSymbol* symtab = nullptr;
    const char* strtab = nullptr;
    const uint32_t* hash = nullptr;
    const uint32_t* gnuHash = nullptr;
    uintptr_t jmprel = 0;
    size_t pltrelSize = 0;
    uintptr_t rela = 0;
    size_t relaSize = 0;
    uintptr_t rel = 0;
    size_t relSize = 0;
    size_t syment = sizeof(ElfSymbol);
    bool usesRela =
#if defined(__LP64__)
        true;
#else
        false;
#endif
};

struct SymbolMatch {
    uintptr_t value = 0;
    size_t size = 0;
    std::string name;
};

inline uintptr_t RuntimePtr(uintptr_t base, uintptr_t value) {
    if (value == 0)
        return 0;
    return value < base ? base + value : value;
}

inline void FlushCodeRange(void* begin, void* end) {
    __builtin___clear_cache(reinterpret_cast<char*>(begin), reinterpret_cast<char*>(end));
}

std::optional<ModuleInfo> FindTargetModule();
std::optional<ModuleInfo> FindModuleFromMaps();
std::optional<MappedFile> MapReadOnlyFile(const std::string& path);
std::optional<MappedFile> MakeOwnedFile(std::vector<std::byte> bytes);
uint16_t ReadLe16(const std::byte* ptr);
uint32_t ReadLe32(const std::byte* ptr);
std::optional<MappedFile> MapEmbeddedStoredElf(const std::string& modulePath);
std::optional<std::pair<const std::byte*, size_t>> FindNamedSectionData(const MappedFile& file,
                                                                        std::string_view name);
const char* XzRetName(enum xz_ret ret);
std::optional<MappedFile> DecompressGnuDebugdata(const std::byte* compressed, size_t size);
std::optional<uintptr_t> FindSymbolOffset(const MappedFile& file, std::string_view symbolName);
std::optional<SymbolMatch> FindLargestSymbolContaining(const MappedFile& file,
                                                       std::string_view needle);
std::optional<size_t> VirtualAddressToFileOffset(const MappedFile& file, uintptr_t address);
std::optional<DynamicInfo> ParseDynamicInfo(const MappedFile& file);
std::optional<RuntimeDynamicInfo> ParseRuntimeDynamicInfo(const ModuleInfo& module);
const ElfSymbol* DynamicSymbolTable(const MappedFile& file, const DynamicInfo& info);
const char* DynamicStringTable(const MappedFile& file, const DynamicInfo& info);
size_t DynamicSymbolCount(const MappedFile& file, const DynamicInfo& info);
uint32_t ComputeGnuHash(const uint8_t* name, size_t len);
uint32_t ComputeElfHash(const uint8_t* name, size_t len);
std::optional<uint32_t> FindDynamicSymbolIndex(const MappedFile& file, const DynamicInfo& info,
                                               const uint8_t* name, size_t nameLen);
std::optional<uint32_t> FindDynamicSymbolIndexWithGnuHash(const MappedFile& file,
                                                          const DynamicInfo& info,
                                                          const uint8_t* name, size_t nameLen,
                                                          uint32_t gnuHash);
std::optional<uint32_t> FindRuntimeSymbolIndex(const RuntimeDynamicInfo& info, const uint8_t* name,
                                               size_t nameLen);
std::vector<uintptr_t> FindRelocationSlotsForSymbol(const MappedFile& file, const DynamicInfo& info,
                                                    uint32_t symIndex, uintptr_t loadBias);
std::vector<uintptr_t> FindRuntimeRelocationSlotsForSymbol(const RuntimeDynamicInfo& info,
                                                           uint32_t symIndex, uintptr_t loadBias);

}  // namespace fusehide
