#include "elf_utils.hpp"

namespace fusehide {

// Module discovery

int DlIterateCallback(dl_phdr_info* info, size_t, void* data) {
    auto* module = reinterpret_cast<ModuleInfo*>(data);
    if (info == nullptr || info->dlpi_name == nullptr) {
        return 0;
    }
    const std::string_view name(info->dlpi_name);
    if (name.find(kTargetLibrary) == std::string_view::npos) {
        return 0;
    }
    module->base = static_cast<uintptr_t>(info->dlpi_addr);
    module->path = info->dlpi_name;
    module->phdrs = reinterpret_cast<const ElfProgramHeader*>(info->dlpi_phdr);
    module->phnum = info->dlpi_phnum;
    return 1;
}

std::optional<ModuleInfo> FindModuleFromMaps() {
    FILE* maps = std::fopen("/proc/self/maps", "re");
    if (maps == nullptr) {
        return std::nullopt;
    }

    char* line = nullptr;
    size_t lineCap = 0;
    uintptr_t lowestBase = 0;
    std::string path;
    while (getline(&line, &lineCap, maps) > 0) {
        const char* found = std::strstr(line, kTargetLibrary);
        if (found == nullptr) {
            continue;
        }
        unsigned long long start = 0;
        if (std::sscanf(line, "%llx-", &start) != 1) {
            continue;
        }
        if (lowestBase == 0 || static_cast<uintptr_t>(start) < lowestBase) {
            lowestBase = static_cast<uintptr_t>(start);
        }
        path = found;
        while (!path.empty() &&
               (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) {
            path.pop_back();
        }
    }

    if (line != nullptr) {
        std::free(line);
    }
    std::fclose(maps);

    if (lowestBase == 0 || path.empty()) {
        return std::nullopt;
    }
    return ModuleInfo{lowestBase, path};
}

std::optional<ModuleInfo> FindTargetModule() {
    ModuleInfo module;
    dl_iterate_phdr(DlIterateCallback, &module);
    if (module.base != 0 && !module.path.empty()) {
        return module;
    }
    return FindModuleFromMaps();
}

// ELF file mapping and parsing

std::optional<MappedFile> MapReadOnlyFile(const std::string& path) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        __android_log_print(6, kLogTag, "failed with %d %s: elf_parser: open %s", errno,
                            strerror(errno), path.c_str());
        return std::nullopt;
    }

    struct stat st {};
    if (fstat(fd, &st) != 0) {
        __android_log_print(6, kLogTag, "failed with %d %s: elf_parser: stat %s", errno,
                            strerror(errno), path.c_str());
        close(fd);
        return std::nullopt;
    }

    void* address = mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (address == MAP_FAILED) {
        __android_log_print(6, kLogTag, "failed with %d %s: elf_parser: mmap %s", errno,
                            strerror(errno), path.c_str());
        return std::nullopt;
    }

    return MappedFile{address, static_cast<size_t>(st.st_size),
                      reinterpret_cast<const std::byte*>(address), static_cast<size_t>(st.st_size)};
}

std::optional<MappedFile> MakeOwnedFile(std::vector<std::byte> bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }
    auto owned = std::make_shared<std::vector<std::byte>>(std::move(bytes));
    MappedFile file;
    file.owned = owned;
    file.data = owned->data();
    file.size = owned->size();
    return file;
}

uint16_t ReadLe16(const std::byte* ptr) {
    uint16_t value = 0;
    std::memcpy(&value, ptr, sizeof(value));
    return value;
}

uint32_t ReadLe32(const std::byte* ptr) {
    uint32_t value = 0;
    std::memcpy(&value, ptr, sizeof(value));
    return value;
}

std::optional<MappedFile> MapEmbeddedStoredElf(const std::string& modulePath) {
    const size_t bang = modulePath.find("!/");
    if (bang == std::string::npos) {
        return std::nullopt;
    }
    const std::string apkPath = modulePath.substr(0, bang);
    const std::string entryPath = modulePath.substr(bang + 2);

    auto apk = MapReadOnlyFile(apkPath);
    if (!apk.has_value()) {
        return std::nullopt;
    }

    const auto* bytes = apk->bytes();
    const size_t size = apk->size;
    if (size < 22) {
        return std::nullopt;
    }

    size_t eocdOffset = std::string::npos;
    const size_t searchStart = size > (0xFFFF + 22) ? size - (0xFFFF + 22) : 0;
    for (size_t off = size - 22 + 1; off-- > searchStart;) {
        if (ReadLe32(bytes + off) == 0x06054b50U) {
            eocdOffset = off;
            break;
        }
    }
    if (eocdOffset == std::string::npos) {
        __android_log_print(5, kLogTag, "embedded apk missing EOCD: %s", apkPath.c_str());
        return std::nullopt;
    }

    const uint32_t centralDirOffset = ReadLe32(bytes + eocdOffset + 16);
    const uint16_t totalEntries = ReadLe16(bytes + eocdOffset + 10);
    size_t cursor = centralDirOffset;
    for (uint16_t i = 0; i < totalEntries && cursor + 46 <= size; ++i) {
        if (ReadLe32(bytes + cursor) != 0x02014b50U) {
            break;
        }
        const uint16_t method = ReadLe16(bytes + cursor + 10);
        const uint32_t compressedSize = ReadLe32(bytes + cursor + 20);
        const uint32_t uncompressedSize = ReadLe32(bytes + cursor + 24);
        const uint16_t nameLen = ReadLe16(bytes + cursor + 28);
        const uint16_t extraLen = ReadLe16(bytes + cursor + 30);
        const uint16_t commentLen = ReadLe16(bytes + cursor + 32);
        const uint32_t localHeaderOffset = ReadLe32(bytes + cursor + 42);

        if (cursor + 46 + nameLen > size) {
            break;
        }
        const char* name = reinterpret_cast<const char*>(bytes + cursor + 46);
        if (entryPath == std::string_view(name, nameLen)) {
            if (method != 0) {
                __android_log_print(5, kLogTag, "embedded entry compressed method=%u path=%s",
                                    method, entryPath.c_str());
                return std::nullopt;
            }
            if (localHeaderOffset + 30 > size ||
                ReadLe32(bytes + localHeaderOffset) != 0x04034b50U) {
                __android_log_print(5, kLogTag, "embedded entry bad local header path=%s",
                                    entryPath.c_str());
                return std::nullopt;
            }
            const uint16_t localNameLen = ReadLe16(bytes + localHeaderOffset + 26);
            const uint16_t localExtraLen = ReadLe16(bytes + localHeaderOffset + 28);
            const size_t dataOffset = localHeaderOffset + 30 + localNameLen + localExtraLen;
            if (dataOffset + uncompressedSize > size || compressedSize != uncompressedSize) {
                return std::nullopt;
            }

            MappedFile embedded = std::move(*apk);
            embedded.data = bytes + dataOffset;
            embedded.size = uncompressedSize;
            __android_log_print(4, kLogTag, "mapped embedded elf entry=%s size=%u",
                                entryPath.c_str(), uncompressedSize);
            return embedded;
        }

        cursor += 46 + nameLen + extraLen + commentLen;
    }

    __android_log_print(5, kLogTag, "embedded entry not found: %s", entryPath.c_str());
    return std::nullopt;
}

std::optional<std::pair<const std::byte*, size_t>> FindNamedSectionData(const MappedFile& file,
                                                                        std::string_view name) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    if (header == nullptr || std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        return std::nullopt;
    }
    if (header->e_shoff == 0 || header->e_shnum == 0 || header->e_shentsize != sizeof(ElfSection) ||
        header->e_shstrndx >= header->e_shnum) {
        return std::nullopt;
    }

    const auto* sections = reinterpret_cast<const ElfSection*>(file.bytes() + header->e_shoff);
    const auto& shstrtab = sections[header->e_shstrndx];
    if (shstrtab.sh_offset + shstrtab.sh_size > file.size) {
        return std::nullopt;
    }
    const char* sectionNames = reinterpret_cast<const char*>(file.bytes() + shstrtab.sh_offset);
    for (uint16_t sectionIndex = 0; sectionIndex < header->e_shnum; ++sectionIndex) {
        const auto& section = sections[sectionIndex];
        if (section.sh_name >= shstrtab.sh_size ||
            section.sh_offset + section.sh_size > file.size) {
            continue;
        }
        const char* currentName = sectionNames + section.sh_name;
        if (name == currentName) {
            return std::pair<const std::byte*, size_t>{file.bytes() + section.sh_offset,
                                                       static_cast<size_t>(section.sh_size)};
        }
    }
    return std::nullopt;
}

const char* XzRetName(enum xz_ret ret) {
    switch (ret) {
        case XZ_OK:
            return "XZ_OK";
        case XZ_STREAM_END:
            return "XZ_STREAM_END";
        case XZ_UNSUPPORTED_CHECK:
            return "XZ_UNSUPPORTED_CHECK";
        case XZ_MEM_ERROR:
            return "XZ_MEM_ERROR";
        case XZ_MEMLIMIT_ERROR:
            return "XZ_MEMLIMIT_ERROR";
        case XZ_FORMAT_ERROR:
            return "XZ_FORMAT_ERROR";
        case XZ_OPTIONS_ERROR:
            return "XZ_OPTIONS_ERROR";
        case XZ_DATA_ERROR:
            return "XZ_DATA_ERROR";
        case XZ_BUF_ERROR:
            return "XZ_BUF_ERROR";
        default:
            return "XZ_UNKNOWN";
    }
}

std::optional<MappedFile> DecompressGnuDebugdata(const std::byte* compressed, size_t size) {
    if (compressed == nullptr || size == 0) {
        return std::nullopt;
    }

    std::call_once(gXzCrcInitOnce, []() { xz_crc32_init(); });

    struct DecoderDeleter {
        void operator()(xz_dec* decoder) const {
            xz_dec_end(decoder);
        }
    };

    std::unique_ptr<xz_dec, DecoderDeleter> decoder(
        xz_dec_init(XZ_DYNALLOC, kMaxGnuDebugdataDictBytes));
    if (decoder == nullptr) {
        __android_log_print(5, kLogTag, "gnu_debugdata xz_dec_init failed");
        return std::nullopt;
    }

    std::vector<std::byte> output(64 * 1024);
    struct xz_buf buffer = {};
    buffer.in = reinterpret_cast<const uint8_t*>(compressed);
    buffer.in_size = size;
    buffer.out = reinterpret_cast<uint8_t*>(output.data());
    buffer.out_size = output.size();

    while (true) {
        const enum xz_ret ret = xz_dec_run(decoder.get(), &buffer);
        if (ret == XZ_STREAM_END) {
            output.resize(buffer.out_pos);
            __android_log_print(4, kLogTag, "decompressed .gnu_debugdata in=%zu out=%zu", size,
                                output.size());
            return MakeOwnedFile(std::move(output));
        }
        if (ret == XZ_UNSUPPORTED_CHECK) {
            continue;
        }
        if (ret == XZ_OK) {
            if (buffer.out_pos == buffer.out_size) {
                if (output.size() >= kMaxGnuDebugdataOutputBytes) {
                    __android_log_print(5, kLogTag, "gnu_debugdata output too large >= %u",
                                        kMaxGnuDebugdataOutputBytes);
                    return std::nullopt;
                }
                const size_t oldOutPos = buffer.out_pos;
                const size_t nextSize =
                    std::min<size_t>(output.size() * 2, kMaxGnuDebugdataOutputBytes);
                output.resize(nextSize);
                buffer.out = reinterpret_cast<uint8_t*>(output.data());
                buffer.out_pos = oldOutPos;
                buffer.out_size = output.size();
            }
            continue;
        }

        __android_log_print(
            5, kLogTag, "gnu_debugdata decompress failed ret=%s in_pos=%zu/%zu out_pos=%zu/%zu",
            XzRetName(ret), buffer.in_pos, buffer.in_size, buffer.out_pos, buffer.out_size);
        return std::nullopt;
    }
}

// Section-based symbol lookup (fallback path)
std::optional<uintptr_t> FindSymbolOffsetImpl(const MappedFile& file, std::string_view symbolName,
                                              int depth) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    if (header == nullptr || std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
        header->e_shoff == 0 || header->e_shnum == 0 || header->e_shentsize != sizeof(ElfSection)) {
        return std::nullopt;
    }

    const auto* sections = reinterpret_cast<const ElfSection*>(file.bytes() + header->e_shoff);
    for (uint16_t sectionIndex = 0; sectionIndex < header->e_shnum; ++sectionIndex) {
        const auto& section = sections[sectionIndex];
        if (section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM) {
            continue;
        }
        if (section.sh_link >= header->e_shnum || section.sh_entsize != sizeof(ElfSymbol) ||
            section.sh_size == 0) {
            continue;
        }
        const auto& strtab = sections[section.sh_link];
        if (strtab.sh_offset + strtab.sh_size > file.size ||
            section.sh_offset + section.sh_size > file.size) {
            continue;
        }
        const char* strings = reinterpret_cast<const char*>(file.bytes() + strtab.sh_offset);
        const auto* symbols = reinterpret_cast<const ElfSymbol*>(file.bytes() + section.sh_offset);
        const size_t symbolCount = section.sh_size / sizeof(ElfSymbol);
        for (size_t symbolIndex = 0; symbolIndex < symbolCount; ++symbolIndex) {
            const auto& symbol = symbols[symbolIndex];
            if (symbol.st_name == 0 || symbol.st_value == 0) {
                continue;
            }
            const char* currentName = strings + symbol.st_name;
            if (currentName != nullptr && symbolName == currentName) {
                return static_cast<uintptr_t>(symbol.st_value);
            }
        }
    }

    if (depth >= 2) {
        return std::nullopt;
    }

    auto debugdata = FindNamedSectionData(file, ".gnu_debugdata");
    if (!debugdata.has_value()) {
        return std::nullopt;
    }

    auto decompressed = DecompressGnuDebugdata(debugdata->first, debugdata->second);
    if (!decompressed.has_value()) {
        return std::nullopt;
    }

    const std::string symbolNameString(symbolName);
    __android_log_print(4, kLogTag, "searching .gnu_debugdata for %s", symbolNameString.c_str());
    auto offset = FindSymbolOffsetImpl(*decompressed, symbolName, depth + 1);
    if (offset.has_value()) {
        __android_log_print(4, kLogTag, "resolved from .gnu_debugdata %s value=%p",
                            symbolNameString.c_str(), reinterpret_cast<void*>(*offset));
    }
    return offset;
}

std::optional<uintptr_t> FindSymbolOffset(const MappedFile& file, std::string_view symbolName) {
    return FindSymbolOffsetImpl(file, symbolName, 0);
}

void CollectSymbolsContainingImpl(const MappedFile& file, std::string_view needle, int depth,
                                  std::vector<SymbolMatch>* matches) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    if (header == nullptr || std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
        header->e_shoff == 0 || header->e_shnum == 0 || header->e_shentsize != sizeof(ElfSection)) {
        return;
    }

    const auto* sections = reinterpret_cast<const ElfSection*>(file.bytes() + header->e_shoff);
    for (uint16_t sectionIndex = 0; sectionIndex < header->e_shnum; ++sectionIndex) {
        const auto& section = sections[sectionIndex];
        if (section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM) {
            continue;
        }
        if (section.sh_link >= header->e_shnum || section.sh_entsize != sizeof(ElfSymbol) ||
            section.sh_size == 0) {
            continue;
        }
        const auto& strtab = sections[section.sh_link];
        if (strtab.sh_offset + strtab.sh_size > file.size ||
            section.sh_offset + section.sh_size > file.size) {
            continue;
        }
        const char* strings = reinterpret_cast<const char*>(file.bytes() + strtab.sh_offset);
        const auto* symbols = reinterpret_cast<const ElfSymbol*>(file.bytes() + section.sh_offset);
        const size_t symbolCount = section.sh_size / sizeof(ElfSymbol);
        for (size_t symbolIndex = 0; symbolIndex < symbolCount; ++symbolIndex) {
            const auto& symbol = symbols[symbolIndex];
            if (symbol.st_name == 0 || symbol.st_value == 0) {
                continue;
            }
            const char* currentName = strings + symbol.st_name;
            if (currentName == nullptr) {
                continue;
            }
            const std::string_view currentNameView(currentName);
            if (currentNameView.find(needle) == std::string_view::npos) {
                continue;
            }
            const bool duplicate =
                std::any_of(matches->begin(), matches->end(), [&](const SymbolMatch& existing) {
                    return existing.value == symbol.st_value && existing.size == symbol.st_size &&
                           existing.name == currentNameView;
                });
            if (!duplicate) {
                matches->push_back(SymbolMatch{static_cast<uintptr_t>(symbol.st_value),
                                               static_cast<size_t>(symbol.st_size),
                                               std::string(currentNameView)});
            }
        }
    }

    if (depth >= 2) {
        return;
    }

    auto debugdata = FindNamedSectionData(file, ".gnu_debugdata");
    if (!debugdata.has_value()) {
        return;
    }

    auto decompressed = DecompressGnuDebugdata(debugdata->first, debugdata->second);
    if (!decompressed.has_value()) {
        return;
    }

    CollectSymbolsContainingImpl(*decompressed, needle, depth + 1, matches);
}

std::optional<SymbolMatch> FindLargestSymbolContaining(const MappedFile& file,
                                                       std::string_view needle) {
    std::vector<SymbolMatch> matches;
    CollectSymbolsContainingImpl(file, needle, 0, &matches);
    if (matches.empty()) {
        return std::nullopt;
    }
    const auto best = std::max_element(matches.begin(), matches.end(),
                                       [](const SymbolMatch& lhs, const SymbolMatch& rhs) {
                                           if (lhs.size != rhs.size) {
                                               return lhs.size < rhs.size;
                                           }
                                           return lhs.value > rhs.value;
                                       });
    __android_log_print(4, kLogTag,
                        "resolved by contains needle=%s candidates=%zu picked=%s value=%p size=%zu",
                        std::string(needle).c_str(), matches.size(), best->name.c_str(),
                        reinterpret_cast<void*>(best->value), best->size);
    return *best;
}

std::optional<size_t> VirtualAddressToFileOffset(const MappedFile& file, uintptr_t address) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    const auto* programHeaders =
        reinterpret_cast<const ElfProgramHeader*>(file.bytes() + header->e_phoff);
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        const auto& phdr = programHeaders[i];
        if (phdr.p_type != PT_LOAD && phdr.p_type != PT_DYNAMIC) {
            continue;
        }
        if (address < phdr.p_vaddr || address >= phdr.p_vaddr + phdr.p_memsz) {
            continue;
        }
        return static_cast<size_t>(phdr.p_offset + (address - phdr.p_vaddr));
    }
    return std::nullopt;
}

std::optional<DynamicInfo> ParseDynamicInfo(const MappedFile& file) {
    const auto* header = reinterpret_cast<const ElfHeader*>(file.bytes());
    const auto* programHeaders =
        reinterpret_cast<const ElfProgramHeader*>(file.bytes() + header->e_phoff);
    const ElfProgramHeader* dynamicPhdr = nullptr;
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (programHeaders[i].p_type == PT_DYNAMIC) {
            dynamicPhdr = &programHeaders[i];
            break;
        }
    }
    if (dynamicPhdr == nullptr) {
        return std::nullopt;
    }

    DynamicInfo info;
    const auto* dyn = reinterpret_cast<const ElfDynamic*>(file.bytes() + dynamicPhdr->p_offset);
    const size_t dynCount = dynamicPhdr->p_filesz / sizeof(ElfDynamic);
    for (size_t i = 0; i < dynCount; ++i) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB:
                info.symtab = dyn[i].d_un.d_ptr;
                break;
            case DT_STRTAB:
                info.strtab = dyn[i].d_un.d_ptr;
                break;
            case DT_HASH:
                info.hash = dyn[i].d_un.d_ptr;
                break;
            case DT_GNU_HASH:
                info.gnuHash = dyn[i].d_un.d_ptr;
                break;
            case DT_JMPREL:
                info.jmprel = dyn[i].d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                info.pltrelSize = dyn[i].d_un.d_val;
                break;
            case DT_RELA:
                info.rela = dyn[i].d_un.d_ptr;
                break;
            case DT_RELASZ:
                info.relaSize = dyn[i].d_un.d_val;
                break;
            case DT_REL:
                info.rel = dyn[i].d_un.d_ptr;
                break;
            case DT_RELSZ:
                info.relSize = dyn[i].d_un.d_val;
                break;
            case DT_SYMENT:
                info.syment = dyn[i].d_un.d_val;
                break;
            case DT_PLTREL:
                info.usesRela = dyn[i].d_un.d_val == DT_RELA;
                break;
            default:
                break;
        }
    }
    if (info.symtab == 0 || info.strtab == 0) {
        return std::nullopt;
    }
    return info;
}

std::optional<RuntimeDynamicInfo> ParseRuntimeDynamicInfo(const ModuleInfo& module) {
    if (module.base == 0 || module.phdrs == nullptr || module.phnum == 0) {
        return std::nullopt;
    }

    RuntimeDynamicInfo info;
    const ElfProgramHeader* dynamicPhdr = nullptr;
    for (uint16_t i = 0; i < module.phnum; ++i) {
        if (module.phdrs[i].p_type == PT_DYNAMIC) {
            dynamicPhdr = &module.phdrs[i];
            break;
        }
    }
    if (dynamicPhdr == nullptr) {
        return std::nullopt;
    }

    const auto* dyn = reinterpret_cast<const ElfDynamic*>(module.base + dynamicPhdr->p_vaddr);
    const size_t dynCount = dynamicPhdr->p_memsz / sizeof(ElfDynamic);
    for (size_t i = 0; i < dynCount; ++i) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB:
                info.symtab =
                    reinterpret_cast<const ElfSymbol*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_STRTAB:
                info.strtab =
                    reinterpret_cast<const char*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_HASH:
                info.hash =
                    reinterpret_cast<const uint32_t*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_GNU_HASH:
                info.gnuHash =
                    reinterpret_cast<const uint32_t*>(RuntimePtr(module.base, dyn[i].d_un.d_ptr));
                break;
            case DT_JMPREL:
                info.jmprel = RuntimePtr(module.base, dyn[i].d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                info.pltrelSize = dyn[i].d_un.d_val;
                break;
            case DT_RELA:
                info.rela = RuntimePtr(module.base, dyn[i].d_un.d_ptr);
                break;
            case DT_RELASZ:
                info.relaSize = dyn[i].d_un.d_val;
                break;
            case DT_REL:
                info.rel = RuntimePtr(module.base, dyn[i].d_un.d_ptr);
                break;
            case DT_RELSZ:
                info.relSize = dyn[i].d_un.d_val;
                break;
            case DT_SYMENT:
                info.syment = dyn[i].d_un.d_val;
                break;
            case DT_PLTREL:
                info.usesRela = dyn[i].d_un.d_val == DT_RELA;
                break;
            default:
                break;
        }
    }

    if (info.symtab == nullptr || info.strtab == nullptr) {
        return std::nullopt;
    }
    return info;
}

// Dynamic symbol table access

const ElfSymbol* DynamicSymbolTable(const MappedFile& file, const DynamicInfo& info) {
    const auto offset = VirtualAddressToFileOffset(file, info.symtab);
    if (!offset.has_value())
        return nullptr;
    return reinterpret_cast<const ElfSymbol*>(file.bytes() + *offset);
}

const char* DynamicStringTable(const MappedFile& file, const DynamicInfo& info) {
    const auto offset = VirtualAddressToFileOffset(file, info.strtab);
    if (!offset.has_value())
        return nullptr;
    return reinterpret_cast<const char*>(file.bytes() + *offset);
}

size_t SymbolCountFromSysvHash(const MappedFile& file, uintptr_t hashAddress) {
    const auto hashOffset = VirtualAddressToFileOffset(file, hashAddress);
    if (!hashOffset.has_value())
        return 0;
    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    return words[1];  // nchain
}

size_t SymbolCountFromGnuHash(const MappedFile& file, uintptr_t gnuHashAddress) {
    const auto hashOffset = VirtualAddressToFileOffset(file, gnuHashAddress);
    if (!hashOffset.has_value())
        return 0;
    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    const uint32_t nbuckets = words[0];
    const uint32_t symoffset = words[1];
    const uint32_t bloomSize = words[2];
    const auto* buckets = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset + 16 +
                                                            bloomSize * sizeof(uintptr_t));
    const auto* chains = buckets + nbuckets;

    uint32_t maxSymbol = symoffset;
    for (uint32_t i = 0; i < nbuckets; ++i) {
        if (buckets[i] > maxSymbol) {
            maxSymbol = buckets[i];
        }
    }
    if (maxSymbol == symoffset)
        return symoffset;
    uint32_t chainIndex = maxSymbol - symoffset;
    while ((chains[chainIndex] & 1U) == 0U) {
        ++chainIndex;
    }
    return symoffset + chainIndex + 1;
}

size_t DynamicSymbolCount(const MappedFile& file, const DynamicInfo& info) {
    if (info.hash != 0) {
        const size_t count = SymbolCountFromSysvHash(file, info.hash);
        if (count != 0)
            return count;
    }
    if (info.gnuHash != 0) {
        const size_t count = SymbolCountFromGnuHash(file, info.gnuHash);
        if (count != 0)
            return count;
    }
    return 0;
}

// Hash-assisted symbol lookup

uint32_t ComputeGnuHash(const uint8_t* name, size_t len) {
    uint32_t hash = 0x1505U;
    for (size_t i = 0; i < len; ++i) {
        hash = hash * 33U + name[i];
    }
    return hash;
}

uint32_t ComputeElfHash(const uint8_t* name, size_t len) {
    uint32_t hash = 0;
    for (size_t i = 0; i < len; ++i) {
        hash = (hash << 4U) + name[i];
        const uint32_t high = hash & 0xF0000000U;
        if (high != 0) {
            hash ^= high >> 24U;
        }
        hash &= 0x0FFFFFFFU;
    }
    return hash;
}

// GNU hash-assisted symbol lookup
std::optional<uint32_t> FindDynamicSymbolIndexWithGnuHash(const MappedFile& file,
                                                          const DynamicInfo& info,
                                                          const uint8_t* name, size_t nameLen,
                                                          uint32_t gnuHash) {
    if (info.gnuHash == 0)
        return std::nullopt;
    const auto hashOffset = VirtualAddressToFileOffset(file, info.gnuHash);
    if (!hashOffset.has_value())
        return std::nullopt;

    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    const uint32_t nbuckets = words[0];
    const uint32_t symoffset = words[1];
    const uint32_t bloomSize = words[2];
    const uint32_t bloomShift = words[3];
    if (nbuckets == 0 || bloomSize == 0)
        return std::nullopt;

    const auto* bloom = reinterpret_cast<const uintptr_t*>(words + 4);
    const auto* buckets = reinterpret_cast<const uint32_t*>(bloom + bloomSize);
    const auto* chains = buckets + nbuckets;

    // Bloom filter check
    const uintptr_t bloomWord = bloom[(gnuHash / (sizeof(uintptr_t) * 8U)) % bloomSize];
    const uintptr_t mask = (uintptr_t{1} << (gnuHash % (sizeof(uintptr_t) * 8U))) |
                           (uintptr_t{1} << ((gnuHash >> bloomShift) % (sizeof(uintptr_t) * 8U)));
    if ((bloomWord & mask) != mask)
        return std::nullopt;

    uint32_t symbolIndex = buckets[gnuHash % nbuckets];
    if (symbolIndex < symoffset)
        return std::nullopt;

    const ElfSymbol* symbols = DynamicSymbolTable(file, info);
    const char* strings = DynamicStringTable(file, info);
    if (symbols == nullptr || strings == nullptr)
        return std::nullopt;

    for (;; ++symbolIndex) {
        const uint32_t chainHash = chains[symbolIndex - symoffset];
        if ((chainHash ^ gnuHash) < 2) {
            const auto& symbol = symbols[symbolIndex];
            const char* currentName = strings + symbol.st_name;
            const size_t currentLen = std::strlen(currentName);
            if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
                return symbolIndex;
            }
        }
        if ((chainHash & 1U) != 0U)
            break;
    }
    return std::nullopt;
}

std::optional<uint32_t> FindDynamicSymbolIndexWithSysvHash(const MappedFile& file,
                                                           const DynamicInfo& info,
                                                           const uint8_t* name, size_t nameLen,
                                                           uint32_t elfHash) {
    if (info.hash == 0)
        return std::nullopt;
    const auto hashOffset = VirtualAddressToFileOffset(file, info.hash);
    if (!hashOffset.has_value())
        return std::nullopt;

    const auto* words = reinterpret_cast<const uint32_t*>(file.bytes() + *hashOffset);
    const uint32_t nbucket = words[0];
    const uint32_t nchain = words[1];
    if (nbucket == 0 || nchain == 0)
        return std::nullopt;

    const auto* buckets = words + 2;
    const auto* chains = buckets + nbucket;
    const ElfSymbol* symbols = DynamicSymbolTable(file, info);
    const char* strings = DynamicStringTable(file, info);
    if (symbols == nullptr || strings == nullptr)
        return std::nullopt;

    uint32_t idx = buckets[elfHash % nbucket];
    while (idx != 0 && idx < nchain) {
        const auto& sym = symbols[idx];
        const char* currentName = strings + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return idx;
        }
        idx = chains[idx];
    }
    return std::nullopt;
}

std::optional<uint32_t> FindDynamicSymbolIndexLinear(const MappedFile& file,
                                                     const DynamicInfo& info, const uint8_t* name,
                                                     size_t nameLen) {
    const ElfSymbol* symbols = DynamicSymbolTable(file, info);
    const char* strings = DynamicStringTable(file, info);
    const size_t symbolCount = DynamicSymbolCount(file, info);
    if (symbols == nullptr || strings == nullptr || symbolCount == 0)
        return std::nullopt;

    for (size_t i = 0; i < symbolCount; ++i) {
        const auto& sym = symbols[i];
        const char* currentName = strings + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return static_cast<uint32_t>(i);
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> FindDynamicSymbolIndex(const MappedFile& file, const DynamicInfo& info,
                                               const uint8_t* name, size_t nameLen) {
    const uint32_t gnuHash = ComputeGnuHash(name, nameLen);
    if (auto index = FindDynamicSymbolIndexWithGnuHash(file, info, name, nameLen, gnuHash);
        index.has_value()) {
        return index;
    }

    const uint32_t elfHash = ComputeElfHash(name, nameLen);
    if (auto index = FindDynamicSymbolIndexWithSysvHash(file, info, name, nameLen, elfHash);
        index.has_value()) {
        return index;
    }

    return FindDynamicSymbolIndexLinear(file, info, name, nameLen);
}

std::optional<uint32_t> FindRuntimeSymbolIndexWithGnuHash(const RuntimeDynamicInfo& info,
                                                          const uint8_t* name, size_t nameLen,
                                                          uint32_t gnuHash) {
    if (info.gnuHash == nullptr)
        return std::nullopt;

    const auto* words = info.gnuHash;
    const uint32_t nbuckets = words[0];
    const uint32_t symoffset = words[1];
    const uint32_t bloomSize = words[2];
    const uint32_t bloomShift = words[3];
    if (nbuckets == 0 || bloomSize == 0)
        return std::nullopt;

    const auto* bloom = reinterpret_cast<const uintptr_t*>(words + 4);
    const auto* buckets = reinterpret_cast<const uint32_t*>(bloom + bloomSize);
    const auto* chains = buckets + nbuckets;
    const uintptr_t bloomWord = bloom[(gnuHash / (sizeof(uintptr_t) * 8U)) % bloomSize];
    const uintptr_t mask = (uintptr_t{1} << (gnuHash % (sizeof(uintptr_t) * 8U))) |
                           (uintptr_t{1} << ((gnuHash >> bloomShift) % (sizeof(uintptr_t) * 8U)));
    if ((bloomWord & mask) != mask)
        return std::nullopt;

    uint32_t symbolIndex = buckets[gnuHash % nbuckets];
    if (symbolIndex < symoffset)
        return std::nullopt;

    for (;; ++symbolIndex) {
        const uint32_t chainHash = chains[symbolIndex - symoffset];
        if ((chainHash ^ gnuHash) < 2) {
            const auto& symbol = info.symtab[symbolIndex];
            const char* currentName = info.strtab + symbol.st_name;
            const size_t currentLen = std::strlen(currentName);
            if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
                return symbolIndex;
            }
        }
        if ((chainHash & 1U) != 0U)
            break;
    }
    return std::nullopt;
}

std::optional<uint32_t> FindRuntimeSymbolIndexWithSysvHash(const RuntimeDynamicInfo& info,
                                                           const uint8_t* name, size_t nameLen,
                                                           uint32_t elfHash) {
    if (info.hash == nullptr)
        return std::nullopt;
    const uint32_t nbucket = info.hash[0];
    const uint32_t nchain = info.hash[1];
    if (nbucket == 0 || nchain == 0)
        return std::nullopt;

    const auto* buckets = info.hash + 2;
    const auto* chains = buckets + nbucket;
    uint32_t idx = buckets[elfHash % nbucket];
    while (idx != 0 && idx < nchain) {
        const auto& sym = info.symtab[idx];
        const char* currentName = info.strtab + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return idx;
        }
        idx = chains[idx];
    }
    return std::nullopt;
}

std::optional<uint32_t> FindRuntimeSymbolIndexLinear(const RuntimeDynamicInfo& info,
                                                     const uint8_t* name, size_t nameLen) {
    size_t symbolCount = 0;
    if (info.hash != nullptr) {
        symbolCount = info.hash[1];
    } else if (info.gnuHash != nullptr) {
        const uint32_t nbuckets = info.gnuHash[0];
        const uint32_t symoffset = info.gnuHash[1];
        const uint32_t bloomSize = info.gnuHash[2];
        const auto* bloom = reinterpret_cast<const uintptr_t*>(info.gnuHash + 4);
        const auto* buckets = reinterpret_cast<const uint32_t*>(bloom + bloomSize);
        const auto* chains = buckets + nbuckets;
        uint32_t maxSymbol = symoffset;
        for (uint32_t i = 0; i < nbuckets; ++i) {
            if (buckets[i] > maxSymbol)
                maxSymbol = buckets[i];
        }
        if (maxSymbol == symoffset) {
            symbolCount = symoffset;
        } else {
            uint32_t chainIndex = maxSymbol - symoffset;
            while ((chains[chainIndex] & 1U) == 0U)
                ++chainIndex;
            symbolCount = symoffset + chainIndex + 1;
        }
    }
    if (symbolCount == 0)
        return std::nullopt;

    for (size_t i = 0; i < symbolCount; ++i) {
        const auto& sym = info.symtab[i];
        const char* currentName = info.strtab + sym.st_name;
        const size_t currentLen = std::strlen(currentName);
        if (nameLen == currentLen && std::memcmp(name, currentName, nameLen) == 0) {
            return static_cast<uint32_t>(i);
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> FindRuntimeSymbolIndex(const RuntimeDynamicInfo& info, const uint8_t* name,
                                               size_t nameLen) {
    const uint32_t gnuHash = ComputeGnuHash(name, nameLen);
    if (auto index = FindRuntimeSymbolIndexWithGnuHash(info, name, nameLen, gnuHash);
        index.has_value()) {
        return index;
    }

    const uint32_t elfHash = ComputeElfHash(name, nameLen);
    if (auto index = FindRuntimeSymbolIndexWithSysvHash(info, name, nameLen, elfHash);
        index.has_value()) {
        return index;
    }

    return FindRuntimeSymbolIndexLinear(info, name, nameLen);
}

// Relocation slot collector
// Finds all relocation slots matching a given symbol index.
// Original iterates 3 relocation table entries: (jmprel, rela, rel).
// Uses usesRela flag for jmprel, always rela for DT_RELA, always rel for DT_REL.
// Collects matching slot addresses into a vector.

#if defined(__LP64__)
static constexpr auto kRelocationTypeJumpSlot = static_cast<uint32_t>(R_AARCH64_JUMP_SLOT);
static constexpr auto kRelocationTypeGlobDat = static_cast<uint32_t>(R_AARCH64_GLOB_DAT);
static constexpr auto kRelocationTypeAbs = static_cast<uint32_t>(R_AARCH64_ABS64);
#else
static constexpr auto kRelocationTypeJumpSlot = static_cast<uint32_t>(R_ARM_JUMP_SLOT);
static constexpr auto kRelocationTypeGlobDat = static_cast<uint32_t>(R_ARM_GLOB_DAT);
static constexpr auto kRelocationTypeAbs = static_cast<uint32_t>(R_ARM_ABS32);
#endif

void CollectRelocationSlots(const MappedFile& file, uintptr_t relocAddress, size_t relocBytes,
                            bool rela, uint32_t targetSymIndex, uintptr_t loadBias,
                            std::vector<uintptr_t>& slots) {
    if (relocAddress == 0 || relocBytes == 0)
        return;
    const auto relocOffset = VirtualAddressToFileOffset(file, relocAddress);
    if (!relocOffset.has_value())
        return;

    const size_t entrySize = rela ? sizeof(ElfRelocationWithAddend) : sizeof(ElfRelocationNoAddend);
    const size_t count = relocBytes / entrySize;

    for (size_t i = 0; i < count; ++i) {
        uint64_t infoValue = 0;
        uintptr_t offsetValue = 0;
        if (rela) {
            const auto* r = reinterpret_cast<const ElfRelocationWithAddend*>(
                file.bytes() + *relocOffset + i * sizeof(ElfRelocationWithAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        } else {
            const auto* r = reinterpret_cast<const ElfRelocationNoAddend*>(
                file.bytes() + *relocOffset + i * sizeof(ElfRelocationNoAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        }

#if defined(__LP64__)
        const uint32_t relocationType = ELF64_R_TYPE(infoValue);
        const uint32_t symIndex = ELF64_R_SYM(infoValue);
#else
        const uint32_t relocationType = ELF32_R_TYPE(infoValue);
        const uint32_t symIndex = ELF32_R_SYM(infoValue);
#endif

        if (symIndex != targetSymIndex)
            continue;
        // Original accepts both JUMP_SLOT and GLOB_DAT for usesRela=true path,
        //   and JUMP_SLOT or ABS for usesRela=false.
        if (relocationType != kRelocationTypeJumpSlot && relocationType != kRelocationTypeGlobDat &&
            relocationType != kRelocationTypeAbs) {
            continue;
        }

        const uintptr_t slotAddr = offsetValue + loadBias;
        if (slotAddr <= loadBias)
            continue;  // sanity check matching original

        // Deduplicate
        bool found = false;
        for (const auto& existing : slots) {
            if (existing == slotAddr) {
                found = true;
                break;
            }
        }
        if (!found) {
            slots.push_back(slotAddr);
        }
    }
}

// Full relocation slot collection for a symbol index, across all 3 tables
std::vector<uintptr_t> FindRelocationSlotsForSymbol(const MappedFile& file, const DynamicInfo& info,
                                                    uint32_t symIndex, uintptr_t loadBias) {
    std::vector<uintptr_t> slots;

    // Table 1: JMPREL (uses DT_PLTREL to determine rela vs rel)
    CollectRelocationSlots(file, info.jmprel, info.pltrelSize, info.usesRela, symIndex, loadBias,
                           slots);
    // Table 2: DT_RELA
    CollectRelocationSlots(file, info.rela, info.relaSize, true, symIndex, loadBias, slots);
    // Table 3: DT_REL
    CollectRelocationSlots(file, info.rel, info.relSize, false, symIndex, loadBias, slots);
    return slots;
}

void CollectRuntimeRelocationSlots(uintptr_t relocAddress, size_t relocBytes, bool rela,
                                   uint32_t targetSymIndex, uintptr_t loadBias,
                                   std::vector<uintptr_t>& slots) {
    if (relocAddress == 0 || relocBytes == 0)
        return;

    const size_t entrySize = rela ? sizeof(ElfRelocationWithAddend) : sizeof(ElfRelocationNoAddend);
    const size_t count = relocBytes / entrySize;
    for (size_t i = 0; i < count; ++i) {
        uint64_t infoValue = 0;
        uintptr_t offsetValue = 0;
        if (rela) {
            const auto* r = reinterpret_cast<const ElfRelocationWithAddend*>(
                relocAddress + i * sizeof(ElfRelocationWithAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        } else {
            const auto* r = reinterpret_cast<const ElfRelocationNoAddend*>(
                relocAddress + i * sizeof(ElfRelocationNoAddend));
            infoValue = r->r_info;
            offsetValue = r->r_offset;
        }

#if defined(__LP64__)
        const uint32_t relocationType = ELF64_R_TYPE(infoValue);
        const uint32_t symIndex = ELF64_R_SYM(infoValue);
#else
        const uint32_t relocationType = ELF32_R_TYPE(infoValue);
        const uint32_t symIndex = ELF32_R_SYM(infoValue);
#endif

        if (symIndex != targetSymIndex)
            continue;
        if (relocationType != kRelocationTypeJumpSlot && relocationType != kRelocationTypeGlobDat &&
            relocationType != kRelocationTypeAbs) {
            continue;
        }

        const uintptr_t slotAddr = offsetValue + loadBias;
        bool found = false;
        for (const auto existing : slots) {
            if (existing == slotAddr) {
                found = true;
                break;
            }
        }
        if (!found) {
            slots.push_back(slotAddr);
        }
    }
}

std::vector<uintptr_t> FindRuntimeRelocationSlotsForSymbol(const RuntimeDynamicInfo& info,
                                                           uint32_t symIndex, uintptr_t loadBias) {
    std::vector<uintptr_t> slots;
    CollectRuntimeRelocationSlots(info.jmprel, info.pltrelSize, info.usesRela, symIndex, loadBias,
                                  slots);
    CollectRuntimeRelocationSlots(info.rela, info.relaSize, true, symIndex, loadBias, slots);
    CollectRuntimeRelocationSlots(info.rel, info.relSize, false, symIndex, loadBias, slots);
    return slots;
}

}  // namespace fusehide
