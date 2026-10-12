#ifndef CODEGEN_X86_REDZONEFRAMER_HPP
#define CODEGEN_X86_REDZONEFRAMER_HPP

#include <codegen/CodegenTypes.hpp>
#include <domain/Types.hpp>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace Codegen {

struct RedZoneFrameReport {
    std::size_t Functions = 0;
    std::size_t RedZoneFunctions = 0;
    std::size_t Framed = 0;
    std::size_t Exits = 0;
    std::map<std::string, std::size_t> Skipped;
};

// Windows writes an exception frame directly below RSP, over the System V red zone. Gives leaf
// functions with a `push rbp; mov rbp, rsp; push ...` prologue that keep values below RSP a frame:
// RSP moves down by the red zone after the prologue and back before each `pop ...; pop rbp; ret`.
std::vector<TrampolineSite> FrameRedZoneFunctions(
    const std::vector<std::uint8_t>& fileBytes,
    const std::vector<Domain::ProgramHeader>& codeSegments,
    const std::vector<TrampolineSite>& existing,
    RedZoneFrameReport& report
);

}

#endif
