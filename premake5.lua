newoption {
   trigger = "ci-build",
   description = "CI build define"
}

function buildinfo()

    local versionfile = assert(io.open("release/version", "r"))
    local version = assert(versionfile:read())
    local versionid = assert(versionfile:read())
    versionfile:close()

    -- set version
    local file = assert(io.open("src/shared/actsinfo.hpp", "w"))
    file:write("#pragma once\n")
    file:write("namespace actsinfo {\n")
    file:write("    // Do not write in this file, it is updated by premake\n")
    file:write("#ifdef DEBUG\n\n")
    file:write("    constexpr const char* VERSION = \"Dev\";\n")
    file:write("    constexpr unsigned int VERSION_ID = 0xFFFFFFFF;\n")
    file:write("\n#else\n\n")
    file:write("    // Version used for the release\n")
    file:write("    constexpr const char* VERSION = \"" .. version .. "\";\n")
    file:write("    constexpr unsigned int VERSION_ID = 0x" .. versionid .. ";\n")
    file:write("\n#endif\n")
    file:write("}\n")
    file:close()

end

workspace "AtianCodTools"
    startproject "AtianCodTools"
    location "./build"
    configurations { 
        "Debug", 
        "Release" 
    }

    architecture "x86_64"
    platforms "x64"

    buildinfo()

    filter { "options:ci-build" }
        defines { "CI_BUILD" }
    
    filter "configurations:Debug"
        defines { "DEBUG" }
        symbols "On"

    filter "configurations:Release"
        defines { "NDEBUG" }
        optimize "Size"
        
    filter {} -- Reset filters

project "ACTSSharedLibrary"
    kind "StaticLib"
    language "C++"
    cppdialect "C++20"
    targetdir "%{wks.location}/bin/"
    objdir "%{wks.location}/obj/"

    targetname "actsshared"
    
    files {
        "./src/shared/**.hpp",
        "./src/shared/**.h",
        "./src/shared/**.cpp",
    }

    includedirs {
        "src/shared",
    }

    vpaths {
        ["*"] = "*"
    }

project "ACTS-BO4-DLL"
    kind "SharedLib"
    language "C++"
    cppdialect "C++20"
    targetdir "%{wks.location}/bin/"
    objdir "%{wks.location}/obj/"

    targetname "acts-bo4-dll"
    
    files {
        "./src/bo4-dll/**.hpp",
        "./src/bo4-dll/**.h",
        "./src/bo4-dll/**.cpp",
    }

    includedirs {
        "src/bo4-dll",
        "src/shared",
    -- link detours
		"deps/Detours/src/"
    }

    vpaths {
        ["*"] = "*"
    }
    
    links { "ACTSSharedLibrary" }
    links { "detours" }
    dependson "ACTSSharedLibrary"
    dependson "detours"

project "AtianCodTools"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++20"
    targetdir "%{wks.location}/bin/"
    objdir "%{wks.location}/obj/"

    targetname "acts"
    
    files {
        "./.github/workflows/**",
        "./src/cli/**.hpp",
        "./src/cli/**.h",
        "./src/cli/**.cpp",
        "./gsc/**.gsc",
        "./gsc/**.csc",
        "./grammar/**.g4",
        "./scripts/**.ps1",
        "./release/**",
        "./resources/**",
        ".gitignore",
        "premake5.lua",
        "packages.txt",
        "resolver.cfg",
        "gsc.conf",
        "LICENSE",
        "README.md"
    }

    includedirs {
        "src/cli",
        "src/shared",
    -- link antlr4
		"deps/antlr4/runtime/Cpp/runtime/src/",
		"deps/zlib/"
    }

    vpaths {
        ["*"] = "*"
    }

    defines { 
        "ANTLR4CPP_STATIC"
    }
    
    links { "antlr4-runtime" }
    links { "ACTSSharedLibrary" }
    links { "zlib" }
    dependson "antlr4-runtime"
    dependson "ACTSSharedLibrary"
    dependson "zlib"

group "deps"
    project "antlr4-runtime"
        language "C++"
        kind "StaticLib"
        cppdialect "C++20"
        warnings "Off"

        targetname "antlr4-runtime"
        targetdir "%{wks.location}/bin/"
        objdir "%{wks.location}/obj/"
        
        files {
            "deps/antlr4/runtime/Cpp/runtime/src/**.hpp",
            "deps/antlr4/runtime/Cpp/runtime/src/**.h",
            "deps/antlr4/runtime/Cpp/runtime/src/**.cpp",
        }

        includedirs {
            "deps/antlr4/runtime/Cpp/runtime/src/"
        }
        
        defines { 
            --"ANTLR4CPP_DLL", -- for SharedLib kind
            "ANTLR4CPP_STATIC"
        }
    project "detours"
        language "C++"
        kind "StaticLib"
        cppdialect "C++20"
        warnings "Off"

        targetname "detours"
        targetdir "%{wks.location}/bin/"
        objdir "%{wks.location}/obj/"
        
        files {
            "deps/Detours/src/detours.*",
            "deps/Detours/src/modules.*",
            "deps/Detours/src/disasm.*",
            "deps/Detours/src/image.*",
            "deps/Detours/src/creatwth.*",
            "deps/Detours/src/disolx86.*",
            "deps/Detours/src/disolx64.*",
            "deps/Detours/src/disolia64.*",
            "deps/Detours/src/disolarm.*",
            "deps/Detours/src/disolarm64.*"
        }

        includedirs {
            "deps/Detours/src/"
        }
    project "zlib"
        language "C"
        kind "StaticLib"
        warnings "Off"

        targetname "zlib"
        targetdir "%{wks.location}/bin/"
        objdir "%{wks.location}/obj/"
        
        files {
            "deps/zlib/*.c",
            "deps/zlib/*.h",
        }
