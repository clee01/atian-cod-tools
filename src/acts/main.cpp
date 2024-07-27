#include <includes.hpp>
#include "hashutils.hpp"
#include "compatibility/scobalula_wni.hpp"
#include "actscli.hpp"
#include "hook/error.hpp"
#include "actslib/logging.hpp"
#include "acts.hpp"
#include "main_ui.hpp"
#include "config.hpp"
#include <Windows.h>
#include "auth.hpp"
#include <string>
#include "key_auth_utils.hpp"
#include "skStr.h"

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

using namespace KeyAuth;

namespace {
	inline bool ShouldHandleACTSOptions(int argc, const char* argv[]) {
		return argc > 1 && argv[1][0] == '-'; // at least one param
	}

	bool HandleACTSOptions(int argc, const char* argv[], std::vector<const char*>& newData) {
		assert(argc > 0);
		newData.reserve((size_t)argc - 1); // remove start because we know we have at least one param
		newData.push_back(argv[0]);

		auto& opt = actscli::options();
		size_t i = 1;
		for (; i < argc; i++) {
			const char* arg = argv[i];
			if (*arg != '-') {
				break; // end of acts params
			}
			if (!strcmp("-?", arg) || !_strcmpi("--help", arg) || !strcmp("-h", arg)) {
				opt.showHelp = true;
			}
			else if (!strcmp("-t", arg) || !_strcmpi("--no-title", arg)) {
				opt.showTitle = false;
			}
			else if (!strcmp("-T", arg) || !_strcmpi("--no-treyarch", arg)) {
				opt.noTreyarchHash = true;
			}
			else if (!strcmp("-I", arg) || !_strcmpi("--no-iw", arg)) {
				opt.noIWHash = true;
			}
			else if (!strcmp("-N", arg) || !_strcmpi("--no-hash", arg)) {
				opt.noDefaultHash = true;
			}
			else if (!_strcmpi("--hash0", arg)) {
				opt.show0Hash = true;
			}
			else if (!strcmp("-d", arg) || !_strcmpi("--debug", arg)) {
				hook::error::EnableHeavyDump();
			}
			else if (!strcmp("-s", arg) || !_strcmpi("--strings", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				opt.defaultHashFile = argv[++i];
			}
			else if (!strcmp("-l", arg) || !_strcmpi("--log", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				auto* val = argv[++i];

				if (!val[0] || val[1]) {
					LOG_ERROR("Invalid log value for param: {}/{}", arg, val);
					return false;
				}

				switch (*val) {
				case 't':
				case 'T':
					alogs::setlevel(alogs::LVL_TRACE);
					actslib::logging::SetLevel(actslib::logging::LEVEL_TRACE);
					break;
				case 'd':
				case 'D':
					alogs::setlevel(alogs::LVL_DEBUG);
					actslib::logging::SetLevel(actslib::logging::LEVEL_DEBUG);
					break;
				case 'i':
				case 'I':
					alogs::setlevel(alogs::LVL_INFO);
					actslib::logging::SetLevel(actslib::logging::LEVEL_INFO);
					break;
				case 'w':
				case 'W':
					alogs::setlevel(alogs::LVL_WARNING);
					actslib::logging::SetLevel(actslib::logging::LEVEL_WARNING);
					break;
				case 'e':
				case 'E':
					alogs::setlevel(alogs::LVL_ERROR);
					actslib::logging::SetLevel(actslib::logging::LEVEL_ERROR);
					break;
				default:
					LOG_ERROR("Invalid log value for param: {}/{}", arg, val);
					return false;
				}
				alogs::setbasiclog(false);
				actslib::logging::SetBasicLog(false);
			}
			else if (!strcmp("-L", arg) || !_strcmpi("--log-file", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				alogs::setbasiclog(false);
				actslib::logging::SetBasicLog(false);
				alogs::setfile(argv[++i]);
				actslib::logging::SetLogFile(argv[i]);
			}
			else if (!_strcmpi("--mark-hash", arg)) {
				opt.markHash = true;
			}
			else if (!strcmp("-x", arg) || !_strcmpi("--extracted", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				opt.dumpHashmap = argv[++i];
			}
			else if (!strcmp("-p", arg) || !_strcmpi("--pack", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				opt.packFile = argv[++i];
			}
			else if (!strcmp("-P", arg) || !_strcmpi("--profiler", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				opt.saveProfiler = argv[++i];
			}
			else if (!strcmp("-w", arg) || !_strcmpi("--wni-files", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				opt.wniFiles = argv[++i];
			}
			else if (!strcmp("-D", arg) || !_strcmpi("--db2-files", arg)) {
				if (i + 1 == argc) {
					LOG_ERROR("Missing value for param: {}!", arg);
					return false;
				}
				opt.seriousDBFile = argv[++i];
			}
			else if (!strcmp("-H", arg) || !_strcmpi("--no-install", arg)) {
				opt.installDirHashes = false;
			}
			else {
				LOG_ERROR("Unknown acts option: {}!", arg);
				return false;
			}
		}

		// add end params
		for (; i < argc; i++) {
			newData.push_back(argv[i]);
		}

		newData.shrink_to_fit();

		return true;
	}

	void PrintACTSHelp(const char* argv0) {
		LOG_INFO("Usage: {} (OPTIONS) [TOOL] (TOOL ARGS)", argv0);
		LOG_INFO("General tools:");
		LOG_INFO("- list (category) : list the tools");
		LOG_INFO("- search (query)  : search for a tool");
		LOG_INFO("");
		LOG_INFO("Options:");
		LOG_INFO(" -? --help -h       : Help");
		LOG_INFO(" -l --log [l]       : Set log level t(race)/d(ebug)/i(nfo)/w(arn)/e(rror), default: i");
		LOG_INFO(" -L --log-file [f]  : Set the log file");
		LOG_INFO(" -d --debug         : Enable debug mode");
		LOG_INFO(" -x --extracted [f] : Write the extracted hashes into a file after the process");
		LOG_INFO(" -t --no-title      : Hide ACTS title at start");
		LOG_INFO(" -p --pack [f]      : Load ACTS pack file");
		LOG_INFO(" -P --profiler [f]  : Save profiler file after tool usage");
		LOG_INFO(" -N --no-hash       : No default hash");
		LOG_INFO(" -H --no-install    : No install hashes");
		LOG_INFO(" -T --no-treyarch   : No Treyarch hash (ignored with -N)");
		LOG_INFO(" -I --no-iw         : No IW hash (ignored with -N)");
		LOG_INFO(" -s --strings [f]   : Set default hash file, default: '{}' (ignored with -N)", hashutils::DEFAULT_HASH_FILE);
		LOG_INFO(" -D --db2-files [f] : Load DB2 files at start, default: '{}'", compatibility::scobalula::wni::packageIndexDir);
		LOG_INFO(" -w --wni-files [f] : Load WNI files at start, default: '{}'", compatibility::scobalula::wni::packageIndexDir);
		LOG_INFO(" --hash0            : Use \"hash_0\" instead of \"\" during lookup");
		LOG_INFO("--mark-hash         : Mark the hash default value");
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	return TRUE; // ignore
}

int MainActs(int argc, const char* _argv[], HINSTANCE hInstance, int nShowCmd) {
	// Key Auth Begin
	// Freeing memory to prevent memory leak or memory scraping
	std::string name = skCrypt("name").decrypt();
	std::string ownerid = skCrypt("ownerid").decrypt();
	std::string secret = skCrypt("secret").decrypt();
	std::string version = skCrypt("1.0").decrypt();
	std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
	std::string path = skCrypt("").decrypt(); //optional, set a path if you're using the token validation setting

	api KeyAuthApp(name, ownerid, secret, version, url, path);

    name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");
    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    if (std::filesystem::exists("test.json")) //change test.txt to the path of your file :smile:
    {
        if (!CheckIfJsonKeyExists("test.json", "username"))
        {
            std::string key = ReadFromJson("test.json", "license");
            KeyAuthApp.license(key);
            if (!KeyAuthApp.response.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
        else
        {
            std::string username = ReadFromJson("test.json", "username");
            std::string password = ReadFromJson("test.json", "password");
            KeyAuthApp.login(username, password);
            if (!KeyAuthApp.response.success)
            {
                std::remove("test.json");
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                Sleep(1500);
                exit(1);
            }
            std::cout << skCrypt("\n\n Successfully Automatically Logged In\n");
        }
    }
    else
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

        int option;
        std::string username;
        std::string password;
        std::string key;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password);
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        case 3:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.upgrade(username, key);
            break;
        case 4:
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.license(key);
            break;
        default:
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            Sleep(3000);
            exit(1);
        }

        if (!KeyAuthApp.response.success)
        {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
            Sleep(1500);
            exit(1);
        }
        if (username.empty() || password.empty())
        {
            WriteToJson("test.json", "license", key, false, "", "");
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }
        else
        {
            WriteToJson("test.json", "username", username, true, "password", password);
            std::cout << skCrypt("Successfully Created File For Auto Login");
        }


    }

    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << KeyAuthApp.user_data.username;
    std::cout << skCrypt("\n IP address: ") << KeyAuthApp.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << KeyAuthApp.user_data.hwid;
    std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.user_data.createdate)));
    std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.user_data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (int i = 0; i < KeyAuthApp.user_data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
    }

    std::cout << skCrypt("\n\n Closing in five seconds...");
    Sleep(5000);
	// Key Auth End

	bool cli{ hInstance == nullptr };
	auto& profiler = actscli::GetProfiler();

	acts::config::SyncConfig();

	// by default we don't display heavy logs in cli

	if (cli) {
		alogs::setbasiclog(true);
		actslib::logging::SetBasicLog(true);
	} else {
		static std::string uiLogs = [] {
			std::filesystem::path path{ utils::GetProgDir() / "acts-ui.log" };
			return path.string();
		}();
		alogs::setfile(uiLogs.data());
		actslib::logging::SetLogFile(uiLogs.data());

		std::string logLevel = acts::config::GetString("ui.logLevel", "INFO");

		if (logLevel != "INFO") {
			if (logLevel == "DEBUG") {
				alogs::setlevel(alogs::LVL_DEBUG);
				actslib::logging::SetLevel(actslib::logging::LEVEL_DEBUG);
			}
			else if (logLevel == "TRACE") {
				alogs::setlevel(alogs::LVL_TRACE);
				actslib::logging::SetLevel(actslib::logging::LEVEL_TRACE);
			}
			else if (logLevel == "ERROR") {
				alogs::setlevel(alogs::LVL_ERROR);
				actslib::logging::SetLevel(actslib::logging::LEVEL_ERROR);
			}
			else if (logLevel == "WARNING") {
				alogs::setlevel(alogs::LVL_WARNING);
				actslib::logging::SetLevel(actslib::logging::LEVEL_WARNING);
			}
		}
	}

	const char** argv;
	if (ShouldHandleACTSOptions(argc, _argv)) {
		static std::vector<const char*> newargv{};
		if (HandleACTSOptions(argc, _argv, newargv)) {
			argv = newargv.data();
			argc = (int)newargv.size();
		}
		else {
			return -1;
		}
	}
	else {
		argv = _argv;
	}
	hook::error::InstallErrorHooks();

	auto& opt = actscli::options();

	if (opt.showTitle && !hInstance) {
		LOG_INFO("Atian tools {} {}", actsinfo::VERSION, (cli ? "CLI" : "UI"));
	}

	if (opt.showHelp || argc == 1) {
		PrintACTSHelp(argv[0]);
		return 0;
	}

	std::filesystem::path packFilePath;

	if (opt.packFile) {
		packFilePath = opt.packFile;
	}
	else {
		packFilePath = utils::GetProgDir() / compatibility::scobalula::wni::packageIndexDir;
	}

	std::vector<std::filesystem::path> packFiles{};

	utils::GetFileRecurse(packFilePath, packFiles, [](const std::filesystem::path& p) {
		auto s = p.string();
		return s.ends_with(".acpf");
	});

	for (const auto& acpf : packFiles) {
		if (!actscli::LoadPackFile(acpf)) {
			LOG_ERROR("Error when loading ACTS pack file {}", acpf.string());
			return -1;
		}
	}

	if (hInstance) {
		hashutils::ReadDefaultFile();
		return tool::ui::MainActsUI(hInstance, nShowCmd); // no tool to run, life's easier if I put that here
	}

	const auto& tool = tool::findtool(argv[1]);

	if (!tool) {
		LOG_ERROR("Error: Bad tool name. {} list for the tools list", *argv);
		bool find{};
		const char* query[]{ argv[1] };
		tool::search(query, 1, [&find](const tool::toolfunctiondata* tool) {
			if (!find) {
				LOG_INFO("Similar tool name(s):");
				find = true;
			}
			LOG_INFO("- {}", tool->m_name);
		});

		return -1;
	}

	Process proc(tool.m_game);

	if (tool.m_game) {

		if (!proc) {
			LOG_ERROR("Can't find game process: {}", utils::WStrToStr(tool.m_game));
			return -1;
		}
		LOG_INFO("Find process {} {}", utils::WStrToStr(tool.m_game), proc);

		if (!proc.Open()) {
			LOG_ERROR("Can't open game process: 0x{:x}", GetLastError());
			return -1;
		}
	}

	hashutils::SaveExtracted(opt.dumpHashmap != nullptr);

	const clock_t beginTime = clock();

	int output;
	{
		actslib::profiler::ProfiledSection ps{ profiler, tool.m_name ? tool.m_name : "no-tool-name" };
#ifndef DEBUG
		try {
#endif
			output = tool.m_func(proc, argc, argv);
#ifndef DEBUG
		}
		catch (std::exception& e) {
			LOG_ERROR("Unhandled exception: {}", e.what());
			output = tool::BASIC_ERROR;
		}
#endif
	}

	LOG_TRACE("Tool took {}s to run with output {}{}", (double)(clock() - beginTime) / CLOCKS_PER_SEC, output, 
		(output == tool::OK ? " (OK)" : output == tool::BAD_USAGE ? " (BAD_USAGE)" : output == tool::BASIC_ERROR ? " (BASIC_ERROR)" : "")
	);

	hashutils::WriteExtracted(opt.dumpHashmap);

	if (output == tool::BAD_USAGE) {
		LOG_ERROR("Error: Bad tool usage: {} {} {}", *argv, argv[1], tool.m_usage);
	}

	if (opt.saveProfiler) {
		std::ofstream pout{ opt.saveProfiler, std::ios::binary };
		if (!pout) {
			LOG_ERROR("Can't open profiler output {}", opt.saveProfiler);
		}
		else {
			profiler.Stop();
			profiler.Write(pout);
			pout.close();
			LOG_INFO("Profiling saved into {}", opt.saveProfiler);
		}
	}

	return output;
}

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}


