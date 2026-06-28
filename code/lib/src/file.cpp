/*
 © Copyright 2025 Dominic Finch
*/

#include "file.h"
#include <string>
#include <cstdlib>

#include <iostream>

namespace cpp { namespace utils {

    namespace fs = std::filesystem;

    fs::path get_home_directory() {
    #if defined(_WIN32)
        const char* home = std::getenv("USERPROFILE");
        if (home) return fs::path(home);

        const char* drive = std::getenv("HOMEDRIVE");
        const char* path  = std::getenv("HOMEPATH");
        if (drive && path)
            return fs::path(std::string(drive) + std::string(path));

        return fs::path(); // empty = failure
    #else
        const char* home = std::getenv("HOME");
        if (home) return fs::path(home);

        return fs::path();
    #endif
    }

    fs::path resolve_path(const std::string& input) {
        if (input.empty())
            return {};

        fs::path path(input);

        // Handle "~" and "~/..."
        if (input[0] == '~') {
            fs::path home = get_home_directory();
            if (home.empty())
                throw std::runtime_error("Unable to resolve home directory");

            if (input.size() == 1) {
                return home;
            }

            if (input[1] == '/' || input[1] == '\\') {
                return home / input.substr(2);
            }

            // Optional: handle ~username (not implemented)
            throw std::runtime_error("~username not supported");
        }

        return path;
    }

    fs::path full_resolve_path(const std::string& input)
    {
        fs::path p = resolve_path(input);

        if (p.is_relative()) {
            p = fs::current_path() / p;
        }

        return fs::weakly_canonical(p);
    }

    bool file_exists(const std::string& fpath) {
        auto full_fpath = full_resolve_path(fpath);
        return fs::exists(full_fpath) && (fs::is_regular_file(full_fpath) || fs::is_character_file(full_fpath));
    }

    bool directory_exists(const std::string& fpath) {
        auto full_fpath = full_resolve_path(fpath);
        return fs::exists( full_fpath ) && fs::is_directory( full_fpath );
    }

    bool create_directories(const std::string& fpath)
    {
        auto path = full_resolve_path(fpath);
        if ( !fs::exists(path) && !(fs::is_regular_file(path) || fs::is_character_file(path))  )
        {
            return fs::create_directories(path);
        } else if ( fs::exists(path) && fs::is_regular_file(path) || fs::is_character_file(path)  )
        {
            return fs::create_directories(path.parent_path());
        }
        return false;
    }

    bool delete_directories(const std::string& fpath) {
        auto path = full_resolve_path(fpath);
        return fs::remove_all(path);
    }

    bool read_file_contents(const std::string& fpath, std::string& contents, std::ios_base::openmode mode) {
        //std::fstream fs;
        std::ifstream istream;
        std::stringstream ss;

        auto full_path = full_resolve_path(fpath);
        istream.open(full_path, mode);

        if(!istream.good())
            return false;

        ss << istream.rdbuf();
        istream.close();

        contents = ss.str();
        return true;
    }

    bool write_file_contents(const std::string& fpath, const std::string& contents, std::ios_base::openmode mode ) {
        std::ofstream ostream;

        auto full_path = full_resolve_path(fpath);
        ostream.open(full_path, mode);

        if(!ostream.good())
            return false;

        ostream << contents;

        ostream.close();
        return true;
    }

    bool read_json_file(const std::string& fpath, Json::Value& contents, std::ios_base::openmode mode)
    {
        bool success = false;
        std::string fileContentStr;

        if(read_file_contents(fpath, fileContentStr, mode))
        {
            Json::CharReaderBuilder rbuilder;
            Json::CharReader * reader = rbuilder.newCharReader();
            std::string parseErrors;        // Note: this var is thrown away

            if(reader->parse(fileContentStr.data(), fileContentStr.data() + fileContentStr.size(),
                &contents, &parseErrors))
            {
                success = true;
            }
            delete reader;
        }
        return success;
    }

    bool write_json_file(const std::string& fpath, const Json::Value& contents, std::ios_base::openmode mode)
    {
        // Open output file stream with specified mode
        std::ofstream ofs(fpath, mode);
        if (!ofs.is_open()) {
            //std::cerr << "Error: Could not open file for writing: " << fpath << std::endl;
            return false;
        }

        try {
            // Configure writer for pretty output
            Json::StreamWriterBuilder writerBuilder;
            writerBuilder["indentation"] = "  "; // 2 spaces for readability
            std::unique_ptr<Json::StreamWriter> writer(writerBuilder.newStreamWriter());

            // Write JSON data to file
            writer->write(contents, &ofs);
            ofs.close();
        } catch (const std::exception& e) {
            //std::cerr << "Error while writing JSON to file: " << e.what() << std::endl;
            return false;
        }

        return true;
    }

}}
