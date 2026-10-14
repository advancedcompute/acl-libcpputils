/*
 © Copyright 2025 Dominic Finch
*/

#pragma once

#include <fstream>
#include <istream>
#include <string>
#include <sstream>

#include <filesystem>
#include <json/json.h>
#include <zip.h>

namespace cpp { namespace utils {

    std::filesystem::path get_home_directory();

    std::filesystem::path resolve_path(const std::string& input);

    bool file_exists(const std::string& fpath);

    bool directory_exists(const std::string& fpath);

    bool create_directories(const std::string& fpath);

    bool delete_directories(const std::string& fpath);

    bool read_file_contents(const std::string& fpath, std::string& contents, std::ios_base::openmode mode = std::ios_base::in );

    bool write_file_contents(const std::string& fpath, const std::string& contents, std::ios_base::openmode mode = std::ios_base::out | std::ios_base::trunc );

    bool read_json_file(const std::string& fpath, Json::Value& contents, std::ios_base::openmode mode = std::ios_base::in );

    bool write_json_file(const std::string& fpath, const Json::Value& contents, std::ios_base::openmode mode = std::ios_base::out | std::ios_base::trunc );

    bool read_zip_file(const std::string& fpath, zip_t** archive);

    bool write_zip_file(const std::string& fpath, const zip_t** archive);

    bool extract_zip_file(zip_t* archive, const std::string& directory);

    bool create_zip_file(const std::string& directory, const std::string& fpath);

}}

