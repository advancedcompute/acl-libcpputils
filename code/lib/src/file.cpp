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

    bool file_exists(const std::string& fpath) {
        auto path = resolve_path(fpath);
        return fs::exists(path) &&
            (fs::is_regular_file(path) || fs::is_character_file(path));
    }

    bool directory_exists(const std::string& fpath) {
        auto full_fpath = resolve_path(fpath);
        return fs::exists( full_fpath ) && fs::is_directory( full_fpath );
    }

    bool create_directories(const std::string& fpath)
    {
        auto full_fpath = resolve_path(fpath);
        try {
            if(fs::exists(full_fpath)) {
                if(fs::is_directory(full_fpath)) return true;
            } else
                return fs::create_directories(full_fpath);
        } catch(std::exception& ex) {
            puts(ex.what());
        }
        return false;
    }

    bool delete_directories(const std::string& fpath) {
        auto path = resolve_path(fpath);
        return fs::remove_all(path);
    }

    bool read_file_contents(const std::string& fpath, std::string& contents, std::ios_base::openmode mode) {
        //std::fstream fs;
        std::ifstream istream;
        std::stringstream ss;

        auto full_path = resolve_path(fpath);
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

        auto full_path = resolve_path(fpath);
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

        auto full_path = resolve_path(fpath);
        if(read_file_contents(full_path, fileContentStr, mode))
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
        auto full_path = resolve_path(fpath);
        std::ofstream ofs(full_path, mode);
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

    bool read_zip_file(const std::string& fpath, zip_t** archive)
    {
        if (!archive)
            return false;

        *archive = nullptr;

        auto full_path = resolve_path(fpath);

        int error = 0;
        *archive = zip_open(full_path.string().c_str(), ZIP_RDONLY, &error);

        return *archive != nullptr;
    }

    bool write_zip_file(const std::string& fpath, zip_t* archive)
    {
        if (!archive)
            return false;

        auto full_path = resolve_path(fpath);

        // Save the archive to the requested path.
        // Note: zip_open() should normally be used to create the archive,
        // rather than constructing an archive entirely in memory.
        int error = 0;
        zip_t* output = zip_open(full_path.string().c_str(),
                                ZIP_CREATE | ZIP_TRUNCATE,
                                &error);

        if (!output)
            return false;

        // Copy entries from archive to output.
        zip_int64_t num_entries = zip_get_num_entries(archive, 0);

        for (zip_uint64_t i = 0; i < static_cast<zip_uint64_t>(num_entries); ++i)
        {
            zip_source_t* source =
                zip_source_zip(output, archive, i, 0, 0, 0);

            if (!source || zip_file_add(output, zip_get_name(archive, i, 0),
                                        source, ZIP_FL_ENC_GUESS) < 0)
            {
                if (source)
                    zip_source_free(source);

                zip_discard(output);
                return false;
            }
        }

        return zip_close(output) == 0;
    }

    bool extract_zip_file(zip_t* archive, const std::string& directory)
    {
        if (!archive)
            return false;

        fs::path output_dir = resolve_path(directory);

        try {
            fs::create_directories(output_dir);

            zip_int64_t count = zip_get_num_entries(archive, 0);

            for (zip_uint64_t i = 0; i < static_cast<zip_uint64_t>(count); ++i)
            {
                zip_stat_t stat;
                zip_stat_init(&stat);

                if (zip_stat_index(archive, i, 0, &stat) < 0)
                    return false;

                fs::path output_path = output_dir / stat.name;

                // Directory entry
                if (stat.name && stat.size == 0 &&
                    stat.name[std::strlen(stat.name) - 1] == '/')
                {
                    fs::create_directories(output_path);
                    continue;
                }

                // Make sure parent directories exist
                fs::create_directories(output_path.parent_path());

                zip_file_t* file = zip_fopen_index(archive, i, 0);
                if (!file)
                    return false;

                std::ofstream output(output_path, std::ios::binary);
                if (!output)
                {
                    zip_fclose(file);
                    return false;
                }

                char buffer[8192];
                zip_int64_t bytes_read;

                while ((bytes_read = zip_fread(file, buffer, sizeof(buffer))) > 0)
                {
                    output.write(buffer, bytes_read);

                    if (!output)
                    {
                        zip_fclose(file);
                        return false;
                    }
                }

                zip_fclose(file);

                if (bytes_read < 0)
                    return false;
            }
        }
        catch (const std::exception&)
        {
            return false;
        }

        return true;
    }


    bool create_zip_file(const std::string& directory, const std::string& fpath)
    {
        fs::path input_dir = resolve_path(directory);
        fs::path output_file = resolve_path(fpath);

        int error = 0;
        zip_t* archive = zip_open(
            output_file.string().c_str(),
            ZIP_CREATE | ZIP_TRUNCATE,
            &error
        );

        if (!archive)
            return false;

        try {
            for (const auto& entry : fs::recursive_directory_iterator(input_dir))
            {
                if (!entry.is_regular_file())
                    continue;

                // Path inside the ZIP, relative to the input directory
                fs::path relative = fs::relative(entry.path(), input_dir);

                zip_source_t* source = zip_source_file(
                    archive,
                    entry.path().string().c_str(),
                    0,
                    0
                );

                if (!source)
                {
                    zip_discard(archive);
                    return false;
                }

                if (zip_file_add(
                        archive,
                        relative.generic_string().c_str(),
                        source,
                        ZIP_FL_ENC_UTF_8) < 0)
                {
                    zip_source_free(source);
                    zip_discard(archive);
                    return false;
                }
            }
        }
        catch (const std::exception&)
        {
            zip_discard(archive);
            return false;
        }

        return zip_close(archive) == 0;
    }

}}
