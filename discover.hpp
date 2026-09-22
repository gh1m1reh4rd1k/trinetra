#ifndef DISCOVER_HPP
#define DISCOVER_HPP


#include <cstddef>
#include <string>
#include <vector>

namespace discover {

struct Country {
    const char* iso2;      
    const char* iso3;      
    const char* name;      
    const char* aliases;   
};

struct CountryMatch {
    enum class How { None, Exact, Prefix, Fuzzy };
    const Country*                country = nullptr;
    How                           how     = How::None;
    std::vector<const Country*>   suggestions;   
};

CountryMatch resolve_country(const std::string& input);
size_t country_count();

struct Options {
    std::string country;               
    bool        want_v4 = true;
    bool        want_v6 = true;
    int         connect_timeout_sec = 10;
    int         total_timeout_sec   = 60;
    bool        verbose = false;
    std::string output_file;           
    bool        owner = false;
    int         dns_timeout_ms  = 2000;   
    int         dns_concurrency = 64;      
    std::vector<std::string> dns_servers;  
};

int run(const Options& opts);

} 

#endif  
