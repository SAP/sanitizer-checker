#ifndef SEMREP_METADATA_HPP
#define SEMREP_METADATA_HPP

#include <string>


class Metadata {

public:
    Metadata();

    bool set_field(std::string key, std::string value);

    std::string get_uuid() const;
    std::string get_sink() const;
    std::string get_source() const;
    int get_taint_range_index() const;
    int get_start_index() const;
    int get_end_index() const;
    bool is_initialized() const;
    void to_dot(std::stringstream &ss) const;
private:
    std::string uuid;
    std::string sink;
    std::string source;
    int taint_range_index;
    int start_index;
    int end_index;
    bool initialized;

};


#endif //SEMREP_METADATA_HPP
