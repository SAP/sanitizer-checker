#ifndef SEMREP_METADATA_HPP
#define SEMREP_METADATA_HPP

#include <string>

enum Exploit_Method {
    A,
    B,
    C,
    Unknown
};

enum Exploit_Status {
    Validated,
    In_Validation,
    Error
};

enum Exploit_Type {
    Html,
    Attribute,
    JavaScript,
    Undefined
};

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
    const std::string &get_exploit_uuid() const;

    bool is_exploit_successful() const;

    Exploit_Method get_exploit_method() const;

    Exploit_Status get_exploit_status() const;

    Exploit_Type get_exploit_type() const;

    const std::string &get_exploit_content() const;

    const std::string &get_exploit_token() const;

    const std::string &get_exploit_tag() const;

    const std::string &get_exploit_quote_type() const;

    int get_hash() const;
    bool is_initialized() const;

    void to_dot(std::stringstream &ss) const;
private:
    std::string uuid;
    std::string sink;
    std::string source;
    int taint_range_index;
    int start_index;
    int hash;
    int end_index;
    bool initialized;
    std::string exploit_uuid;
    bool exploit_success{};
    Exploit_Method exploit_method;
    Exploit_Status exploit_status;
    Exploit_Type exploit_type;
    std::string exploit_content;
    std::string exploit_token;
    std::string exploit_tag;
    std::string exploit_quote_type;
};


#endif //SEMREP_METADATA_HPP
