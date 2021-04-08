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

    bool set_field(const std::string& key, const std::string& value);

    std::string get_uuid() const;
    std::string get_url() const;
    std::string get_sink() const;
    std::string get_source() const;
    int get_taint_range_index() const;
    int get_start_index() const;
    int get_end_index() const;
    bool has_valid_exploit() const;
    const std::string &get_exploit_uuid() const;

    std::string get_break_out() const;
    std::string get_break_in() const;
    std::string get_payload() const;

    bool is_exploit_successful() const;

    Exploit_Method get_exploit_method() const;

    Exploit_Status get_exploit_status() const;

    Exploit_Type get_exploit_type() const;

    const std::string &get_exploit_content() const;

    const std::string &get_exploit_token() const;

    const std::string &get_exploit_tag() const;

    const std::string &get_exploit_quote_type() const;

    const std::string& get_script() const;
    int get_line() const;

    std::string get_original_uuid() const;
    std::string get_domain() const;
    int get_twenty_five_million_flows_id() const;
    int get_sanitizer_hash() const;
    int get_hash() const;
    bool is_initialized() const;

    void to_dot(std::stringstream &ss) const;
private:
    std::string uuid;
    std::string url;
    std::string sink;
    std::string source;
    int taint_range_index;
    int start_index;
    int hash;
    int sanitizer_hash;
    int twenty_five_million_flows_id;
    int end_index;
    bool initialized;
    std::string exploit_uuid;
    std::string original_uuid;
    std::string script;
    std::string domain;
    int line{};
    bool exploit_success{};
    Exploit_Method exploit_method;
    Exploit_Status exploit_status;
    Exploit_Type exploit_type;
    std::string exploit_content;
    std::string exploit_token;
    std::string exploit_tag;
    std::string exploit_quote_type;
    std::string break_out;
    std::string break_in;
    std::string payload;
    bool valid_exploit{};
};


#endif //SEMREP_METADATA_HPP
