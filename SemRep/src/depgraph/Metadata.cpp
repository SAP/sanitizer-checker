#include "Metadata.hpp"
#include <iostream>
#include <sstream>

namespace {
    Exploit_Method method_of_string(const std::string &method) {
        if (method == "A") {
            return A;
        } if (method == "B") {
            return B;
        } if (method == "C") {
            return C;
        }
        return Unknown;

    }
    Exploit_Status status_of_string(const std::string &status) {
        if (status == "validated") {
            return Validated;
        } if (status == "in_validation") {
            return In_Validation;
        }
        return Error;

    }

    Exploit_Type type_of_string(const std::string &type) {
        if (type == "html") {
            return Html;
        }
        if (type == "js") {
            return JavaScript;
        }
        return Undefined;
    }

    bool bool_of_string(const std::string& value) {
        return value == "true";
    }
}
Metadata::Metadata() : uuid(), url(), sink(), source(), taint_range_index(0), start_index(0), end_index(0), initialized(false), exploit_method(Unknown), exploit_status(Error), exploit_type(Undefined), hash(0) {

}

std::string Metadata::get_uuid() const {
    return this->uuid;
}

std::string Metadata::get_url() const {
    return this->url;
}

std::string Metadata::get_sink() const {
    return this->sink;
}

std::string Metadata::get_source() const {
    return this->source;
}

int Metadata::get_taint_range_index() const {
    return this->taint_range_index;
}

int Metadata::get_start_index() const {
    return this->start_index;
}


int Metadata::get_end_index() const {
    return this->end_index;
}


bool Metadata::is_initialized() const {
    return this->initialized;
}

bool Metadata::set_field(std::string key, std::string value) {
    if(key == "Finding") {
        this->initialized = true;
        this->uuid = value;
        return true;
    }
    if(key == "Finding.url") {
        this->initialized = true;
        this->url = value;
        return true;
    }
    if(key == "Finding.sink") {
        this->initialized = true;
        this->sink = value;
        return true;
    }
    if(key == "Finding.source") {
        this->initialized = true;
        this->source = value;
        return true;
    }
    if(key == "Finding.begin") {
        this->start_index = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Finding.end") {
        this->end_index = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Finding.script") {
        this->initialized = true;
        this->script = value;
        return true;
    }
    if(key == "Finding.line") {
        this->line = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Finding.original_uuid") {
        this->original_uuid = value;
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.uuid") {
        this->exploit_uuid = value;
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.success") {
        this->exploit_success = ::bool_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.method") {
        this->exploit_method = ::method_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.status") {
        this->exploit_status = ::status_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.type") {
        this->exploit_type = ::type_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "DepGraph.hash") {
        this->hash = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.token") {
        this->exploit_token = value;
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.content") {
        this->exploit_content = value;
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.tag") {
        this->exploit_tag = value;
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.quote_type") {
        this->exploit_quote_type = value;
        this->initialized = true;
        return true;
    }
    std::cout << "key value pair: (" << key << ", " << value << ") unknown!\n";
    return false;

}

void Metadata::to_dot(std::stringstream &ss) const {
    ss << "// Finding: " << this->uuid << "\n";
    ss << "// Finding.url: " << this->url << "\n";
    ss << "// Finding.sink: " << this->sink << "\n";
    ss << "// Finding.source: " << this->source << "\n";
    ss << "// Finding.begin: " << this->start_index << "\n";
    ss << "// Finding.end: " << this->end_index << "\n";
    ss << "// Finding.original_uuid: " << this->original_uuid << "\n";
    ss << "// Finding.script: " << this->script << "\n";
    ss << "// Finding.line: " << this->line << "\n";

}

const std::string &Metadata::get_exploit_uuid() const {
    return exploit_uuid;
}

bool Metadata::is_exploit_successful() const {
    return exploit_success;
}

Exploit_Method Metadata::get_exploit_method() const {
    return exploit_method;
}

Exploit_Status Metadata::get_exploit_status() const {
    return exploit_status;
}

Exploit_Type Metadata::get_exploit_type() const {
    return exploit_type;
}

const std::string &Metadata::get_exploit_content() const {
    return exploit_content;
}

const std::string &Metadata::get_exploit_token() const {
    return exploit_token;
}

const std::string &Metadata::get_exploit_tag() const {
    return exploit_tag;
}

const std::string &Metadata::get_exploit_quote_type() const {
    return exploit_quote_type;
}

int Metadata::get_hash() const {
    return this->hash;
}

const std::string &Metadata::get_script() const {
    return this->script;
}

int Metadata::get_line() const {
    return this->line;
}

const std::string Metadata::get_original_uuid() const {
    return this->original_uuid;
}
