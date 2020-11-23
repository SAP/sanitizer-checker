#include "Metadata.hpp"
#include <iostream>
#include <sstream>

Metadata::Metadata() : uuid(), sink(), source(), taint_range_index(0), start_index(0), end_index(0), initialized(false) {

}

std::string Metadata::get_uuid() const {
    return this->uuid;
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

    std::cout << "key value pair: (" << key << ", " << value << ") unknown!\n";
    return false;

}

void Metadata::to_dot(std::stringstream &ss) const {
    ss << "// Finding: " << this->uuid << "\n";
    ss << "// Finding.sink: " << this->sink << "\n";
    ss << "// Finding.source: " << this->source << "\n";
    ss << "// Finding.begin: " << this->start_index << "\n";
    ss << "// Finding.end: " << this->end_index << "\n";
}
