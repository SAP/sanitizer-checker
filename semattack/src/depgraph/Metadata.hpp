/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * Metadata.hpp
 *
 * Copyright (C) 2020 SAP SE
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the  Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335,
 * USA.
 *
 * Authors: Thomas Barber
 */


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
    // This is just needed to stop the csv output from breaking
    std::string get_comma_escaped_url() const;
    std::string get_sink() const;
    std::string get_source() const;
    int get_sanitizer_score() const;
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
    std::string get_base_domain() const;
    std::string get_parent_loc() const;
    std::string get_sanitizer_name() const;
    std::string get_sanitizer_location() const;
    int get_twenty_five_million_flows_id() const;
    int get_sanitizer_hash() const;
    int get_hash() const;
    int get_begin_taint_url() const;
    int get_end_taint_url() const;
    int get_replace_begin_url() const;
    int get_replace_end_url() const;
    int get_replace_begin_param() const;
    int get_replace_end_param() const;
    int get_max_encode_attr_chain_length() const;
    int get_max_encode_text_fragment_chain_length() const;
    bool has_approximated_method() const;
    bool has_unsupported_method() const;
    bool has_infinite_regex() const;
    bool has_url_on_rhs_of_replace() const;
    bool has_url_on_lhs_of_replace() const;
    bool has_url_in_match_pattern() const;
    bool has_url_in_exec_pattern() const;
    bool has_removed_lr_concats() const;
    bool has_removed_replace_artifacts() const;
    bool has_matching_error() const;
    bool has_cookie_value_in_match_pattern() const;
    bool has_cookie_value_in_exec_pattern() const;
    bool has_cookie_value_on_lhs_of_replace() const;
    bool has_cookie_value_on_rhs_of_replace() const;
    bool is_initialized() const;

    bool has_correct_exploit_match() const;

    void to_dot(std::stringstream &ss) const;

    std::string generate_exploit_from_scratch() const;
    std::string generate_exploit_from_scratch(const std::string& function, bool solidus) const;
    std::string generate_attribute_exploit_from_scratch() const;
    std::string generate_attribute_exploit_from_scratch(const std::string& function, bool solidus) const;
    std::string get_generated_exploit(const std::string& function) const;
    std::string generate_exploit_url(const std::string& payload) const;

    void print(std::ostream& os) const;
    static void printHeader(std::ostream& os);

private:
    static std::string UriEncode(const std::string & sSrc);
    static bool replaceAll( std::string &s, const std::string &search, const std::string &replace );
    static std::string default_payload;

    std::string uuid;
    std::string url;
    std::string parentloc;
    std::string base_domain;
    std::string sink;
    std::string source;
    int sanitizer_score;
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
    std::string sanitizer_name;
    std::string sanitizer_loc;
    bool valid_exploit{};
    int begin_taint_url;
    int end_taint_url;
    int replace_begin_url;
    int replace_end_url;
    int replace_begin_param;
    int replace_end_param;
    int max_encode_attr_chain_length;
    int max_encode_text_fragment_chain_length;
    bool approximated_method{};
    bool unsupported_method{};
    bool infinite_regex{};
    bool url_on_rhs_of_replace{};
    bool url_on_lhs_of_replace{};
    bool url_in_exec_pattern{};
    bool url_in_match_pattern{};
    bool cookie_value_in_rhs_of_replace{};
    bool cookie_value_in_lhs_of_replace{};
    bool cookie_value_in_exec_pattern{};
    bool cookie_value_in_match_pattern{};
    bool removed_lr_concats{};
    bool removed_replace_artifacts{};
    bool removed_nop_replaces{};
    bool merged_splits_and_joins{};

};


#endif //SEMREP_METADATA_HPP
