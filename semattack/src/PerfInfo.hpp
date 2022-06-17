/*
 * PerfInfo.hpp
 *
 * Copyright (C) 2013-2014 University of California Santa Barbara.
 *
 * Modifications Copyright SAP SE. 2020-2022.  All rights reserved.
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
 * Authors: Abdulbaki Aydin, Muath Alkhalaf
 */

#ifndef PERFINFO_HPP_
#define PERFINFO_HPP_

#include <string>
#include <boost/date_time/posix_time/posix_time.hpp>

class PerfInfo {
public:

    // Make PerfInfo a singleton
    static PerfInfo & getInstance() {
        static PerfInfo instance;
        return instance;
    }

	 void reset();

	 boost::posix_time::ptime current_time();

	 void print_validation_extraction_info();
	 void print_sanitization_extraction_info();
	 void print_operations_info();

	 void calculate_total_validation_extraction_time();
	 void calculate_total_sanitization_length_extraction_time();
	 void calculate_total_sanitization_extraction_time();

//	Validation Extraction Time
	 boost::posix_time::time_duration validation_target_backward_time;
	 boost::posix_time::time_duration validation_reference_backward_time;
	 boost::posix_time::time_duration validation_comparison_time;
	 boost::posix_time::time_duration validation_patch_extraction_total_time;

//    Sanitization Extraction Time
	 boost::posix_time::time_duration sanitization_target_first_forward_time;
	 boost::posix_time::time_duration sanitization_reference_first_forward_time;
	 boost::posix_time::time_duration sanitization_length_issue_check_time;
	 boost::posix_time::time_duration sanitization_length_backward_time;
	 boost::posix_time::time_duration sanitization_length_patch_extraction_total_time;
	 boost::posix_time::time_duration sanitization_patch_backward_time;
	 boost::posix_time::time_duration sanitization_comparison_time;
	 boost::posix_time::time_duration sanitization_patch_extraction_total_time;

//    Stranger Automaton Operations

//    Core string operation information
//    concat, union, intersection, closure, replace...

	 boost::posix_time::time_duration intersect_total_time;
         boost::posix_time::time_duration product_total_time;
	 boost::posix_time::time_duration union_total_time;
	 boost::posix_time::time_duration closure_total_time;
	 boost::posix_time::time_duration complement_total_time;
	 boost::posix_time::time_duration precisewiden_total_time;
	 boost::posix_time::time_duration coarsewiden_total_time;
	 boost::posix_time::time_duration concat_total_time;
	 boost::posix_time::time_duration pre_concat_total_time;
	 boost::posix_time::time_duration const_pre_concat_total_time;
	 boost::posix_time::time_duration replace_total_time;
	 boost::posix_time::time_duration pre_replace_total_time;

	 boost::posix_time::time_duration performance_time;


	 unsigned int num_of_intersect;
    	 unsigned int num_of_product;
	 unsigned int num_of_union;
	 unsigned int num_of_closure;
	 unsigned int num_of_complement;
	 unsigned int num_of_precisewiden;
	 unsigned int num_of_coarsewiden;
	 unsigned int num_of_concat;
	 unsigned int num_of_pre_concat;
	 unsigned int num_of_const_pre_concat;
	 unsigned int num_of_replace;
	 unsigned int num_of_pre_replace;


//    Composed string operations
	 boost::posix_time::time_duration vlab_restrict_total_time;
	 boost::posix_time::time_duration pre_vlab_restrict_total_time;
	 boost::posix_time::time_duration addslashes_total_time;
	 boost::posix_time::time_duration pre_addslashes_total_time;
	 boost::posix_time::time_duration htmlspecialchars_total_time;
	 boost::posix_time::time_duration pre_htmlspecialchars_total_time;
	 boost::posix_time::time_duration stripslashes_total_time;
	 boost::posix_time::time_duration pre_stripslashes_total_time;
	 boost::posix_time::time_duration mysql_escape_string_total_time;
	 boost::posix_time::time_duration pre_mysql_escape_string_total_time;
	 boost::posix_time::time_duration to_uppercase_total_time;
	 boost::posix_time::time_duration pre_to_uppercase_total_time;
	 boost::posix_time::time_duration to_lowercase_total_time;
	 boost::posix_time::time_duration pre_to_lowercase_total_time;
	 boost::posix_time::time_duration trim_spaces_total_time;
	 boost::posix_time::time_duration pre_trim_spaces_total_time;
	 boost::posix_time::time_duration trim_spaces_left_total_time;
	 boost::posix_time::time_duration pre_trim_spaces_left_total_time;
	 boost::posix_time::time_duration trim_spaces_right_total_time;
	 boost::posix_time::time_duration pre_trim_spaces_rigth_total_time;
	 boost::posix_time::time_duration trim_set_total_time;
	 boost::posix_time::time_duration pre_trim_set_total_time;
	 boost::posix_time::time_duration substr_total_time;
	 boost::posix_time::time_duration pre_substr_total_time;
	 boost::posix_time::time_duration encodeattrstring_total_time;
     boost::posix_time::time_duration pre_encodeattrstring_total_time;
     boost::posix_time::time_duration encodetextfragment_total_time;
     boost::posix_time::time_duration pre_encodetextfragment_total_time;
     boost::posix_time::time_duration escapehtmltags_total_time;
     boost::posix_time::time_duration pre_escapehtmltags_total_time;

    unsigned int number_of_vlab_restrict;
	 unsigned int number_of_pre_vlab_restrict;
	 unsigned int number_of_addslashes;
	 unsigned int number_of_pre_addslashes;
	 unsigned int number_of_htmlspecialchars;
	 unsigned int number_of_pre_htmlspecialchars;
    	 unsigned int number_of_encodeuricomponent;
         unsigned int number_of_decodeuricomponent;
	 unsigned int number_of_stripslashes;
	 unsigned int number_of_pre_stripslashes;
	 unsigned int number_of_mysql_escape_string;
	 unsigned int number_of_pre_mysql_escape_string;
	 unsigned int number_of_to_uppercase;
	 unsigned int number_of_pre_to_uppercase;
	 unsigned int number_of_to_lowercase;
	 unsigned int number_of_pre_to_lowercase;
	 unsigned int number_of_trim_spaces;
	 unsigned int number_of_pre_trim_spaces;
	 unsigned int number_of_trim_spaces_left;
	 unsigned int number_of_pre_trim_spaces_left;
	 unsigned int number_of_trim_spaces_rigth;
	 unsigned int number_of_pre_trim_spaces_rigth;
	 unsigned int number_of_trim_set;
	 unsigned int number_of_pre_trim_set;
	 unsigned int number_of_substr;
	 unsigned int number_of_pre_substr;
    unsigned int number_of_encodeattrstring;
    unsigned int number_of_pre_encodeattrstring;
    unsigned int number_of_encodetextfragment;
    unsigned int number_of_pre_encodetextfragment;
    unsigned int number_of_escapehtmltags;
    unsigned int number_of_pre_escapehtmltags;
protected:
    virtual ~PerfInfo();

private:
    PerfInfo();
    PerfInfo(PerfInfo const &)  = delete;
    void operator=(PerfInfo const &) = delete;

};


#endif /* PERFINFO_HPP_ */
