/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * automatonify.cpp
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
 * Authors: Abdulbaki Aydin, Muath Alkhalaf, Thomas Barber
 */

#include <boost/program_options.hpp>
#include "StrangerAutomaton.hpp"

using namespace std;
using namespace boost;
namespace po = boost::program_options;


void make_automaton(const string& str, const string& output_file, bool do_sink){

  StrangerAutomaton* a = nullptr;
  if (str == "") {
    a = StrangerAutomaton::makeEmptyString();
  } else {
    a = StrangerAutomaton::regExToAuto(str);
  }
  if (a) {
    a->toDotFileAscii(output_file, do_sink ? 1 : 0);
  }
  delete a;
}


// A helper function to simplify the main part.
template<class T>
ostream& operator<<(ostream& os, const vector<T>& v)
{
    copy(v.begin(), v.end(), ostream_iterator<T>(cout, " "));
    return os;
}

void usage() {
    cout << "Usage: automatonify <string> <output>\n";
}

int main(int argc, char *argv[]) {
    try {

        po::options_description desc("Allowed options");
        desc.add_options()
          ("help", "produce help message")
          ("output,o", po::value<string>()->required(), "path to output file.")
          ("string,s", po::value<string>()->required(), "string to create an automaton from")
          ("sink,k",   po::value<bool>()->default_value(false), "include the sink in the dot output");

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).
                  options(desc).run(), vm);

        if (vm.count("help"))
        {
            usage();
            return 0;
        }

        po::notify(vm);

        make_automaton(vm["string"].as<string>(), vm["output"].as<string>(), vm["sink"].as<bool>());

    } catch(std::exception& e) {
           cerr << "Error: " << e.what() << "\n";
           exit(EXIT_FAILURE);
    }
    catch(...)
    {
        cerr << "Unknown error!" << "\n";
        return false;
    }

}
