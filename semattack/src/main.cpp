/*
 * SemRep
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

#include <boost/program_options.hpp>
#include "SemRepair.hpp"
#include "AnalysisResult.hpp"
#include "exceptions/StrangerException.hpp"

using namespace std;
using namespace boost;
namespace po = boost::program_options;


void call_sem_repair(string reference_name, string target_name, string field_name){
	try {
		cout << endl << "\t------ Starting Analysis for: " << field_name << " ------" << endl;
		cout << endl << "\t       Reference: " << reference_name  << endl;
		cout << endl << "\t       Target: " << target_name  << endl;
		SemRepair semRepair(reference_name, target_name, field_name);
		semRepair.calculate_rejected_set = true;
		semRepair.computeValidationPatch();
		semRepair.computeSanitizationPatch();

		cout << endl << "\t------ OVERALL RESULT for: " << field_name << " ------" << endl;
		cout << "\t    Reference: " << reference_name << endl;
		cout << "\t    Target: " << target_name << endl;

		semRepair.printResults();

		cout << endl << "\t------ END RESULT for: " << field_name << " ------" << endl;
	} catch (StrangerException const &e) {
		cerr << e.what();
		exit(EXIT_FAILURE);
	}

}


// A helper function to simplify the main part.
template<class T>
ostream& operator<<(ostream& os, const vector<T>& v)
{
    copy(v.begin(), v.end(), ostream_iterator<T>(cout, " "));
    return os;
}

int main(int argc, char *argv[]) {
    try {

        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("verbose", po::value<string>()->implicit_value("0"), "verbosity level")
            ("target,t", po::value<string>()->required(), "Path to dependency graph file for repair target function.")
            ("reference,r", po::value<string>()->required(), "Path to dependency graph file for repair reference function.")
            ("fieldname,f", po::value<string>()->required(), "Name of the input field for which sanitization code needs to be repaired.");

        po::positional_options_description p;
        p.add("target", 1);
        p.add("reference", 1);
        p.add("fieldname", 1);


        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).
                  options(desc).positional(p).run(), vm);

        if (vm.count("help"))
        {
            cout << "Usage: SemRep [options] <target> <reference> <fieldname>\n";
            cout << "<target> is Path to dependency graph file for repair target function.\n";
            cout << "<reference> is Path to dependency graph file for repair reference function.\n";
            cout << "<fieldname> is Name of the input field for which sanitization code needs to be repaired.\n";
            cout << desc << "\n";
            return 0;
        }

        po::notify(vm);

        if (vm.count("target") && vm.count("reference") && vm.count("fieldname"))
        {
            call_sem_repair(vm["reference"].as<string>(), vm["target"].as<string>(), vm["fieldname"].as<string>());
        }
        else {
            cerr << "Unknown error while parsing cmdline options!" << "\n";
            return false;
        }

    } catch(std::exception& e)
    {
           cerr << "Error: " << e.what() << "\n";
           exit(EXIT_FAILURE);
    }
    catch(...)
    {
        cerr << "Unknown error!" << "\n";
        return false;
    }

}
