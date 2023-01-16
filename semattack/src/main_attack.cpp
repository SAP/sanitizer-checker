/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
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
 * Authors: Abdulbaki Aydin, Muath Alkhalaf, Thomas Barber
 */

#include <boost/program_options.hpp>
#include "SemAttack.hpp"
#include "AttackPatterns.hpp"
#include "exceptions/StrangerException.hpp"
#include "main_attack.hpp"

using namespace std;
using namespace boost;
namespace po = boost::program_options;

std::string call_sem_attack(string target_name, string dep_graph, string field_name){
    try {
        cout << endl << "\t------ Starting Analysis for: " << field_name << " ------" << endl;
        cout << endl << "\t       Target: " << target_name  << endl;
        DepGraph target_dep_graph;
        if (dep_graph != "") {
            target_dep_graph = DepGraph::parseString(dep_graph);
        } else 
        {
            target_dep_graph = DepGraph::parseDotFile(target_name);
        }
        SemAttack semAttack(target_name, target_dep_graph, field_name);
        semAttack.setPrintDots(true);
        semAttack.init();
        AnalysisResult result = semAttack.computeTargetFWAnalysis();
        const StrangerAutomaton* postImage = semAttack.getPostImage(result);
        StrangerAutomaton* attackPattern = AttackPatterns::getHtmlPattern();
        StrangerAutomaton* intersection = semAttack.computeAttackPatternOverlap(postImage, attackPattern);
// bw = doBackwardAnalysisForPayload(attr_payload, output_dir, computePreImage, singletonIntersection, outputDotfiles, attack_forward)
        cout << endl << "\t------ OVERALL RESULT for: " << field_name << " ------" << endl;
        cout << "\t    Target: " << target_name << endl;

        semAttack.printResults();

        cout << endl << "\t------ END RESULT for: " << field_name << " ------" << endl;
    } catch (StrangerException const &e) {
        cerr << e.what();
        // exit(EXIT_FAILURE);
    }

    return "";
}


// A helper function to simplify the main part.
template<class T>
ostream& operator<<(ostream& os, const vector<T>& v)
{
    copy(v.begin(), v.end(), ostream_iterator<T>(cout, " "));
    return os;
}

void usage() {
    cout << "Usage: SemAttack [options] <target> <fieldname>\n";
    cout << "<target> is Path to dependency graph file for repair target function.\n";
    cout << "<digraph> is the dependency graph object in string format.\n";
    cout << "<fieldname> is Name of the input field for which sanitization code needs to be repaired.\n";
}

int main(int argc, char *argv[]) {
    try {

        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("verbose", po::value<string>()->implicit_value("0"), "verbosity level")
            ("target,t", po::value<string>()->required(), "Path to dependency graph file for target function.")
            ("digraph,d", po::value<string>(), "the dependency graph object in string format.")
            ("fieldname,f", po::value<string>(), "Name of the input field for which sanitization code needs to be repaired.");

        po::positional_options_description p;
        p.add("target", 1);
        p.add("fieldname", 1);
        p.add("digraph", 1);


        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).
                  options(desc).positional(p).run(), vm);

        if (vm.count("help"))
        {
            usage();
            return 0;
        }

        po::notify(vm);

        if (vm.count("digraph") && vm.count("fieldname") && !vm.count("target"))
        {
            call_sem_attack("", vm["digraph"].as<string>(), vm["fieldname"].as<string>());
        }
        else if (vm.count("target") && vm.count("fieldname") && !vm.count("digraph"))
        {
            call_sem_attack(vm["target"].as<string>(), "", vm["fieldname"].as<string>());
        }
        else if (vm.count("digraph") && vm.count("target")) {
            cerr << "either a digraph or a target file has to be provided, but not both" << "\n";
            usage();
            return false;
        }
        else {
            cerr << "Unknown error while parsing cmdline options!" << "\n";
            usage();
            return false;
        }

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
