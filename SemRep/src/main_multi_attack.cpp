/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * Main multi attack
 * Copyright (C) 2013-2014 University of California Santa Barbara.
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
#include "MultiAttack.hpp"
#include "AttackContext.hpp"
#include "StrangerAutomaton.hpp"
#include "exceptions/StrangerException.hpp"

using namespace std;
using namespace boost;
namespace po = boost::program_options;


void call_sem_attack(const string& target_name, const string& output_dir, const string& field_name,
                     bool concats, bool singleton_intersection, bool preImage, bool encode, bool payloadOnly, bool dotfiles)
{
    try {
        cout << endl << "\t------ Starting Analysis for: " << field_name << " ------" << endl;
        cout << endl << "\t       Target: " << target_name  << endl;

        StrangerAutomaton* input = StrangerAutomaton::makeAnyString();
        if (encode) {
          StrangerAutomaton* encoded = input->encodeURI(input);
          delete input;
          input = encoded;
        }
        MultiAttack attack(target_name, output_dir, field_name, input);
        // MultiAttack clones the input
        delete input;

        attack.setSingletonIntersection(singleton_intersection);
        attack.setConcats(concats);
        attack.setComputePreimage(preImage);
        attack.setDotFiles(dotfiles);

        if (!payloadOnly) {
          attack.addAttackPattern(AttackContext::LessThan);
          attack.addAttackPattern(AttackContext::GreaterThan);
          attack.addAttackPattern(AttackContext::Ampersand);
          attack.addAttackPattern(AttackContext::Quote);
          attack.addAttackPattern(AttackContext::SingleQuote);
          attack.addAttackPattern(AttackContext::Backtick);
          attack.addAttackPattern(AttackContext::Slash);
          attack.addAttackPattern(AttackContext::Equals);
          attack.addAttackPattern(AttackContext::Open_Paren);
          attack.addAttackPattern(AttackContext::Closing_paren);
          attack.addAttackPattern(AttackContext::Space);
          attack.addAttackPattern(AttackContext::Script);
          attack.addAttackPattern(AttackContext::Alert);
          attack.addAttackPattern(AttackContext::HtmlMinimal);
          attack.addAttackPattern(AttackContext::HtmlMedium);
          attack.addAttackPattern(AttackContext::Html);
          attack.addAttackPattern(AttackContext::HtmlAttr);
          attack.addAttackPattern(AttackContext::JavaScript);
          attack.addAttackPattern(AttackContext::JavaScriptMinimal);
          attack.addAttackPattern(AttackContext::Url);
          attack.addAttackPattern(AttackContext::HtmlPayload);
          attack.addAttackPattern(AttackContext::HtmlAttributePayload);
          attack.addAttackPattern(AttackContext::HtmlSingleQuoteAttributePayload);
          attack.addAttackPattern(AttackContext::UrlPayload);
          attack.addAttackPattern(AttackContext::HtmlPolygotPayload);
        }
        attack.compute();

        cout << endl << "\t------ OVERALL RESULT for: " << field_name << " ------" << endl;
        cout << "\t    Target: " << target_name << endl;

        attack.printResults();

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
          ("help",         "produce help message")
          ("verbose,v",    po::value<string>()->implicit_value("0"), "verbosity level")
          ("target,t",     po::value<string>()->required(), "Path to dependency graph file for target function.")
          ("output,o",     po::value<string>()->required(), "Path to output directory.")
          ("fieldname,f",  po::value<string>()->required(), "Name of the input field for which sanitization code needs to be repaired.")
          ("concat,c",     po::value<bool>()->default_value(false), "Compute concat operations")
          ("encode,e",     po::value<bool>()->default_value(false), "Use URL encoded automaton as analysis input (default is any string)")
          ("singleton,s",  po::value<bool>()->default_value(false), "Use singletons for post-image computation")
          ("preimage,p",   po::value<bool>()->default_value(true), "Compute preimages for attack patterns")
          ("payload,y",    po::value<bool>()->default_value(false), "Use only payload string attack patterns")
          ("dotfiles,d",    po::value<bool>()->default_value(true), "Output all dot output files to disk");

        po::positional_options_description p;
        p.add("target", 1);
        p.add("fieldname", 1);


        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).
                  options(desc).positional(p).run(), vm);

        if (vm.count("help"))
        {
            cout << desc << "\n";
            return 0;
        }

        po::notify(vm);

        if (vm.count("target") && vm.count("fieldname")) {
          cout << boolalpha
               << "Calling multiattack with target: " << vm["target"].as<string>()
               << ", output dir: " << vm["output"].as<string>()
               << ", fieldname: " << vm["fieldname"].as<string>()
               << ", concat enabled: " << vm["concat"].as<bool>()
               << ", singleton computation: " << vm["singleton"].as<bool>()
               << ", preimage computation: " << vm["preimage"].as<bool>()
               << ", URL encode input: " << vm["encode"].as<bool>()
               << ", Only payload attack patterns: " << vm["payload"].as<bool>()
               << ", Output dot files: " << vm["dotfiles"].as<bool>()
               << "\n";

            call_sem_attack(vm["target"].as<string>(),
                            vm["output"].as<string>(),
                            vm["fieldname"].as<string>(),
                            vm["concat"].as<bool>(),
                            vm["singleton"].as<bool>(),
                            vm["preimage"].as<bool>(),
                            vm["encode"].as<bool>(),
                            vm["payload"].as<bool>(),
                            vm["dotfiles"].as<bool>()
              );
        }
        else {
            cerr << "Unknown error while parsing cmdline options!" << "\n";
            cout << desc << "\n";
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
