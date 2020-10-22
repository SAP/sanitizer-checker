/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * SemAttack.cpp
 *
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

#include "SemAttackBw.hpp"
#include "AttackPatterns.hpp"

PerfInfo SemAttackBw::perfInfo;

SemAttackBw::SemAttackBw(const string& target_dep_graph_file_name, const string& input_field_name) : enable_debug(true), target_dep_graph_file_name(target_dep_graph_file_name), input_field_name(input_field_name) {

    // read dep graphs
    this->target_dep_graph = DepGraph::parseDotFile(target_dep_graph_file_name);

    // initialize input nodes
    this->target_uninit_field_node = target_dep_graph.findInputNode(input_field_name);
    if (this->target_uninit_field_node == nullptr) {
        throw StrangerStringAnalysisException("Cannot find input node " + input_field_name + " in target dep graph.");
    }
    message(stringbuilder() << "target uninit node(" << this->target_uninit_field_node->getID() << ") found for field " << input_field_name << ".");
    ImageComputer::perfInfo = &SemAttackBw::perfInfo;
    ImageComputer::staticInit();
    // initialize input relevant graphs
    this->target_field_relevant_graph = this->target_dep_graph.getInputRelevantGraph(this->target_uninit_field_node);
    this->attack_pattern_auto = AttackPatterns::getHtmlPattern();
    message(this->target_dep_graph.toDot());
    message(this->target_field_relevant_graph.toDot());


}

SemAttackBw::~SemAttackBw() {
    delete this->target_uninit_field_node;
}

void SemAttackBw::message(const string& msg) {
    cout << endl << "~> SemAttackBW says: " << msg << endl;
}

string SemAttackBw::generateOutputFilePath(string folder_name, bool unique_name) {
    boost::filesystem::path curr_dir(boost::filesystem::current_path());
    boost::filesystem::path output_dir(curr_dir / folder_name);

    if (! boost::filesystem::exists(output_dir)) {
        boost::filesystem::create_directory(output_dir);
    }
    if (!unique_name) {
        return stringbuilder() << output_dir.string() << "/";
    }
    size_t ref_ext_index = reference_dep_graph_file_name.find_last_of('.');
    if (ref_ext_index == string::npos) {
        ref_ext_index = reference_dep_graph_file_name.length() - 1;
    }
    size_t ref_index =  reference_dep_graph_file_name.find_last_of('/');
    if (ref_index == string::npos) {
        ref_index = 0;
    }
    string ref_file = reference_dep_graph_file_name.substr(ref_index + 1, ref_ext_index - ref_index - 1);

    size_t tar_ext_index = target_dep_graph_file_name.find_last_of('.');
    if (tar_ext_index == string::npos) {
        tar_ext_index = target_dep_graph_file_name.length() - 1;
    }
    size_t tar_index = target_dep_graph_file_name.find_last_of('/');
    if (tar_index == string::npos) {
        tar_index = 0;
    }

    string tar_file = target_dep_graph_file_name.substr(tar_index + 1, tar_ext_index - tar_index - 1);

    return stringbuilder() << output_dir.string() << "/" << ref_file << "_" << tar_file << "_" << input_field_name;
}

void SemAttackBw::printAnalysisResults(AnalysisResult& result) {
    cout << endl;
    for (auto& entry : result ) {
        cout << "Printing automata for node ID: " << entry.first << endl;
        (entry.second)->toDotAscii(2);
        cout << endl << endl;
    }
}

void SemAttackBw::printNodeList(NodesList nodes) {
    cout << endl;
    for (auto node : nodes ) {
        cout << node->getID() << " ";
    }
    cout << endl;
}

// TODO add output file option
void SemAttackBw::printResults() {
    string file_path =  generateOutputFilePath("outputs/generated_patch_automata", false);

    if (this->is_validation_patch_required) {
        cout << "\t    - validation patch is generated" << endl;
        string vp_fname = stringbuilder() << file_path << "validation_patch_dfa_with_ASCII_transitions.dot";
        string vp_mn_fname = stringbuilder() << file_path << "validation_patch_dfa_with_MONA_transitions.dot";
        string vp_bdd_fname = stringbuilder() << file_path << "validation_patch_BDD.dot";
        cout << "\t file : " << vp_fname << endl;
        cout << "\t file : " << vp_mn_fname << endl;
        cout << "\t file : " << vp_bdd_fname << endl;
        DEBUG_AUTO_TO_FILE(this->target_sink_auto, vp_fname);
        DEBUG_AUTO_TO_FILE_MN(this->target_sink_auto,vp_mn_fname);
        this->target_sink_auto->toDotBDDFile(vp_bdd_fname);

        cout << "\t size : states " << this->target_sink_auto->get_num_of_states() << " : "
             << "bddnodes " << this->target_sink_auto->get_num_of_bdd_nodes() << endl;

        //cout << "\t    - validation patch is generated" << endl;

        if (DEBUG_ENABLED_RESULTS != 0) {
            DEBUG_MESSAGE("validation patch auto:");
            DEBUG_AUTO(this->target_sink_auto);
        }

    } else {
        cout << "\t    - no validation patch" << endl;
        cout << "\t size : states 0 : bddnodes 0" << endl;
    }

    perfInfo.print_validation_extraction_info();
    perfInfo.print_sanitization_extraction_info();
    perfInfo.print_operations_info();
    perfInfo.reset();
}

AnalysisResult SemAttackBw::analyzePostImages() {
    AnalysisResult analysis_result;

    UninitNodesList uninit_nodes = this->target_dep_graph.getUninitNodes();
    message(stringbuilder() << "initializing inputs with bottom other than: " << this->input_field_name );
    for (auto *uninit_node : uninit_nodes) {
        analysis_result[uninit_node->getID()] = StrangerAutomaton::makePhi(uninit_node->getID());
    }

    message(stringbuilder() << "initializing input node: "<< input_field_name << "(" << this->target_uninit_field_node->getID() << ") with sigma star");
    delete analysis_result[this->target_uninit_field_node->getID()];
    analysis_result[this->target_uninit_field_node->getID()] = StrangerAutomaton::makeAnyString(this->target_uninit_field_node->getID());

    ImageComputer analyzer;

    try {

        message("starting forward analysis...");
        analyzer.doForwardAnalysis_SingleInput(this->target_dep_graph, this->target_field_relevant_graph, analysis_result);
        message("...finished forward analysis.");

    } catch (StrangerStringAnalysisException const &e) {
        cerr << e.what();
        exit(EXIT_FAILURE);
    }

    return analysis_result;
}

AnalysisResult SemAttackBw::analyzePreImages(StrangerAutomaton* intersection_auto, const AnalysisResult& fwAnalysisResult) {
    ImageComputer analyzer;

    try {
        message("starting backward analysis...");
        AnalysisResult analysis_result = analyzer.doBackwardAnalysis_GeneralCase(this->target_dep_graph, this->target_field_relevant_graph, intersection_auto, fwAnalysisResult);
        message("...finished backward analysis.");
        return analysis_result;

    } catch (StrangerStringAnalysisException const &e) {
        cerr << e.what();
        exit(EXIT_FAILURE);
    }
}

StrangerAutomaton* SemAttackBw::generateAttack() {

    AnalysisResult fwAnalysisResult = analyzePostImages();
    printAnalysisResults(fwAnalysisResult);
    this->sink_auto = fwAnalysisResult[this->target_dep_graph.getRoot()->getID()];
    if (this->enable_debug) {
        message("Post image of sink node:");
        debug_auto(this->sink_auto, 0);
    }

    StrangerAutomaton* intersection = this->sink_auto->intersect(this->attack_pattern_auto,this->target_dep_graph.getRoot()->getID());

    if (enable_debug) {
        message("Intersection:");
        intersection->printAutomaton();
        debug_auto(intersection, 0);
    }
    if (intersection->isEmpty()) {
        message("Attack pattern can not be exploited, no vulnerability signature");
        return nullptr;
    }
    std::cout.flush();

    AnalysisResult bwAnalysisResult = analyzePreImages(intersection, fwAnalysisResult);
    vs_auto = bwAnalysisResult[this->target_uninit_field_node->getID()];
    if (enable_debug) {
        message("Vulnerability Signature:");
        debug_auto(vs_auto, 0);
    }
    message(vs_auto->generateSatisfyingExample());
    return vs_auto;
}

/**
 * Computes sink post image for target, first time
 */
StrangerAutomaton* SemAttackBw::computeTargetFWAnalysis() {
    message("computing target sink post image...");
    AnalysisResult targetAnalysisResult;
    UninitNodesList targetUninitNodes = target_dep_graph.getUninitNodes();

    // initialize reference input nodes to bottom
    message("initializing reference inputs with bottom");
    for (auto* uninit_node : targetUninitNodes) {
        targetAnalysisResult[uninit_node->getID()] = StrangerAutomaton::makePhi(uninit_node->getID());
    }
    // initialize uninit node that we are interested in with sigma star
    message(stringbuilder() << "initializing input node(" << target_uninit_field_node->getID() << ") with sigma star");
    delete targetAnalysisResult[target_uninit_field_node->getID()];
    targetAnalysisResult[target_uninit_field_node->getID()] = StrangerAutomaton::makeAnyString(target_uninit_field_node->getID());

    ImageComputer targetAnalyzer;

    try {
        message("starting forward analysis for target...");
        targetAnalyzer.doForwardAnalysis_SingleInput(target_dep_graph, target_field_relevant_graph, targetAnalysisResult);
        message("...finished forward analysis for target.");        
    } catch (StrangerStringAnalysisException const &e) {
        cerr << e.what();
        exit(EXIT_FAILURE);
    }

    target_sink_auto = targetAnalysisResult[target_field_relevant_graph.getRoot()->getID()];
    message("...computed target sink post image.");
    return target_sink_auto;
}

void SemAttackBw::debug_auto(StrangerAutomaton* automaton, int type) {
    switch (type) {
        case 0:
            automaton->toDotAscii(0);
            break;
        case 1:
            automaton->toDotAscii(1);
            break;
        case 2:
            automaton->toDot();
            break;
        default:
            automaton->toDotAscii(0);
            break;
    }
}


