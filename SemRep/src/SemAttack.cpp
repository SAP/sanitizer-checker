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

#include "SemAttack.hpp"

PerfInfo SemAttack::perfInfo;

SemAttack::SemAttack(string target_dep_graph_file_name, string input_field_name) {

    this->target_dep_graph_file_name = target_dep_graph_file_name;
    this->input_field_name = input_field_name;

    // read dep graphs
    this->target_dep_graph = DepGraph::parseDotFile(target_dep_graph_file_name);

    // initialize input nodes
    this->target_uninit_field_node = target_dep_graph.findInputNode(input_field_name);
    if (target_uninit_field_node == NULL) {
        throw StrangerStringAnalysisException("Cannot find input node " + input_field_name + " in target dep graph.");
    }
    message(stringbuilder() << "target uninit node(" << target_uninit_field_node->getID() << ") found for field " << input_field_name << ".");

    // initialize input relevant graphs
    this->target_field_relevant_graph = target_dep_graph.getInputRelevantGraph(target_uninit_field_node);

    if (DEBUG_ENABLED_INIT != 0) {
        DEBUG_MESSAGE("------------ Debugging Initalization ------------");
        DEBUG_MESSAGE("Target Dependency Graph");
        this->target_dep_graph.toDot();
        DEBUG_MESSAGE("Target Field Relevant Dependency Graph");
        this->target_field_relevant_graph.toDot();
    }

    DEBUG_AUTO_TO_FILE_MN(validation_patch_auto, "");
    ImageComputer::perfInfo = &SemAttack::perfInfo;
    ImageComputer::staticInit();
}

SemAttack::~SemAttack() {
    delete this->target_uninit_field_node;
}

void SemAttack::message(string msg) {
    cout << endl << "~~~~~~~~~~~>>> SemAttack says: " << msg << endl;
}

string SemAttack::generateOutputFilePath(string folder_name, bool unique_name) {
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

void SemAttack::printAnalysisResults(AnalysisResult& result) {
    cout << endl;
    for (auto& entry : result ) {
        cout << "Printing automata for node ID: " << entry.first << endl;
        (entry.second)->toDot();
        cout << endl << endl;
    }
}

void SemAttack::printNodeList(NodesList nodes) {
    cout << endl;
    for (auto node : nodes ) {
        cout << node->getID() << " ";
    }
    cout << endl;
}

// TODO add output file option
void SemAttack::printResults() {
    string file_path =  generateOutputFilePath("outputs/generated_patch_automata", false);

    if (is_validation_patch_required) {
        cout << "\t    - validation patch is generated" << endl;
        string vp_fname = stringbuilder() << file_path << "validation_patch_dfa_with_ASCII_transitions.dot";
        string vp_mn_fname = stringbuilder() << file_path << "validation_patch_dfa_with_MONA_transitions.dot";
        string vp_bdd_fname = stringbuilder() << file_path << "validation_patch_BDD.dot";
        cout << "\t file : " << vp_fname << endl;
        cout << "\t file : " << vp_mn_fname << endl;
        cout << "\t file : " << vp_bdd_fname << endl;
        DEBUG_AUTO_TO_FILE(validation_patch_auto, vp_fname);
        DEBUG_AUTO_TO_FILE_MN(validation_patch_auto,vp_mn_fname);
        validation_patch_auto->toDotBDDFile(vp_bdd_fname);

        cout << "\t size : states " << validation_patch_auto->get_num_of_states() << " : "
             << "bddnodes " << validation_patch_auto->get_num_of_bdd_nodes() << endl;

        //cout << "\t    - validation patch is generated" << endl;

        if (DEBUG_ENABLED_RESULTS != 0) {
            DEBUG_MESSAGE("validation patch auto:");
            DEBUG_AUTO(validation_patch_auto);
        }

    } else {
        cout << "\t    - no validation patch" << endl;
        cout << "\t size : states 0 : bddnodes 0" << endl;
    }


    if (is_length_patch_required) {
        cout << "\t    - length patch is generated" << endl;

        string lp_fname = stringbuilder() << file_path << "length_patch_dfa_with_ASCII_transitions.dot";
        string lp_mn_fname = stringbuilder() << file_path << "length_patch_dfa_with_MONA_transitions.dot";
        string lp_bdd_fname = stringbuilder() << file_path << "length_patch_BDD.dot";
        cout << "\t file : " << lp_fname << endl;
        cout << "\t file : " << lp_mn_fname << endl;
        cout << "\t file : " << lp_bdd_fname << endl;
        DEBUG_AUTO_TO_FILE(length_patch_auto, lp_fname);
        DEBUG_AUTO_TO_FILE_MN(length_patch_auto,lp_mn_fname);
        length_patch_auto->toDotBDDFile(lp_bdd_fname);

        cout << "\t size : states " << length_patch_auto->get_num_of_states() << " : "
             << "bddnodes " << length_patch_auto->get_num_of_bdd_nodes() << endl;



        if (DEBUG_ENABLED_RESULTS != 0) {
            DEBUG_MESSAGE("length patch auto:");
            DEBUG_AUTO(length_patch_auto);
        }
    } else {
        cout << "\t    - no length patch" << endl;
        cout << "\t size : states 0 : bddnodes 0" << endl;
    }

    if (is_sanitization_patch_required) {
        cout << "\t    - sanitization patch is generated :" << endl;

        string sp_fname = stringbuilder() << file_path << "sanitization_patch_dfa_with_ASCII_transitions.dot";
        string sp_mn_fname = stringbuilder() << file_path << "sanitization_patch_dfa_with_MONA_transitions.dot";
        string sp_bdd_fname = stringbuilder() << file_path << "sanitization_patch_BDD.dot";
        string refsink_mn_fname = stringbuilder() << file_path << "reference_dfa_with_MONA_transitions.dot";
        cout << "\t file : " << sp_fname << endl;
        cout << "\t file : " << sp_mn_fname << endl;
        cout << "\t file : " << sp_bdd_fname << endl;
        cout << "\t file : " << refsink_mn_fname << endl;
        DEBUG_AUTO_TO_FILE(sanitization_patch_auto,sp_fname);
        DEBUG_AUTO_TO_FILE_MN(sanitization_patch_auto,sp_mn_fname);
        sanitization_patch_auto->toDotBDDFile(sp_bdd_fname);

        cout << "\t size : states " << sanitization_patch_auto->get_num_of_states() << " : "
             << "bddnodes " << sanitization_patch_auto->get_num_of_bdd_nodes() << endl;


        if (DEBUG_ENABLED_RESULTS != 0) {
            DEBUG_MESSAGE("sanitization patch auto:");
            DEBUG_AUTO(sanitization_patch_auto);
        }
    } else {
        cout << "\t    - no sanitization patch" << endl;
        cout << "\t size : states 0 : bddnodes 0" << endl;
    }

    perfInfo.print_validation_extraction_info();
    perfInfo.print_sanitization_extraction_info();
    perfInfo.print_operations_info();
    perfInfo.reset();
}


/**
 * checks if length has maximum restriction, or minimum restriction without a maximium restriction
 * TODO currently that function only checks if the minimum restriction length is 1 or not, handle any minimum restriction later
 * result 0 : no worries about length
 * result 1 : there is a maximum length restriction (may also have minimum inside)
 * result 2 : there is a minimum length restriction (max length is infinite in that case)
 */
int SemAttack::isLengthAnIssue(StrangerAutomaton* referenceAuto, StrangerAutomaton*targetAuto) {
    message("BEGIN LENGTH PATCH ANALYSIS PHASE........................................");
    boost::posix_time::ptime start_time = perfInfo.current_time();
    int result = 0;
    if(referenceAuto->isLengthFinite()) {
        if (targetAuto->isLengthFinite()) {
            if (referenceAuto->getMaxLength() < targetAuto->getMaxLength()) {
                result = 1;
            }
        }
        else {
            result = 1;
        }
    } else if (referenceAuto->checkEmptyString()) {
        if( !targetAuto->checkEmptyString() ) {
            result = 2;
        }
    }
    perfInfo.sanitization_length_issue_check_time = perfInfo.current_time() - start_time;
    return result;
}

/**
 * Initial backward analysis phase for extracting validation behavior
 */
StrangerAutomaton* SemAttack::computeValidationPatch() {

    message("BEGIN VALIDATION ANALYSIS PHASE........................................");

    ImageComputer analyzer;
    boost::posix_time::ptime start_time;
    try {
        message("extracting validation from target");
        start_time = perfInfo.current_time();
        AnalysisResult target_validationExtractionResults =
            analyzer.doBackwardAnalysis_ValidationCase(target_dep_graph, target_field_relevant_graph, StrangerAutomaton::makeBottom());
        StrangerAutomaton* target_negVPatch = target_validationExtractionResults[target_uninit_field_node->getID()];
        StrangerAutomaton* target_validation = target_negVPatch;
        if ( !calculate_rejected_set ) {
            target_validation = target_negVPatch->complement(target_uninit_field_node->getID());
        }
        perfInfo.validation_target_backward_time = perfInfo.current_time() - start_time;
        if (DEBUG_ENABLED_VP != 0) {
            DEBUG_MESSAGE("target validation auto:");
            DEBUG_AUTO(target_validation);
        }

        delete target_validation;

    } catch (StrangerStringAnalysisException const &e) {
        cerr << e.what();
        exit(EXIT_FAILURE);
    }

    perfInfo.calculate_total_validation_extraction_time();
    message("........................................END VALIDATION ANALYSIS PHASE");
    return validation_patch_auto;
}

/**
 * Computes sink post image for target, first time
 */
AnalysisResult SemAttack::computeTargetFWAnalysis() {
    AnalysisResult targetAnalysisResult;
    UninitNodesList targetUninitNodes = target_dep_graph.getUninitNodes();

    message("initializing target inputs with bottom");
    for (auto uninit_node : targetUninitNodes) {
        targetAnalysisResult[uninit_node->getID()] = StrangerAutomaton::makePhi(uninit_node->getID());
    }

    // initialize uninit node that we are interested in with validation patch_auto
    message(stringbuilder() << "initializing input node(" << target_uninit_field_node->getID() << ") with validation patch auto");
    delete targetAnalysisResult[target_uninit_field_node->getID()];
    if (calculate_rejected_set) {
        targetAnalysisResult[target_uninit_field_node->getID()] = validation_patch_auto->complement(target_uninit_field_node->getID());
    } else {
        targetAnalysisResult[target_uninit_field_node->getID()] = validation_patch_auto;
    }

    ImageComputer targetAnalyzer;

    try {

        message("starting forward analysis for target...");
        targetAnalyzer.doForwardAnalysis_SingleInput(target_dep_graph, target_field_relevant_graph, targetAnalysisResult);
        message("...finished forward analysis for target.");

    } catch (StrangerStringAnalysisException const &e) {
        cerr << e.what();
        exit(EXIT_FAILURE);
    }

    return targetAnalysisResult;
}

StrangerAutomaton* SemAttack::computeTargetLengthPatch(StrangerAutomaton* initialAuto, AnalysisResult& fwAnalysisResult) {
    message("starting a backward analysis to calculate length patch...");
    ImageComputer targetAnalyzer;
    try {
        fwAnalysisResult[target_uninit_field_node->getID()] = StrangerAutomaton::makeAnyString(-5);
        boost::posix_time::ptime start_time = perfInfo.current_time();
        AnalysisResult bwResult = targetAnalyzer.doBackwardAnalysis_GeneralCase(target_dep_graph, target_field_relevant_graph, initialAuto, fwAnalysisResult);
        perfInfo.sanitization_length_backward_time = perfInfo.current_time() - start_time;
        StrangerAutomaton* negPatchAuto = bwResult[target_uninit_field_node->getID()];
        if ( calculate_rejected_set ) {
            length_patch_auto = negPatchAuto->clone(-5);
        } else {
            length_patch_auto = negPatchAuto->complement(-5);
        }
//		fwAnalysisResult[target_uninit_field_node->getID()] = validation_patch_auto->intersect(length_patch_auto,-5);

    } catch (StrangerStringAnalysisException const &e) {
        cerr << e.what();
        exit(EXIT_FAILURE);
    }
    message("...length patch is generated");
    return length_patch_auto;
}



