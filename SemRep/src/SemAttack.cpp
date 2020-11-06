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
#include "AttackPatterns.hpp"

PerfInfo SemAttack::perfInfo;

CombinedAnalysisResult::CombinedAnalysisResult(const std::string& target_dep_graph_file_name,
                                               const std::string& input_field_name,
                                               StrangerAutomaton* automaton)
  : m_fwAnalysis(target_dep_graph_file_name, input_field_name, automaton)
  , m_bwAnalysisMap()
{
}

void CombinedAnalysisResult::addBackwardAnalysis(AttackContext context)
{
  m_bwAnalysisMap.insert(std::make_pair(context, BackwardAnalysisResult(m_fwAnalysis, context)));
}

void CombinedAnalysisResult::printResult() const
{
  for (auto bwResult : m_bwAnalysisMap) {
    AttackContext c = bwResult.first;
    const BackwardAnalysisResult& result = bwResult.second;
    std::cout << AttackContextHelper::getName(c) << ": "
              << (result.isVulnerable() ? "true" : "false")
              << ", ";
  }
}

BackwardAnalysisResult::BackwardAnalysisResult(
  const ForwardAnalysisResult& fwResult, AttackContext context)
  : m_fwResult(fwResult)
  , m_context(context)
{
  StrangerAutomaton* pattern = AttackPatterns::getAttackPatternForContext(context);
  const StrangerAutomaton* postImage = m_fwResult.getPostImage();
  m_intersection = this->getAttack()->computeAttackPatternOverlap(postImage, pattern);
  m_result = this->getAttack()->computePreImage(m_intersection, m_fwResult.getFwAnalysisResult());
  delete pattern;
}

BackwardAnalysisResult::~BackwardAnalysisResult()
{
}

ForwardAnalysisResult::ForwardAnalysisResult(
  const std::string& target_dep_graph_file_name,
  const std::string& input_field_name,
  StrangerAutomaton* automaton)
{
  m_attack = new SemAttack(target_dep_graph_file_name, input_field_name);
  m_input = automaton;
  m_result = m_attack->computeTargetFWAnalysis(m_input);
}

ForwardAnalysisResult::~ForwardAnalysisResult()
{
  delete m_attack;
  delete m_input;
}

SemAttack::SemAttack(const string& target_dep_graph_file_name, const string& input_field_name)
  : target_dep_graph_file_name(target_dep_graph_file_name)
  , input_field_name(input_field_name)
{

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

    message(this->target_dep_graph.toDot());
    message(this->target_field_relevant_graph.toDot());

    ImageComputer::perfInfo = &SemAttack::perfInfo;
    ImageComputer::staticInit();
}

SemAttack::~SemAttack() {
    delete this->target_uninit_field_node;
}

void SemAttack::message(const std::string& msg) const {
    cout << endl << "~~~~~~~~~~~>>> SemAttack says: " << msg << endl;
}

string SemAttack::generateOutputFilePath(string folder_name, bool unique_name) const {
    boost::filesystem::path curr_dir(boost::filesystem::current_path());
    boost::filesystem::path output_dir(curr_dir / folder_name);

    if (! boost::filesystem::exists(output_dir)) {
        boost::filesystem::create_directory(output_dir);
    }
    if (!unique_name) {
        return stringbuilder() << output_dir.string() << "/";
    }

    size_t tar_ext_index = target_dep_graph_file_name.find_last_of('.');
    if (tar_ext_index == string::npos) {
        tar_ext_index = target_dep_graph_file_name.length() - 1;
    }
    size_t tar_index = target_dep_graph_file_name.find_last_of('/');
    if (tar_index == string::npos) {
        tar_index = 0;
    }

    string tar_file = target_dep_graph_file_name.substr(tar_index + 1, tar_ext_index - tar_index - 1);

    return stringbuilder() << output_dir.string() << tar_file << "_" << input_field_name;
}

void SemAttack::printAnalysisResults(AnalysisResult& result) const {
    cout << endl;
    for (auto& entry : result ) {
        cout << "Printing automata for node ID: " << entry.first << endl;
        (entry.second)->toDot();
        cout << endl << endl;
    }
}

void SemAttack::printNodeList(NodesList nodes) const {
    cout << endl;
    for (auto node : nodes ) {
        cout << node->getID() << " ";
    }
    cout << endl;
}

// TODO add output file option
void SemAttack::printResults() const {
    string file_path =  generateOutputFilePath("outputs/generated_patch_automata", false);

    string vp_fname = stringbuilder() << file_path << "validation_patch_dfa_with_ASCII_transitions.dot";
    string vp_mn_fname = stringbuilder() << file_path << "validation_patch_dfa_with_MONA_transitions.dot";
    string vp_bdd_fname = stringbuilder() << file_path << "validation_patch_BDD.dot";
    cout << "\t file : " << vp_fname << endl;
    cout << "\t file : " << vp_mn_fname << endl;
    cout << "\t file : " << vp_bdd_fname << endl;
    //DEBUG_AUTO_TO_FILE(target_sink_auto, vp_fname);
    //DEBUG_AUTO_TO_FILE_MN(target_sink_auto,vp_mn_fname);
    //target_sink_auto->toDotBDDFile(vp_bdd_fname);

    cout << "\t size : states " << target_sink_auto->get_num_of_states() << " : "
         << "bddnodes " << target_sink_auto->get_num_of_bdd_nodes() << endl;

    //cout << "\t    - validation patch is generated" << endl;

    if (DEBUG_ENABLED_RESULTS != 0) {
      DEBUG_MESSAGE("validation patch auto:");
      DEBUG_AUTO(target_sink_auto);
    }

    perfInfo.print_validation_extraction_info();
    perfInfo.print_sanitization_extraction_info();
    perfInfo.print_operations_info();
    perfInfo.reset();
}


/**
 * Computes sink post image for target, first time
 */
AnalysisResult SemAttack::computeTargetFWAnalysis(StrangerAutomaton* inputAuto) {
    message("computing target sink post image...");
    AnalysisResult targetAnalysisResult;
    UninitNodesList targetUninitNodes = target_dep_graph.getUninitNodes();

    // initialize reference input nodes to bottom
    message("initializing reference inputs with bottom");
    for (auto uninit_node : targetUninitNodes) {
        targetAnalysisResult[uninit_node->getID()] = StrangerAutomaton::makePhi(uninit_node->getID());
    }
    // initialize uninit node that we are interested in with sigma star
    message(stringbuilder() << "initializing input node(" << target_uninit_field_node->getID() << ") with sigma star");
    delete targetAnalysisResult[target_uninit_field_node->getID()];
    
    targetAnalysisResult[target_uninit_field_node->getID()] = inputAuto;

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
    return targetAnalysisResult;
}

AnalysisResult SemAttack::computeTargetFWAnalysis()
{
  return computeTargetFWAnalysis(StrangerAutomaton::makeAnyString(target_uninit_field_node->getID()));
}

const StrangerAutomaton* SemAttack::getPostImage(const AnalysisResult& result) const
{
  return result.at(target_field_relevant_graph.getRoot()->getID());
}

StrangerAutomaton* SemAttack::computeAttackPatternOverlap(const StrangerAutomaton* postImage,
                                                          const StrangerAutomaton* attackPattern) const {
  message("BEGIN SANITIZATION ANALYSIS PHASE........................................");
  boost::posix_time::ptime start_time = perfInfo.current_time();
  perfInfo.sanitization_target_first_forward_time = perfInfo.current_time() - start_time;
  if (DEBUG_ENABLED_SC != 0) {
    DEBUG_MESSAGE("Target Sink Auto - First forward analysis");
    DEBUG_AUTO(postImage);
  }

  postImage->toDotAscii(1);
  message("Example sanitizer string:");
  message(postImage->generateSatisfyingExample());

  attackPattern->toDotAscii(1);
  message("Example attack pattern string:");
  message(attackPattern->generateSatisfyingExample());
        
  StrangerAutomaton* intersection = postImage->intersect(attackPattern);
  intersection->toDotAscii(1);
        
  if (intersection->isEmpty()) {
    message("No intersection, validation function is good!");
  } else {
    message("Intersection between attack pattern and sanitizer!");
    message(intersection->generateSatisfyingExample());
  }

  return intersection;
}

AnalysisResult SemAttack::computePreImage(const StrangerAutomaton* intersection,
                                          const AnalysisResult& result) const
{
  try {
    message("starting backward analysis...");
    ImageComputer analyzer;
    AnalysisResult analysis_result = analyzer.doBackwardAnalysis_GeneralCase(
      this->target_dep_graph, this->target_field_relevant_graph, intersection, result);
    message("...finished backward analysis.");
    return analysis_result;

  } catch (StrangerStringAnalysisException const &e) {
    cerr << e.what();
  }
  return AnalysisResult();
}

const StrangerAutomaton* SemAttack::getPreImage(const AnalysisResult& result) const
{
  return result.at(this->target_uninit_field_node->getID());
}


