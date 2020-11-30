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

#include <boost/filesystem.hpp>

PerfInfo& SemAttack::perfInfo = PerfInfo::getInstance();

namespace fs = boost::filesystem;

CombinedAnalysisResult::CombinedAnalysisResult(const fs::path& target_dep_graph_file_name,
                                               const std::string& input_field_name,
                                               StrangerAutomaton* automaton)
  : m_fwAnalysis(target_dep_graph_file_name, input_field_name, automaton)
  , m_bwAnalysisMap()
  , m_inputfile(target_dep_graph_file_name)
  , m_input_name(input_field_name)
{
}

CombinedAnalysisResult::~CombinedAnalysisResult()
{
  for (auto bwResult : m_bwAnalysisMap) {
    delete bwResult.second;
  }
  m_bwAnalysisMap.clear();
}

const BackwardAnalysisResult* CombinedAnalysisResult::addBackwardAnalysis(AttackContext context)
{
  BackwardAnalysisResult* bw = new BackwardAnalysisResult(m_fwAnalysis, context);
  m_bwAnalysisMap.insert(std::make_pair(context, bw));
  return bw;
}

void CombinedAnalysisResult::printResult() const
{
  for (auto bwResult : m_bwAnalysisMap) {
    AttackContext c = bwResult.first;
    const BackwardAnalysisResult* result = bwResult.second;
    bool good = !result->isVulnerable();
    std::cout << AttackContextHelper::getName(c) << ": "
              << (good ? "true" : "false");
    if (!good) {
      std::cout << "("
                << result->getIntersection()->generateSatisfyingExample()
                << ")";
    } else if (result->hasPostAttackImage()) {
      std::cout << "("
                << result->getAttackPostImage()->generateSatisfyingExample()
                << ")";
    }
    std::cout << ", ";
  }
}

void CombinedAnalysisResult::printDetailedResults() const
{
  std::cout << "File: " << this->getFileName();
  for (auto bwResult : m_bwAnalysisMap) {
    AttackContext c = bwResult.first;
    const BackwardAnalysisResult* result = bwResult.second;
    bool good = !result->isVulnerable();
    std::cout << AttackContextHelper::getName(c) << ": "
              << (good ? "true" : "false");
    if (!good) {
      std::cout << ", postImage: "
                << result->getIntersection()->generateSatisfyingExample();
      std::cout << ", preImage: "
                << result->getPreImage()->generateSatisfyingExample();
      // std::cout << std::endl;
      // result->getIntersection()->toDotAscii(0);
    }
    std::cout << ", ";
  }
}

BackwardAnalysisResult::BackwardAnalysisResult(
  ForwardAnalysisResult& fwResult, AttackContext context)
  : m_fwResult(fwResult)
  , m_name(AttackContextHelper::getName(context))
  , m_attack(AttackPatterns::getAttackPatternForContext(context))
  , m_context(context)
  , m_intersection(nullptr)
  , m_preimage(nullptr)
  , m_post_attack(nullptr)
{
  this->init();
}

BackwardAnalysisResult::BackwardAnalysisResult(
  ForwardAnalysisResult& fwResult, const StrangerAutomaton* attack, const std::string& name)
  : m_fwResult(fwResult)
  , m_name(name)
  , m_attack(new StrangerAutomaton(attack))
  , m_context(AttackContext::None)
  , m_intersection(nullptr)
  , m_preimage(nullptr)
  , m_post_attack(nullptr)
{
  this->init();
}

BackwardAnalysisResult::~BackwardAnalysisResult()
{
  if (m_preimage) {
    delete m_preimage;
    m_preimage = nullptr;
  }
  if (m_attack) {
    delete m_attack;
    m_attack = nullptr;
  }
  if (m_intersection) {
    delete m_intersection;
    m_intersection = nullptr;
  }
  if (m_post_attack) {
    delete m_post_attack;
    m_post_attack = nullptr;
  }
}

void BackwardAnalysisResult::init()
{
  const StrangerAutomaton* postImage = m_fwResult.getPostImage();
  m_intersection = this->getAttack()->computeAttackPatternOverlap(postImage, m_attack);
  if (this->isVulnerable()) {
    // Only compute BW analysis if vulnerable
    try {
      AnalysisResult result = this->getAttack()->computePreImage(m_intersection, m_fwResult.getFwAnalysisResult());
      m_preimage = new StrangerAutomaton(this->getAttack()->getPreImage(result));
      //  clean up target analysis result
      AnalysisResultHelper::DeleteResults(result);
    } catch (StrangerStringAnalysisException const &e) {
      throw;
    }
  } else {
    // Otherwise see what happens if attack pattern is used for a forward analysis
    AnalysisResult result = this->getAttack()->computeTargetFWAnalysis(m_attack);
    const StrangerAutomaton* post = this->getAttack()->getPostImage(result);
    if (post) {
      m_post_attack = new StrangerAutomaton(post);
    } else {
      m_post_attack = nullptr;
    }
  }
}

void BackwardAnalysisResult::writeResultsToFile(const fs::path& dir) const
{
  fs::create_directories(dir);

  fs::path output_image_file(dir / fs::path("post_image_attack_" + this->getName() + ".dot"));
  m_attack->toDotFileAscii(output_image_file.string(), 0);
  fs::path output_image_file_bdd(dir / fs::path("post_image_attack_" + this->getName() + ".bdd"));
  m_attack->exportToFile(output_image_file_bdd.string());

  fs::path output_file(dir / fs::path("post_image_intersection_" + this->getName() + ".dot"));
  m_intersection->toDotFileAscii(output_file.string(), 0);
  fs::path output_file_bdd(dir / fs::path("post_image_intersection_" + this->getName() + ".bdd"));
  m_intersection->exportToFile(output_file_bdd.string());

  if (this->isVulnerable()) {
    fs::path output_file_pre(dir / fs::path("pre_image_" + this->getName() + ".dot"));
    getPreImage()->toDotFileAscii(output_file_pre.string(), 0);
    fs::path output_file_pre_bdd(dir / fs::path("pre_image_" + this->getName() + ".bdd"));
    getPreImage()->exportToFile(output_file_pre_bdd.string());
  }
}

ForwardAnalysisResult::ForwardAnalysisResult(const fs::path& target_dep_graph_file_name,
                                             const std::string& input_field_name,
                                             StrangerAutomaton* automaton)
  : m_attack(new SemAttack(target_dep_graph_file_name, input_field_name))
  , m_result()
  , m_input(automaton)
  , m_postImage(nullptr)
{
}

ForwardAnalysisResult::~ForwardAnalysisResult()
{
  finishAnalysis();
  delete m_input;
  if (m_postImage) {
    delete m_postImage;
    m_postImage = nullptr;
  }
}

void ForwardAnalysisResult::doAnalysis()
{
  m_result = m_attack->computeTargetFWAnalysis(m_input);
  const StrangerAutomaton* post = this->getAttack()->getPostImage(m_result);
  if (post) {
    m_postImage = new StrangerAutomaton(post);
  } else {
    m_postImage = nullptr;
  }
}

void ForwardAnalysisResult::writeResultsToFile(const fs::path& dir) const
{
  fs::create_directories(dir);

  fs::path output_file(dir / fs::path("post_image_ascii.dot"));
  this->getPostImage()->toDotFileAscii(output_file.string(), 0);  

  fs::path output_file_bdd(dir / fs::path("post_image.bdd"));
  this->getPostImage()->exportToFile(output_file_bdd.string());
}

void ForwardAnalysisResult::finishAnalysis() {
  if (m_attack) {
    delete m_attack;
    m_attack = nullptr;
  }
  AnalysisResultHelper::DeleteResults(m_result);
}

SemAttack::SemAttack(const fs::path& target_dep_graph_file_name, const string& input_field_name)
  : target_dep_graph_file_name(target_dep_graph_file_name)
  , input_field_name(input_field_name)
  , m_print_dots(false)
{
}

SemAttack::SemAttack(const std::string& target_dep_graph_file_name, const string& input_field_name)
  : target_dep_graph_file_name(target_dep_graph_file_name)
  , input_field_name(input_field_name)
  , m_print_dots(false)
{
}

void SemAttack::init()
{
    // read dep graphs
    this->target_dep_graph = DepGraph::parseDotFile(target_dep_graph_file_name.string());

    // initialize input nodes
    this->target_uninit_field_node = target_dep_graph.findInputNode(input_field_name);
    if (target_uninit_field_node == NULL) {
        throw StrangerStringAnalysisException("Cannot find input node " + input_field_name + " in target dep graph.");
    }
    message(stringbuilder() << "target uninit node(" << target_uninit_field_node->getID() << ") found for field " << input_field_name << ".");

    // initialize input relevant graphs
    this->target_field_relevant_graph = target_dep_graph.getInputRelevantGraph(target_uninit_field_node);

    if (m_print_dots) {
      message(this->target_dep_graph.toDot());
      message(this->target_field_relevant_graph.toDot());
    }
}

SemAttack::~SemAttack() {
}

void SemAttack::writeResultsToFile(const fs::path& dir) const
{
  fs::create_directories(dir);

  fs::path output_file(dir / fs::path("input_depgraph.dot"));

  this->target_dep_graph.dumpDot(output_file.string());
}


void SemAttack::message(const std::string& msg) const {
    cout << endl << "~~~~~~~~~~~>>> SemAttack says: " << msg << endl;
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
//    perfInfo.reset();
}


/**
 * Computes sink post image for target, first time
 */
AnalysisResult SemAttack::computeTargetFWAnalysis(const StrangerAutomaton* inputAuto)
{
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

    // Copy the input
    targetAnalysisResult[target_uninit_field_node->getID()] = new StrangerAutomaton(inputAuto);

    ImageComputer targetAnalyzer(false, false);

    try {
        message("starting forward analysis for target...");
        targetAnalyzer.doForwardAnalysis_SingleInput(target_dep_graph, target_field_relevant_graph, targetAnalysisResult);
        message("...finished forward analysis for target.");        
    } catch (StrangerStringAnalysisException const &e) {
      //  clean up target analysis result
      AnalysisResultHelper::DeleteResults(targetAnalysisResult);
      throw;
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
  return result.at(target_dep_graph.getRoot()->getID());
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

  if (m_print_dots) {
    message("Sanitizer Automaton");
    postImage->toDotAscii(1);
    message("Example sanitizer string:");
    message(postImage->generateSatisfyingExample());

    message("Attack Pattern Automaton");
    attackPattern->toDotAscii(1);
    message("Example attack pattern string:");
    message(attackPattern->generateSatisfyingExample());
  }
  
  StrangerAutomaton* intersection = postImage->intersect(attackPattern);

  if (m_print_dots) {
    message("Intersection Automaton");
    intersection->toDotAscii(1);

    if (intersection->isEmpty()) {
      message("No intersection, validation function is good!");
    } else {
      message("Intersection between attack pattern and sanitizer!");
      message(intersection->generateSatisfyingExample());
    }
  }

  return intersection;
}

AnalysisResult SemAttack::computePreImage(const StrangerAutomaton* intersection,
                                          const AnalysisResult& result) const
{
  try {
    message("starting backward analysis...");
    ImageComputer analyzer(false, false);
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
