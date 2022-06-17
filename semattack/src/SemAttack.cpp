/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * SemAttack.cpp
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
#include <boost/filesystem.hpp>

#include "SemAttack.hpp"
#include "AttackPatterns.hpp"
#include "exceptions/StrangerException.hpp"

PerfInfo& SemAttack::perfInfo = PerfInfo::getInstance();

namespace fs = boost::filesystem;

CombinedAnalysisResult::CombinedAnalysisResult(const fs::path& target_dep_graph_file_name,
                                               DepGraph target_dep_graph_,
                                               const std::string& input_field_name,
                                               StrangerAutomaton* automaton)
  : m_fwAnalysis(target_dep_graph_file_name, input_field_name, target_dep_graph_, automaton)
  , m_bwAnalysisMap()
  , m_inputfile(target_dep_graph_file_name)
  , m_input_name(input_field_name)
  , m_metadata()
  , m_duplicate_count(1)
  , m_done(false)
  , m_metadataAnalysisMap()
  , m_stringAnalysisMap()
{
  m_metadata.push_back(target_dep_graph_.get_metadata());
}

CombinedAnalysisResult::~CombinedAnalysisResult()
{
  for (auto bwResult : m_bwAnalysisMap) {
    delete bwResult.second;
  }
  m_bwAnalysisMap.clear();

  for (auto mdResult : m_stringAnalysisMap) {
    if (mdResult.second != nullptr) {
      delete mdResult.second;
    }
  }
  m_metadataAnalysisMap.clear();
}

bool CombinedAnalysisResult::operator< (const CombinedAnalysisResult &other) const {
  // Sort by the complexity of the input dependency graph
  return this->getAttack() < other.getAttack();
}

BackwardAnalysisResult* CombinedAnalysisResult::addBackwardAnalysis(AttackContext context)
{
  BackwardAnalysisResult* bw = new BackwardAnalysisResult(m_fwAnalysis, context);
  m_bwAnalysisMap.insert(std::make_pair(context, bw));
  return bw;
}

bool CombinedAnalysisResult::hasBackwardanalysisResult(AttackContext context) const
{
  auto search = m_bwAnalysisMap.find(context);
  if (search != m_bwAnalysisMap.end()) {
    return true;
  }
  return false;
}

BackwardAnalysisResult* CombinedAnalysisResult::doBackwardAnalysisForPayload(const std::string& payload, const fs::path& output_dir, bool computePreImage, bool singletonIntersection, bool outputDotfiles, bool attack_forward)
{
  if (payload.empty()) {
    //std::cout << "Skipping empty payload." << std::endl;
    return nullptr;
  }
  BackwardAnalysisResult* bw = nullptr;

  // Check if we already did the analysis for this string
  if (m_stringAnalysisMap.find(payload) != m_stringAnalysisMap.end()) {
    // Just return existing analysis
    bw = m_stringAnalysisMap.at(payload);
  } else {
    std::cout << "Ouput: " << output_dir.string() <<": Doing backward analysis for payload: " << payload << std::endl;
    try {
      StrangerAutomaton* a = StrangerAutomaton::makeContainsString(payload);
      //a->toDotAscii(1);
      bw = new BackwardAnalysisResult(m_fwAnalysis, a, payload);
      bw->doAnalysis(computePreImage, singletonIntersection, attack_forward);
      if (bw && outputDotfiles) {
        bw->writeResultsToFile(output_dir);
      }
      bw->finishAnalysis();
    } catch (...) {
      std::cout << "EXCEPTION! Analysing in metadata specific analysis" << std::endl;
    }

    // Add to the map
    m_stringAnalysisMap.insert(std::make_pair(payload, bw));
  }
  return bw;
}

void CombinedAnalysisResult::doMetadataSpecificAnalysis(const fs::path& output_dir, bool computePreImage, bool singletonIntersection, bool outputDotfiles, bool attack_forward)
{
  // Create a specific payload for each metadata entry
  unsigned int i = 0;
  static std::vector<std::string> functions = { "taintfoxLog(\"xss\")", "taintfoxLog('xss')", "taintfoxLog`xss`" };
  static std::vector<bool> use_solidus = { false, true };
  const std::string file = getFileName();
  m_atLeastOnePayloadVulnerable = false;
  m_allPayloadsVulnerable = true;
  m_allPayloadsErrored = true;
  for (const Metadata &m : m_metadata) {
    std::vector<BackwardAnalysisResult*> bws;
    for (auto& f : functions) {
      for (bool b : use_solidus) {
        BackwardAnalysisResult* bw = nullptr;
        // Normal payload
        std::string payload = m.generate_exploit_from_scratch(f, b);
        bw = doBackwardAnalysisForPayload(payload, output_dir, computePreImage, singletonIntersection, outputDotfiles, attack_forward);
        if (bw != nullptr) {
          m_atLeastOnePayloadVulnerable |= bw->isVulnerable();
          if (!bw->isVulnerable()) {
            m_allPayloadsVulnerable = false;
          } else {
            std::cout << file << ": " << payload << " --> " << bw->get_preimage_example() << std::endl;
          }
          if (!bw->isErrored()) {
            m_allPayloadsErrored = false;
          } else {
            std::cout << "doMetadataSpecificAnalysis::ERROR computing pre-image for payload:" << payload << " file: " << file << std::endl;
          }
          bws.push_back(bw);
        }
        // Attribute payload
        std::string attr_payload = m.generate_attribute_exploit_from_scratch(f, b);
        bw = doBackwardAnalysisForPayload(attr_payload, output_dir, computePreImage, singletonIntersection, outputDotfiles, attack_forward);
        if (bw != nullptr) {
          m_atLeastOnePayloadVulnerable |= bw->isVulnerable();
          if (!bw->isVulnerable()) {
            m_allPayloadsVulnerable = false;
          } else {
            std::cout << file << ": " << attr_payload << " --> " << bw->get_preimage_example() << std::endl;
          }
          if (!bw->isErrored()) {
            m_allPayloadsErrored = false;
          } else {
            std::cout << "doMetadataSpecificAnalysis::ERROR computing pre-image for payload:" << payload << " file: " << file << std::endl;
          }
          bws.push_back(bw);
        }
      }
    }
    // Add to map
    m_metadataAnalysisMap.insert(std::make_pair(&m, bws));
  }
}

void CombinedAnalysisResult::printHeader(std::ostream& os, const std::vector<AttackContext>& contexts) const
{
  for (auto c : contexts) {
    os << AttackContextHelper::getName(c);
    os << ", inclusion, post, pre, ";
  }
}

void CombinedAnalysisResult::printResult(std::ostream& os, bool printHeader, const std::vector<AttackContext>& contexts) const
{
  for (auto c : contexts) {
    if (this->hasBackwardanalysisResult(c)) {
      const BackwardAnalysisResult* result = m_bwAnalysisMap.at(c);
      if (result) {
        result->printResult(os, printHeader);
      }
    }
  }
}

bool CombinedAnalysisResult::hasAtLeastOneBypass() const {
  bool bypass = false;
  for (auto& map : m_metadataAnalysisMap) {
    for (auto& bw : map.second) {
      if (bw != nullptr) {
        if (!bw->isErrored() && bw->isVulnerable() && !bw->get_preimage_example().empty()) {
          bypass = true;
          break;
        }
      }
    }
  }
  return bypass;
}

void CombinedAnalysisResult::printGeneratedPayloadHeader(std::ostream& os) {
  // Headers
  os << "filename,name,";
  os << "sanitized,inclusion,post,pre,";
  os << "one_vulnerable,all_vulnerable,";
  os << "exploits_equal,";
  os << "preimage_exploit,";
  os << "original_exploit,";
  Metadata::printHeader(os);
  os << std::endl;
}

void CombinedAnalysisResult::printGeneratedPayloads(std::ostream& os) const
{
  for (auto& map : m_metadataAnalysisMap) {
    const Metadata* m = map.first;
    for (auto& bw : map.second) {
      os << getFileName() << ",";
      bw->printResult(os, true);
      os << (m_atLeastOnePayloadVulnerable ? "true" : "false");
      os << ",";
      os << (m_allPayloadsVulnerable ? "true" : "false");
      os << ",";
      std::string preimage_exploit = bw->get_preimage_example();
      std::string postimage_exploit = bw->get_intersection_example();
      os << ((preimage_exploit == postimage_exploit) ? "true" : "false") << ",";
      os << m->generate_exploit_url(preimage_exploit) << ",";
      os << m->generate_exploit_url(postimage_exploit) << ",";
      m->print(os);
      os << std::endl;
    }
  }
}

void CombinedAnalysisResult::printUnmatchedUuids(std::ostream& os) const
{
  if (!getFwAnalysis().isErrored()) {
    if (!hasAtLeastOnePayload()) {
      for (auto& m : m_metadata) {
        os << m.get_uuid() << std::endl;
      }
    }
  }
}

bool CombinedAnalysisResult::addMetadata(const Metadata& metadata)
{
  // Loop over the existing metadata for this entry
  bool isNew = true;
  int id = metadata.get_twenty_five_million_flows_id();
  if (metadata.is_initialized()) {
    // Check the hash map
    auto search = this->m_finding_metadata_map.find(id);
    if (search != this->m_finding_metadata_map.end()) {
      isNew = false;
    } else {
    }
  }

  if (isNew) {
    m_metadata.push_back(metadata);
    if (metadata.has_valid_exploit()) {
      m_finding_metadata_map.insert(std::make_pair(id, &m_metadata.back()));
    }
  }

  // Increment the total
  m_duplicate_count++;
  return isNew;
}

std::set<std::string> CombinedAnalysisResult::getUniqueDomains() const
{
  std::set<std::string> s;

  if (!getFwAnalysis().isErrored()) {
      for (auto m : m_metadata) {
        s.insert(m.get_base_domain());
      }
  }
  return s;
}

std::set<std::string> CombinedAnalysisResult::getUniqueDomainsWithPayload() const
{
  std::set<std::string> s;

  if (!getFwAnalysis().isErrored()) {
    for (auto m : m_metadata) {
      if (m.has_valid_exploit()) {
        s.insert(m.get_base_domain());
      }
    }
  }
  return s;
}

std::set<std::string> CombinedAnalysisResult::getVulnerableDomainsWithPayload() const
{
  std::set<std::string> s;

  if (!getFwAnalysis().isErrored()) {
    for (const Metadata &m : m_metadata) {
      if (m.has_valid_exploit()) {
        if (m_metadataAnalysisMap.find(&m) != m_metadataAnalysisMap.end()) {
          for (const BackwardAnalysisResult* b : m_metadataAnalysisMap.at(&m)) {
            if (b->isVulnerable()) {
              s.insert(m.get_base_domain());
              break;
            }
          }
        }
      }
    }
  }
  return s;
}

std::set<int> CombinedAnalysisResult::getUniqueInjectionPoints() const
{
  std::set<int> ids;

  // Depending on how the metadata is added in addMetadata, the
  // domains might be already unique, but loop anyway in case this changes
  for (auto m : m_metadata) {
    ids.insert(m.get_twenty_five_million_flows_id());
  }
  return ids;
}

bool CombinedAnalysisResult::isFilterSuccessful(const AttackContext& context) const
{
  bool success = false;
  if (this->hasBackwardanalysisResult(context)) {
    const BackwardAnalysisResult* result = m_bwAnalysisMap.at(context);
    if (!result->isErrored()) { // Otherwise errors count as success
      success = result->isSafe();
    }
  }
  return success;
}

bool CombinedAnalysisResult::isFilterContained(const AttackContext& context) const
{
  bool success = false;
  if (this->hasBackwardanalysisResult(context)) {
    const BackwardAnalysisResult* result = m_bwAnalysisMap.at(context);
    if (!result->isErrored()) { // Otherwise errors count as success
      success = result->isContained();
    }
  }
  return success;
}

void CombinedAnalysisResult::finishAnalysis()
{
  getFwAnalysis().finishAnalysis();
  m_done = true;
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
  , m_error(AnalysisError::None)
  , m_isErrored(true)
  , m_isSafe(false)
  , m_isContained(false)
{
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
  , m_isErrored(true)
  , m_isSafe(false)
  , m_isContained(false)
{
}

BackwardAnalysisResult::~BackwardAnalysisResult()
{
  finishAnalysis();
}

void BackwardAnalysisResult::doAnalysis(bool computePreImage, bool singletonIntersection, bool doPostAttack)
{
  const StrangerAutomaton* postImage = m_fwResult.getPostImage();
  m_intersection = this->getAttack()->computeAttackPatternOverlap(postImage, m_attack);
  m_isErrored = true;
  m_isSafe = false;
  m_isContained = false;
  if ((m_intersection) && (!m_intersection->isNull())) {
    m_isErrored = false;
    if (this->isVulnerable()) {
      // Only compute BW analysis if vulnerable
      m_isSafe = false;
      m_isContained = postImage->checkInclusion(m_attack);
      // Cache examples for printing
      m_intersection_example = m_intersection->generateSatisfyingExample();
      if (computePreImage) {
        try {
          AnalysisResult result;
          if (singletonIntersection) {
            StrangerAutomaton* singleton = m_intersection->generateSatisfyingSingleton();
            result = this->getAttack()->computePreImage(singleton, m_fwResult.getFwAnalysisResult());
            delete singleton;
          } else {
            result = this->getAttack()->computePreImage(m_intersection, m_fwResult.getFwAnalysisResult());
          }
          const StrangerAutomaton* preimage = this->getAttack()->getPreImage(result);
          if (preimage != nullptr) {
            m_preimage = new StrangerAutomaton(this->getAttack()->getPreImage(result));
            m_preimage_example = m_preimage->generateSatisfyingExample();
          } else {
            m_preimage = nullptr;
            m_preimage_example = "ERROR";
            throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
          }
          //  clean up target analysis result
        } catch (StrangerException const &e) {
          std::cout << "EXCEPTION caught in bw analysis: " << e.what() << std::endl;
          m_isErrored = true;
          m_error = e.getError();
          throw;
        }
      } else {
        m_preimage_example = "N/A";
      }
    } else {
      m_isSafe = true;
      if (doPostAttack) {
        // Otherwise see what happens if attack pattern is used for a forward analysis
        try {
          AnalysisResult result = this->getAttack()->computeTargetFWAnalysis(m_attack);
          const StrangerAutomaton* post = this->getAttack()->getPostImage(result);
          if (post) {
            m_post_attack = new StrangerAutomaton(post);
            m_post_attack_example = m_post_attack->generateSatisfyingExample();
          } else {
            m_post_attack = nullptr;
          }
        } catch (StrangerException const &e) {
          std::cout << "EXCEPTION caught in bw analysis: " << e.what() << std::endl;
          m_isErrored = true;
          m_error = e.getError();
          throw;
        }
      }
    }
  }
}

void BackwardAnalysisResult::finishAnalysis()
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

void BackwardAnalysisResult::printResult(std::ostream& os, bool printHeader) const
{
  bool error = this->isErrored();
  bool good =  this->isSafe();
  bool contained =  this->isContained();
  if (printHeader) {
    os << m_name << ",";
    }
  if (error) {
    os << "error,error,error,error,";
  } else {
    os << (good ? "true" : "false");
    os << ",";
    os << (contained ? "true" : "false");
    os << ",";     
    if (!good) {
      os << m_intersection_example;
      os << ",";
      os << m_preimage_example;
        os << ",";
    } else {
      os << m_post_attack_example;
      // No pre-image if no intersection
      os << ",N/A,";
    }
  }
}

void BackwardAnalysisResult::writeResultsToFile(const fs::path& dir) const
{
  fs::create_directories(dir);
  int with_sink = 0;
  
  if (m_attack) {
    fs::path output_image_file(dir / fs::path("post_image_attack_" + this->getName() + ".dot"));
    m_attack->toDotFileAscii(output_image_file.string(), with_sink);
    fs::path output_image_file_bdd(dir / fs::path("post_image_attack_" + this->getName() + ".bdd"));
    m_attack->exportToFile(output_image_file_bdd.string());
  }

  if (!this->isErrored()) {
    if (m_intersection) {
      fs::path output_file(dir / fs::path("post_image_intersection_" + this->getName() + ".dot"));
      m_intersection->toDotFileAscii(output_file.string(), with_sink);
      fs::path output_file_bdd(dir / fs::path("post_image_intersection_" + this->getName() + ".bdd"));
      m_intersection->exportToFile(output_file_bdd.string());
    }
    if (this->isVulnerable()) {
      const StrangerAutomaton* preimage = getPreImage();
      if (preimage) {
        fs::path output_file_pre(dir / fs::path("pre_image_" + this->getName() + ".dot"));
        preimage->toDotFileAscii(output_file_pre.string(), with_sink);
        fs::path output_file_pre_bdd(dir / fs::path("pre_image_" + this->getName() + ".bdd"));
        preimage->exportToFile(output_file_pre_bdd.string());
      }
    }
  }
}

bool BackwardAnalysisResult::isErrored() const {
  if (m_intersection == nullptr) {
    return m_isErrored;
  }
  return m_intersection->isNull();
}

bool BackwardAnalysisResult::isSafe() const
{
  if (m_intersection == nullptr) {
    return m_isSafe;
  }
  return (getIntersection()->isEmpty() || getIntersection()->checkEmptyString());
}

bool BackwardAnalysisResult::isContained() const
{
  const StrangerAutomaton* postImage = m_fwResult.getPostImage();
  if ((postImage == nullptr || this->m_attack == nullptr)) {
    return m_isContained;
  }
  return postImage->checkInclusion(this->m_attack);
}

ForwardAnalysisResult::ForwardAnalysisResult(const fs::path& target_dep_graph_file_name,
                                             const std::string& input_field_name,
                                             DepGraph target_dep_graph_,
                                             StrangerAutomaton* automaton)
  : m_attack(new SemAttack(target_dep_graph_file_name, target_dep_graph_, input_field_name))
  , m_result()
  , m_error(AnalysisError::None)
  , m_input(automaton->clone())
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
void ForwardAnalysisResult::doAnalysis(bool doConcat)
{
  try {
    m_result = m_attack->computeTargetFWAnalysis(m_input, doConcat);
  } catch (StrangerException const &e) {
    m_postImage = nullptr;
    m_error = e.getError();
    throw;
  } catch (...) {
    m_error = AnalysisError::Other;
    throw;
  }

  const StrangerAutomaton* post = this->getAttack()->getPostImage(m_result);
  if (post) {
    m_postImage = post->clone();
  } else {
    m_error = AnalysisError::MonaException;
    m_postImage = nullptr;
  }
}

void ForwardAnalysisResult::writeResultsToFile(const fs::path& dir) const
{
  fs::create_directories(dir);
  int with_sink = 1;

  fs::path output_file(dir / fs::path("post_image_ascii.dot"));
  this->getPostImage()->toDotFileAscii(output_file.string(), with_sink);  

  fs::path output_file_bdd(dir / fs::path("post_image.bdd"));
  this->getPostImage()->exportToFile(output_file_bdd.string());
}

void ForwardAnalysisResult::finishAnalysis() {
  if (m_attack) {
    delete m_attack;
    m_attack = nullptr;
  }
  m_result.clear();
}

bool ForwardAnalysisResult::isErrored() const {
  return (m_postImage == nullptr);
}


SemAttack::SemAttack(const fs::path& target_dep_graph_file_name, DepGraph target_dep_graph_, const string& input_field_name)
  : target_dep_graph_file_name(target_dep_graph_file_name)
  , input_field_name(input_field_name)
  , m_print_dots(false)
  , m_print(true)
  , target_dep_graph(target_dep_graph_)
{
}

SemAttack::SemAttack(const std::string& target_dep_graph_file_name, DepGraph target_dep_graph_, const string& input_field_name)
  : target_dep_graph_file_name(target_dep_graph_file_name)
  , input_field_name(input_field_name)
  , m_print_dots(false)
  , m_print(true)
  , target_dep_graph(target_dep_graph_)
{
}

bool SemAttack::operator<(const SemAttack &other)
{
  return this->target_dep_graph < other.target_dep_graph;
}

void SemAttack::init()
{
    // initialize input nodes
    this->target_uninit_field_node = target_dep_graph.findInputNode(input_field_name);
    if (target_uninit_field_node == NULL) {
      throw StrangerException(AnalysisError::MalformedDepgraph, "Cannot find input node " + input_field_name + " in target dep graph.");
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
  if (m_print) {
    cout << endl << "~~~~~~~~~~~>>> SemAttack says: " << msg << endl;
  }
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
AnalysisResult SemAttack::computeTargetFWAnalysis(const StrangerAutomaton* inputAuto, bool doConcat)
{
    message("computing target sink post image...");
    AnalysisResult targetAnalysisResult;
    UninitNodesList targetUninitNodes = target_dep_graph.getUninitNodes();

    // Do some checks on the metadata information
    const Metadata& m = target_dep_graph.get_metadata();
    if (m.is_initialized()) {
      /* if (m.get_max_encode_attr_chain_length() > 3) {
        throw StrangerException(AnalysisError::LargeEncodeAttrChain,
                                stringbuilder() << "Large EncodeAttr chain:"
                                << m.get_max_encode_attr_chain_length());
      } else if (m.get_max_encode_text_fragment_chain_length() > 3) {
        throw StrangerException(AnalysisError::LargeEncodeTextChain,
                                stringbuilder() << "Large EncodeTextFragment chain:"
                                << m.get_max_encode_text_fragment_chain_length());
      } */ /*else if (m.has_infinite_regex()) {
        throw StrangerException(AnalysisError::InfiniteRegex,
                                stringbuilder() << "Large EncodeTextFragment chain:"
                                << m.get_max_encode_text_fragment_chain_length());
      }*/
    }

    // initialize reference input nodes to bottom
    message("initializing reference inputs with bottom");
    for (auto uninit_node : targetUninitNodes) {
      targetAnalysisResult.set(uninit_node->getID(), StrangerAutomaton::makePhi(uninit_node->getID()));
    }
    // initialize uninit node that we are interested in with sigma star
    message(stringbuilder() << "initializing input node(" << target_uninit_field_node->getID() << ") with sigma star");

    // Copy the input
    targetAnalysisResult.set(target_uninit_field_node->getID(), inputAuto->clone());

    ImageComputer targetAnalyzer(doConcat, false, inputAuto->clone());

    try {
        message("starting forward aalysis for target...");
        targetAnalyzer.doForwardAnalysis_SingleInput(target_dep_graph, target_field_relevant_graph, targetAnalysisResult);
        message("...finished forward analysis for target.");        
    } catch (StrangerException const &e) {
      throw;
    }

    target_sink_auto = targetAnalysisResult.get(target_field_relevant_graph.getRoot()->getID());
    message("...computed target sink post image.");
    return targetAnalysisResult;
}

AnalysisResult SemAttack::computeTargetFWAnalysis()
{
  return computeTargetFWAnalysis(StrangerAutomaton::makeAnyString(target_uninit_field_node->getID()));
}

const StrangerAutomaton* SemAttack::getPostImage(const AnalysisResult& result) const
{
  return result.get(target_dep_graph.getRoot()->getID());
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
  if (postImage == nullptr || attackPattern == nullptr) {
    return nullptr;
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
    ImageComputer analyzer(false, false, nullptr);
    AnalysisResult analysis_result = analyzer.doBackwardAnalysis_GeneralCase(
      this->target_dep_graph, this->target_field_relevant_graph, intersection, result);
    message("...finished backward analysis.");
    return analysis_result;

  } catch (StrangerException const &e) {
    cerr << e.what();
  }
  return AnalysisResult();
}

const StrangerAutomaton* SemAttack::getPreImage(const AnalysisResult& result) const
{
  return result.get(this->target_uninit_field_node->getID());
}
