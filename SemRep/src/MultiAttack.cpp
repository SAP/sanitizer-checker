/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * MultiAttack.cpp
 *
 * Copyright (C) 2020 SAP SE
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
 * Authors: Thomas Barber
 */

#include "SemAttack.hpp"
#include "AttackPatterns.hpp"
#include "MultiAttack.hpp"
#include "StrangerAutomaton.hpp"

#include <iostream>
#include <fstream>
#include <thread>
#include <algorithm>
#include <functional>
#include <unordered_set>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

namespace asio = boost::asio;

MultiAttack::MultiAttack(const std::string& graph_directory, const std::string& output_dir, const std::string& input_field_name, StrangerAutomaton* input_auto)
  : m_graph_directory(graph_directory)
  , m_output_directory(output_dir)
  , m_input_name(input_field_name)
  , m_dot_paths()
  , m_results()
  , m_result_hash_map()
  , m_automata()
  , m_groups()
  , m_analyzed_contexts()
  , results_mutex()
  , m_nThreads(boost::thread::hardware_concurrency())
  , m_concats(0)
  , m_compute_preimage(true)
  , m_input_automaton(nullptr)
{
  if (input_auto == nullptr) {
    m_input_automaton = StrangerAutomaton::makeAnyString();
  } else {
    m_input_automaton = input_auto->clone();
  }
  fillCommonPatterns();
}

MultiAttack::~MultiAttack() {

  for (auto iter : m_results) {
    delete iter;
  }
  m_results.clear();
  m_result_hash_map.clear();
  for (auto iter : m_automata) {
    delete iter;
  }
  m_automata.clear();
}

void MultiAttack::writeResultsToFile() const {
  fs::path output(m_output_directory / fs::path("semattack_groups.csv"));
  std::ofstream ofs;
  ofs.open (output.string(), std::ofstream::out);
  printResults(ofs, true);
  ofs.close();

  fs::path output_files(m_output_directory / fs::path("semattack_files.csv"));
  std::ofstream ofs_files;
  ofs_files.open (output_files.string(), std::ofstream::out);
  printFiles(ofs_files);
  ofs_files.close();

  fs::path output_sum(m_output_directory / fs::path("semattack_summary.csv"));
  std::ofstream ofs_sum;
  ofs_sum.open (output_sum.string(), std::ofstream::out);
  m_groups.printOverlapSummary(ofs_sum, m_analyzed_contexts);
  ofs_sum.close();

  fs::path output_sum_pc(m_output_directory / fs::path("semattack_summary_percent.csv"));
  std::ofstream ofs_sum_pc;
  ofs_sum_pc.open (output_sum_pc.string(), std::ofstream::out);
  m_groups.printOverlapSummary(ofs_sum_pc, m_analyzed_contexts, true);
  ofs_sum_pc.close();
}

void MultiAttack::printFiles(std::ostream& os) const {
  os << "Printing files:" << std::endl;
  int i = 0;
  for (auto result : m_results) {
    if (result->isDone()) {
      os << i << ", ";
      os << result->getFileName() << ", ";
      os << result->getCountWithDuplicates() << ", ";
      os << result->getCount() << ", ";
      result->printResult(os, true, m_analyzed_contexts);
      os << std::endl;
      ++i;
    }
  }
}

void MultiAttack::printResults(std::ostream& os, bool printFiles) const
{
  os << "# Found " << this->m_dot_paths.size() << " dot files" << std::endl;
  os << "# Computed images with pool of " << m_nThreads << " threads." << std::endl;
  os << "# Printing Groups:" << std::endl;
  m_groups.printGroups(os, printFiles, m_analyzed_contexts);
}

int MultiAttack::countDone() const
{
  int done = 0;
  for (auto result : m_results) {
    if (result->isDone()) {
      done++;
    }
  }
  return done;
}
  
void MultiAttack::printStatus() const
{
  int done = countDone();
  int total = m_results.size();
  double percent = total > 0 ? ((double) done / (double) total) * 100.0 : 0.0;
  std::cout << "Status: completed " << done << "/" << total << "(" << percent << "%)" << std::endl;
  m_groups.printStatus(std::cout);
}

void MultiAttack::computeAttackPatternOverlap(CombinedAnalysisResult* result, AttackContext context)
{
  const std::string& file = result->getAttack()->getFileName();
  std::cout << "Doing backward analysis for file: "
            << file
            << ", context: " << AttackContextHelper::getName(context)
            << std::endl;
  try {
    fs::path dir(m_output_directory / result->getAttack()->getFile());
    BackwardAnalysisResult* bw = result->addBackwardAnalysis(context);
    bw->doAnalysis(m_compute_preimage, m_singleton_intersection);
    bw->writeResultsToFile(dir);
    bw->finishAnalysis();
  } catch (StrangerStringAnalysisException const &e) {
    std::cout << "EXCEPTION! Analysing file: " << file << " in thread " << std::this_thread::get_id() << std::endl;
    std::cerr << e.what() << std::endl;
  } catch (const std::exception& e) {
    std::cout << "EXCEPTION! Analysing file: " << file << " in thread " << std::this_thread::get_id() << std::endl;
    std::cerr << e.what() << std::endl;
  }
}

void MultiAttack::computeAttackPatternOverlapForMetadata(CombinedAnalysisResult* result)
{
  const std::string& file = result->getAttack()->getFileName();
  std::cout << "Doing context specific backward analysis for file: "
            << file
            << std::endl;
  fs::path dir(m_output_directory / result->getAttack()->getFile());
  result->doMetadataSpecificAnalysis(dir, m_compute_preimage, m_singleton_intersection);
}

CombinedAnalysisResult* MultiAttack::findOrCreateResult(const fs::path& file, DepGraph& target_dep_graph) {
  // Find the result for the given hash
  const std::lock_guard<std::mutex> lock(this->results_mutex);
  CombinedAnalysisResult* result = nullptr;
  int hash = target_dep_graph.get_metadata().get_sanitizer_hash();
  auto search = this->m_result_hash_map.find(hash);
  if(target_dep_graph.get_metadata().is_initialized() && // Legacy failsafe to support depgraphs without the hash field
     search != this->m_result_hash_map.end()) {
    if (search->second->addMetadata(target_dep_graph.get_metadata())) {
      std::cout << "Incremeted count to " << search->second->getCount() << " for " << search->second->getFileName() << std::endl;
    } else {
      // This is a bit too verbose
      //std::cout << "Discarding duplicate depgraph: " << file.string() << " (total: " << search->second->getCountWithDuplicates() << ")" << std::endl;
    }
  } else {
    std::cout << "Ading file: " << file.string() << " to worker queue." << std::endl;
    result = new CombinedAnalysisResult(file, target_dep_graph, m_input_name, m_input_automaton);
    // Add to results
    this->m_results.push_back(result);
    // Only insert into hash map if metadata is initialized
    if (target_dep_graph.get_metadata().is_initialized()) {
      this->m_result_hash_map.insert(std::make_pair(hash, result));
    }
  }
  return result;
}

void MultiAttack::computeImages(CombinedAnalysisResult* result) {
  if (result == nullptr) {
    return;
  }
  const StrangerAutomaton* postImage = NULL;
  const std::string file = result->getFileName();
  fs::path dir(m_output_directory / result->getInputPath());
  std::cout << "Analysing file: " << file << std::endl;
  // Reduce debug prints
  result->getAttack()->setPrint(false);
  try {
    // Forward Analysis
    result->getAttack()->init();
    result->getFwAnalysis().doAnalysis(m_concats);
    postImage = result->getFwAnalysis().getPostImage();
    result->getAttack()->writeResultsToFile(dir);
    result->getFwAnalysis().writeResultsToFile(dir);
  } catch (...) {
    if (postImage != nullptr) {
      delete postImage;
      postImage = nullptr;
    }
    std::cout << "EXCEPTION! In FW analysis: " << file << " in thread " << std::this_thread::get_id() << std::endl;
  }
  
  // Backward analysis
  for (auto c : m_analyzed_contexts) {
    try {
      computeAttackPatternOverlap(result, c);
    } catch(...) {
      std::cout << "EXCEPTION! In BW analysis: " << file << " in thread " << std::this_thread::get_id() << std::endl;
    }
  }

  // Additional backward analysis for generated payloads
  computeAttackPatternOverlapForMetadata(result);   
  
  // Finish up (delete the semattack object)
  result->finishAnalysis();

  // Mutex Lock
  const std::lock_guard<std::mutex> lock(this->results_mutex);
  std::cout << "Finished analysis of " << file << std::endl;
  std::cout << "Inserting results into groups for " << file << std::endl;
  this->m_groups.addAutomaton(postImage, result);
  std::cout << "Finished inserting results into groups for " << file << std::endl;
  printStatus();
}

void MultiAttack::loadDepGraphs() {
  findDotFiles();
  boost::asio::thread_pool pool(this->m_nThreads);
  std::cout << "Computing post images with pool of " << m_nThreads << " threads." << std::endl;

  // Add all files first
  for (const auto& file : this->m_dot_paths) {
    asio::post(pool, [this, &pool, file]() {
        try {
          DepGraph target_dep_graph = DepGraph::parseDotFile(file.string());
          {
            findOrCreateResult(file, target_dep_graph);
          }
        } catch(std::exception& e) {
          cerr << "Error parsing " << file.string() << ": " << e.what() << "\n";
        }
      });
  }
  pool.join();
  printStatus();
}

void MultiAttack::doAnalysis() {
  boost::asio::thread_pool pool(this->m_nThreads);
  std::cout << "Starting analysis " << m_nThreads << " threads." << std::endl;

  // Start the analysis
  for (auto result : m_results) {
    asio::post(pool, std::bind(&MultiAttack::computeImages, this, result));
  }
  pool.join();
  std::cout << "Forward analysis finished!" << std::endl;
  printStatus();
  this->writeResultsToFile();  
}
  
void MultiAttack::compute() {
  loadDepGraphs();
  doAnalysis();
}

void MultiAttack::addAttackPattern(AttackContext context)
{
  m_analyzed_contexts.push_back(context);
}

void MultiAttack::fillCommonPatterns() {

  StrangerAutomaton* a = nullptr;

  // Add NULL
  m_groups.createGroup(nullptr, "NULL");

  // Add empty automaton
  a = StrangerAutomaton::makeEmptyString();
  m_automata.push_back(a);
  m_groups.createGroup(a, "Empty");

  // Add all strings
  a = StrangerAutomaton::makeAnyString();
  m_automata.push_back(a);
  m_groups.createGroup(a, "SigmaStar");

  // HTML Escaped
  a = AttackPatterns::getHtmlEscaped();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscaped");

  // HTML Escape < >
  a = AttackPatterns::getEncodeHtmlTagsOnly();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscapeTags");

  // Allowed characters in innerHTML, excludes ">", "<", "'", """,
  // "&" is only considered harmful if it is not escaped
  a = AttackPatterns::getHtmlNoSlashesPattern();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscapeNoSlashes");

  // Allowed characters in innerHTML, excludes ">", "<", "'", """, "`"
  // "&" is only considered harmful if it is not escaped
  a = AttackPatterns::getHtmlBacktickPattern();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscapeBacktick");

  // HTML Removed
  a = AttackPatterns::getHtmlRemoved();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLRemoved");

  // HTML Removed with slashes allowed
  a = AttackPatterns::getHtmlRemovedNoSlash();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLRemovedNoSlash");

  // HTML Escape < > &
  a = AttackPatterns::getEncodeHtmlCompat();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscape<>&");

  // HTML Escape < > & "
  a = AttackPatterns::getEncodeHtmlNoQuotes();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscape<>&\"");

  // HTML Escape < > & " '
  a = AttackPatterns::getEncodeHtmlQuotes();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscape<>&\"'");

  // HTML Escape < > & " /
  a = AttackPatterns::getEncodeHtmlSlash();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLEscape<>&\"'/");

  // HTML Attribute Escaped
  a = AttackPatterns::getHtmlAttrEscaped();
  m_automata.push_back(a);
  m_groups.createGroup(a, "HTMLAttrEscaped");

  // Javascript Escaped
  a = AttackPatterns::getJavascriptEscaped();
  m_automata.push_back(a);
  m_groups.createGroup(a, "Javascript");

  // URL Escaped
  a = AttackPatterns::getUrlEscaped();
  m_automata.push_back(a);
  m_groups.createGroup(a, "URL");

  // After UriComponentEncode
  a = AttackPatterns::getUrlComponentEncoded();
  m_automata.push_back(a);
  m_groups.createGroup(a, "UriComponentEncoded");

  // Double UriComponentEncode
  a = StrangerAutomaton::encodeURIComponent(a);
  m_automata.push_back(a);
  m_groups.createGroup(a, "DoubleUriComponentEncoded");
}

void MultiAttack::findDotFiles() {
  this->m_dot_paths = getDotFilesInDir(this->m_graph_directory);
}

std::vector<fs::path> MultiAttack::getDotFilesInDir(fs::path const &dir)
{
  return getFilesInPath(dir, ".dot");
}

/**
 * \brief   Return the filenames of all files that have the specified extension
 *          in the specified directory and all subdirectories.
 */
std::vector<fs::path> MultiAttack::getFilesInPath(fs::path const & root, std::string const & ext)
{
  std::vector<fs::path> paths;

  if (fs::exists(root)) {
    // Recurse into directories
    if (fs::is_directory(root)) {
      for (auto const & entry : fs::recursive_directory_iterator(root)) {
        if (fs::is_regular_file(entry) && entry.path().extension() == ext) {
          paths.emplace_back(entry.path());
        }
      }
    // Single file
    } else {
      if (root.extension() == ext) {
          paths.emplace_back(root);
      }
    }
  }
  return paths;
}
