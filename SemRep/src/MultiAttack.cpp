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
#include <thread>
#include <algorithm>
#include <functional>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

namespace asio = boost::asio;

MultiAttack::MultiAttack(const std::string& graph_directory, const std::string& output_dir, const std::string& input_field_name)
  : m_graph_directory(graph_directory)
  , m_output_directory(output_dir)
  , m_input_name(input_field_name)
  , m_dot_paths()
  , m_results()
  , m_automata()
  , m_groups()
  , m_analyzed_contexts()
  , results_mutex()
  , m_nThreads(boost::thread::hardware_concurrency())
{
  fillCommonPatterns();
}

MultiAttack::~MultiAttack() {

  for (auto iter : m_results) {
    delete iter;
  }
  m_results.clear();

  for (auto iter : m_automata) {
    delete iter;
  }
  m_automata.clear();
}

void MultiAttack::printResults(bool printFiles) const
{
  std::cout << "Found " << this->m_dot_paths.size() << " dot files" << std::endl;
  std::cout << "Computed images with pool of " << m_nThreads << " threads." << std::endl;
  std::cout << "Printing Groups:" << std::endl;
  m_groups.printGroups(printFiles);
  if (printFiles) {
    std::cout << "Printing files:" << std::endl;
    int i = 0;
    for (auto result : m_results) {
      std::cout << i << ": ";
      result->printDetailedResults();
      // const AutomatonGroup* group = this->m_groups.getGroupForAutomaton(result->getFwAnalysis().getPostImage());
      // std::cout << " Group: ";
      // group->printSummary();
      std::cout << std::endl;
      ++i;
    }
  }
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
    const BackwardAnalysisResult* bw = result->addBackwardAnalysis(context);
    bw->writeResultsToFile(dir);
  } catch (StrangerStringAnalysisException const &e) {
    std::cout << "EXCEPTION! Analysing file: " << file << " in thread " << std::this_thread::get_id() << std::endl;
    std::cerr << e.what() << std::endl;
  } catch (const std::exception& e) {
    std::cout << "EXCEPTION! Analysing file: " << file << " in thread " << std::this_thread::get_id() << std::endl;
    std::cerr << e.what() << std::endl;
  }
}

void MultiAttack::computeImagesForFile(const fs::path& file) {
  fs::path dir(m_output_directory / file);
  std::cout << "Analysing file: " << file.string() << " in thread " << std::this_thread::get_id() << std::endl;
  CombinedAnalysisResult* result =
    new CombinedAnalysisResult(file, m_input_name, StrangerAutomaton::makeAnyString());
  try {
    // Forward Analysis
    result->getAttack()->init();
    result->getFwAnalysis().doAnalysis();
    const StrangerAutomaton* postImage = result->getFwAnalysis().getPostImage();
    result->getAttack()->writeResultsToFile(dir);
    result->getFwAnalysis().writeResultsToFile(dir);

    // Backward analysis
    for (auto c : m_analyzed_contexts) {
      computeAttackPatternOverlap(result, c);
    }

    // Finish up (delete the semattack object)
    result->finishAnalysis();

    const std::lock_guard<std::mutex> lock(this->results_mutex);
    std::cout << "Finished forward analysis of " << file << std::endl;
    std::cout << "Inserting results into groups for " << file << std::endl;
    this->m_groups.addAutomaton(postImage, result);
    this->m_results.emplace_back(result);
    std::cout << "Finished inserting results into groups for " << file << std::endl;
    this->printResults();
  } catch (...) {
    std::cout << "EXCEPTION! Analysing file: " << file << " in thread " << std::this_thread::get_id() << std::endl;
    // Still add the results to the null group
    result->finishAnalysis();
    const std::lock_guard<std::mutex> lock(this->results_mutex);
    this->m_groups.addAutomaton(nullptr, result);
    this->m_results.emplace_back(result);   
  }
}

void MultiAttack::compute() {
  findDotFiles();
  boost::asio::thread_pool pool(this->m_nThreads);
  std::cout << "Computing post images with pool of " << m_nThreads << " threads." << std::endl;
  for (auto file : this->m_dot_paths) {
      asio::post(pool, std::bind(&MultiAttack::computeImagesForFile, this, file));
  }
  pool.join();
  std::cout << "Forward analysis finished!" << std::endl;
  this->printResults(true);
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

  if (fs::exists(root) && fs::is_directory(root))
  {
    for (auto const & entry : fs::recursive_directory_iterator(root))
    {
      if (fs::is_regular_file(entry) && entry.path().extension() == ext) {
        paths.emplace_back(entry.path());
      }
    }
  }

  return paths;
}
