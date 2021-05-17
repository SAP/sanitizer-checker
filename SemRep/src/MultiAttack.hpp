/*
 * MultiAttack.hpp
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

#ifndef MULTIATTACK_HPP_
#define MULTIATTACK_HPP_

#include "AutomatonGroups.hpp"
#include "StrangerAutomaton.hpp"

#define BOOST_FILESYSTEM_VERSION 3
#define BOOST_FILESYSTEM_NO_DEPRECATED
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

#include <ostream>
#include <thread>
#include <vector>

namespace fs = boost::filesystem;

// Perform attack analysis on all dot files in the given directory
class MultiAttack {

public:
    MultiAttack(const std::string& graph_directory, const std::string& output_dir, const std::string& input_field_name, int max, StrangerAutomaton* input_auto = nullptr);
    virtual ~MultiAttack();

    void compute();
    void addAttackPattern(AttackContext context);
    void printResults(bool printFiles = false) const { printResults(std::cout, printFiles); }
    void printFiles() const { printFiles(std::cout); }
    void writeResultsToFile() const;
    void printStatus() const;
    void setConcats(bool c) { m_concats = c; }
    void setSingletonIntersection(bool s) { m_singleton_intersection = s; }
    void setComputePreimage(bool c) { m_compute_preimage = c; }
    void setPayloadAnalysis(bool a) { m_payload_analysis = a; }
    void setDotFiles(bool d) { m_output_dotfiles = d; }
    void setDoForwardAnalysisWithAttackPattern(bool f) { m_attack_forward = f; }
private:
    void printResults(std::ostream& os, bool printFiles = false) const;
    void printFiles(std::ostream& os) const;
    void fillCommonPatterns();
    void findDotFiles();
    CombinedAnalysisResult* findOrCreateResult(const fs::path& file, DepGraph& target_dep_graph, boost::asio::thread_pool &pool);
    void doFwAnalysis(CombinedAnalysisResult* result);
    void doBwAnalysis(CombinedAnalysisResult* result);
    void computeAttackPatternOverlap(CombinedAnalysisResult* result, AttackContext context);
    void computeAttackPatternOverlapForMetadata(CombinedAnalysisResult* result);
    static std::vector<fs::path> getDotFilesInDir(fs::path const &dir);
    static std::vector<fs::path> getFilesInPath(fs::path const & root, std::string const & ext);

    void loadDepGraphs();
    void doAnalysis();
    
    int countDone() const;

    fs::path m_graph_directory;
    fs::path m_output_directory;

    std::string m_input_name;
    std::vector<fs::path> m_dot_paths;
    // A list of all the results
    std::vector<CombinedAnalysisResult*> m_results;
    // A map of depgraph hashes to their results
    std::map<int, CombinedAnalysisResult*> m_result_hash_map;
    // A list of all post images
    std::vector<StrangerAutomaton*> m_automata;
    // Results grouped by post image
    AutomatonGroups m_groups;
    std::vector<AttackContext> m_analyzed_contexts;

    std::mutex results_mutex;

    // Configuration
    int m_max;
    unsigned int m_nThreads;
    bool m_concats;
    bool m_singleton_intersection;
    bool m_compute_preimage;
    bool m_payload_analysis;
    bool m_output_dotfiles;
    bool m_attack_forward;
    StrangerAutomaton* m_input_automaton;
};



#endif /* MULTIATTACK_HPP_ */
