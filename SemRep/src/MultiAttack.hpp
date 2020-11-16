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

#include <thread>
#include <vector>

namespace fs = boost::filesystem;

// Perform attack analysis on all dot files in the given directory
class MultiAttack {

public:
    MultiAttack(const std::string& graph_directory, const std::string& output_dir, const std::string& input_field_name);
    virtual ~MultiAttack();

    void computePostImages();
    void computeAttackPatternOverlaps(AttackContext context);
    void printResults() const;
    void printDetailedResults() const;

private:
    void fillCommonPatterns();
    void findDotFiles();
    void computePostImage(const fs::path& file);
    void computeAttackPatternOverlap(CombinedAnalysisResult* result, AttackContext context);
    static std::vector<fs::path> getDotFilesInDir(fs::path const &dir);
    static std::vector<fs::path> getFilesInPath(fs::path const & root, std::string const & ext);

    fs::path m_graph_directory;
    fs::path m_output_directory;

    std::string m_input_name;
    std::vector<fs::path> m_dot_paths;
    std::vector<CombinedAnalysisResult*> m_results;
    std::vector<StrangerAutomaton*> m_automata;
    AutomatonGroups m_groups;
    std::vector<AttackContext> m_analyzed_contexts;
    std::mutex results_mutex;
    unsigned int m_nThreads;
};



#endif /* MULTIATTACK_HPP_ */
