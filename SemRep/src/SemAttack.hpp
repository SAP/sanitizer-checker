/*
 * SemAttack.hpp
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

#ifndef SEMATTACK_HPP_
#define SEMATTACK_HPP_

#include <boost/filesystem.hpp>
#include "StrangerAutomaton.hpp"
#include "AttackContext.hpp"
#include "ImageComputer.hpp"
#include "SemRepairDebugger.hpp"
#include "depgraph/DepGraph.hpp"

namespace fs = boost::filesystem;

class SemAttack {
public:
    SemAttack(const std::string& target_dep_graph_file_name, const std::string& input_field_name);
    SemAttack(const fs::path& target_dep_graph_file_name, const std::string& input_field_name);
    virtual ~SemAttack();

    // Load the depgraph from file
    void init();

    // Compute the post image with sigma star input
    AnalysisResult computeTargetFWAnalysis();

    // Compute the post image with custom input
    AnalysisResult computeTargetFWAnalysis(const StrangerAutomaton* inputAuto);

    // Get the post-image from the analysis result
    const StrangerAutomaton* getPostImage(const AnalysisResult& result) const;

    // Calculate intersection between postImage and attack pattern
    StrangerAutomaton* computeAttackPatternOverlap(const StrangerAutomaton* postImage,
                                                   const StrangerAutomaton* attackPattern) const;

    // Compute the pre-image from the intersection and the previously computed
    // analysis result from computeTargetFWAnalysis()
    AnalysisResult computePreImage(const StrangerAutomaton* intersection,
                                   const AnalysisResult& result) const;

    const StrangerAutomaton* getPreImage(const AnalysisResult& result) const;
    
    void printResults() const;
    void writeResultsToFile(const fs::path& dir) const;
    
    void setPrintDots(bool print) { m_print_dots = print; }
    std::string getFileName() const { return target_dep_graph_file_name.string(); }
    const fs::path& getFile() const { return target_dep_graph_file_name; }
    static PerfInfo& perfInfo;

private:
    fs::path target_dep_graph_file_name;
    std::string input_field_name;

    NodeOwningDepGraph target_dep_graph;
    DepGraph target_field_relevant_graph;

    DepGraphNode* target_uninit_field_node;

    StrangerAutomaton* target_sink_auto;

    void message(const std::string& msg) const;
    void printAnalysisResults(AnalysisResult& result) const;
    void printNodeList(NodesList nodes) const;

    bool m_print_dots;
};

// Class containing all revelant forward analysis results
class ForwardAnalysisResult {

public:
    // Do forward analysis and get result
    ForwardAnalysisResult(const fs::path& target_dep_graph_file_name,
                          const std::string& input_field_name,
                          StrangerAutomaton* automaton);
        
    virtual ~ForwardAnalysisResult();

    void doAnalysis();

    const SemAttack* getAttack() const { return m_attack; }
    SemAttack* getAttack() { return m_attack; }
    const StrangerAutomaton* getPostImage() const { return m_postImage; }
    const AnalysisResult& getFwAnalysisResult() const { return m_result; }

    void writeResultsToFile(const fs::path& dir) const;

    void finishAnalysis();
private:
  SemAttack* m_attack;
  AnalysisResult m_result;
  StrangerAutomaton* m_input;
  StrangerAutomaton* m_postImage;
};

// Class containing all revelant backward analysis results
class BackwardAnalysisResult {

public:

    BackwardAnalysisResult(ForwardAnalysisResult& result,
                           AttackContext context);

    BackwardAnalysisResult(ForwardAnalysisResult& result,
                           const StrangerAutomaton* attack, const std::string& name);

    virtual ~BackwardAnalysisResult();

    const StrangerAutomaton* getPreImage() const { return m_preimage; }
    const StrangerAutomaton* getIntersection() const { return m_intersection; }
    const StrangerAutomaton* getAttackPattern() const { return m_attack; }
    const StrangerAutomaton* getAttackPostImage() const { return m_post_attack; }
    bool isSafe() const { return (getIntersection()->isEmpty() || getIntersection()->checkEmptyString()); }
    bool isVulnerable() const { return !isSafe(); }
    bool hasPostAttackImage() const { return m_post_attack != nullptr; }
    const std::string& getName() const { return m_name; }
    void writeResultsToFile(const fs::path& dir) const;

private:
    void init();
    const SemAttack* getAttack() const { return m_fwResult.getAttack(); }
    SemAttack* getAttack() { return m_fwResult.getAttack(); }
    ForwardAnalysisResult& m_fwResult;
    std::string m_name;

    // Automaton representing the attack pattern which was tested
    StrangerAutomaton* m_attack;
    // Context of the attack pattern
    AttackContext m_context;
    // Intersection between attack pattern and post image
    StrangerAutomaton* m_intersection;
    // Pre-image of intersection
    StrangerAutomaton* m_preimage;
    // Post-image if attack pattern is used as input
    StrangerAutomaton* m_post_attack;
};

class CombinedAnalysisResult {

public:
    CombinedAnalysisResult(const fs::path& target_dep_graph_file_name,
                           const std::string& input_field_name,
                           StrangerAutomaton* automaton);
    ~CombinedAnalysisResult();

    const BackwardAnalysisResult* addBackwardAnalysis(AttackContext context);

    const SemAttack* getAttack() const { return m_fwAnalysis.getAttack(); }
    SemAttack* getAttack() { return m_fwAnalysis.getAttack(); }

    const ForwardAnalysisResult& getFwAnalysis() const { return m_fwAnalysis; }
    ForwardAnalysisResult& getFwAnalysis() { return m_fwAnalysis; }

    std::string getFileName() const { return m_inputfile.string(); }
    
    void printResult() const;
    void printDetailedResults() const;
    void finishAnalysis() { getFwAnalysis().finishAnalysis(); }
private:
    fs::path m_inputfile;
    std::string m_input_name;

    ForwardAnalysisResult m_fwAnalysis;
    std::map<AttackContext, BackwardAnalysisResult*> m_bwAnalysisMap;
};

#endif /* SEMATTACK_HPP_ */
