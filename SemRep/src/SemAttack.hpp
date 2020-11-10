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

class SemAttack {
public:
    SemAttack(const std::string& target_dep_graph_file_name, const std::string& input_field_name);
    virtual ~SemAttack();

    // Compute the post image with sigma star input
    AnalysisResult computeTargetFWAnalysis();

    // Compute the post image with custom input
    AnalysisResult computeTargetFWAnalysis(StrangerAutomaton* inputAuto);

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

    std::string getFileName() const { return target_dep_graph_file_name; }
    static PerfInfo& perfInfo;

private:
    std::string target_dep_graph_file_name;
    std::string input_field_name;

    DepGraph reference_dep_graph;
    DepGraph target_dep_graph;
    DepGraph reference_field_relevant_graph;
    DepGraph target_field_relevant_graph;

    DepGraphNode* reference_uninit_field_node;
    DepGraphNode* target_uninit_field_node;

    StrangerAutomaton* target_sink_auto;

    void message(const std::string& msg) const;
    std::string generateOutputFilePath(std::string folder_name, bool unique_name) const;
    void printAnalysisResults(AnalysisResult& result) const;
    void printNodeList(NodesList nodes) const;
};

// Class containing all revelant forward analysis results
class ForwardAnalysisResult {

public:
    // Do forward analysis and get result
    ForwardAnalysisResult(const std::string& target_dep_graph_file_name,
                          const std::string& input_field_name,
                          StrangerAutomaton* automaton);
        
    virtual ~ForwardAnalysisResult();

    const SemAttack* getAttack() const { return m_attack; }
    const StrangerAutomaton* getPostImage() const { return m_attack->getPostImage(m_result); }
    const AnalysisResult& getFwAnalysisResult() const { return m_result; }

private:
  SemAttack* m_attack;
  AnalysisResult m_result;
  StrangerAutomaton* m_input;
  
};

// Class containing all revelant backward analysis results
class BackwardAnalysisResult {

public:

    BackwardAnalysisResult(const ForwardAnalysisResult& result,
                           AttackContext context);

    virtual ~BackwardAnalysisResult();

    const StrangerAutomaton* getPreImage() const { return getAttack()->getPreImage(m_result); }
    const StrangerAutomaton* getIntersection() const { return m_intersection; }
    bool isSafe() const { return (getIntersection()->isEmpty() || getIntersection()->checkEmptyString()); }
    bool isVulnerable() const { return !isSafe(); }

private:

    const SemAttack* getAttack() const { return m_fwResult.getAttack(); }

    const ForwardAnalysisResult& m_fwResult;
    AttackContext m_context;
    StrangerAutomaton* m_intersection;
    AnalysisResult m_result;
};

class CombinedAnalysisResult {

public:
    CombinedAnalysisResult(const std::string& target_dep_graph_file_name,
                           const std::string& input_field_name,
                           StrangerAutomaton* automaton);
    ~CombinedAnalysisResult() {}

    void addBackwardAnalysis(AttackContext context);

    const SemAttack* getAttack() const { return m_fwAnalysis.getAttack(); }

    const ForwardAnalysisResult& getFwAnalysis() const { return m_fwAnalysis; }

    void printResult() const;

private:
    ForwardAnalysisResult m_fwAnalysis;
    std::map<AttackContext, BackwardAnalysisResult> m_bwAnalysisMap;
};

#endif /* SEMATTACK_HPP_ */
