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

#ifndef SEMATTACK_BW_HPP_
#define SEMATTACK_BW_HPP_

#include <boost/filesystem.hpp>
#include "StrangerAutomaton.hpp"
#include "ImageComputer.hpp"
#include "SemRepairDebugger.hpp"
#include "depgraph/DepGraph.hpp"

using namespace std;

class SemAttackBw {
public:
    SemAttackBw(const string& target_dep_graph_file_name, const string& input_field_name);
    virtual ~SemAttackBw();

    StrangerAutomaton* generateAttack();

    StrangerAutomaton* getTargetAuto() { return target_sink_auto; }

    void testNewFunctions();

    void printResults();

    bool is_validation_patch_required = false;
    bool is_length_patch_required = false;
    bool is_sanitization_patch_required = false;

    bool calculate_rejected_set = false;

    static PerfInfo& perfInfo;

private:
    StrangerAutomaton* sink_auto;
    StrangerAutomaton* vs_auto;
    StrangerAutomaton* attack_pattern_auto;

    AnalysisResult analyzePostImages();
    AnalysisResult analyzePreImages(StrangerAutomaton* intersection_auto, const AnalysisResult& fwAnalysisResult);
    void message(const string& msg);
    void debug_auto(StrangerAutomaton* automaton, int type);
    bool enable_debug;

    string reference_dep_graph_file_name;
    string target_dep_graph_file_name;
    string input_field_name;

    NodeOwningDepGraph target_dep_graph;
    DepGraph target_field_relevant_graph;
    DepGraphNode* target_uninit_field_node;
    StrangerAutomaton* target_sink_auto;

    string generateOutputFilePath(string folder_name, bool unique_name);
    void printAnalysisResults(AnalysisResult& result);
    void printNodeList(NodesList nodes);
};



#endif /* SEMREPAIR_HPP_ */
