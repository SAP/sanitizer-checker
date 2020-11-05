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
#include "ImageComputer.hpp"
#include "SemRepairDebugger.hpp"
#include "depgraph/DepGraph.hpp"

class SemAttack {
public:
    SemAttack(std::string target_dep_graph_file_name, std::string input_field_name);
    virtual ~SemAttack();

    StrangerAutomaton* computeAttackPatternOverlap();

    StrangerAutomaton* computeTargetFWAnalysis();

    StrangerAutomaton* getTargetAuto() { return target_sink_auto; }

    void testNewFunctions();

    void printResults();

    std::string getFileName() const { return target_dep_graph_file_name; }

    const StrangerAutomaton* getPostImage() const { return target_sink_auto; }

    static PerfInfo perfInfo;
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

    void message(std::string msg);
    std::string generateOutputFilePath(std::string folder_name, bool unique_name);
    void printAnalysisResults(AnalysisResult& result);
    void printNodeList(NodesList nodes);
};



#endif /* SEMATTACK_HPP_ */
