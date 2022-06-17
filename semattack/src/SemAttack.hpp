/*
 * SemAttack.hpp
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

#ifndef SEMATTACK_HPP_
#define SEMATTACK_HPP_

#include <unordered_map>
#include <boost/filesystem.hpp>
#include "StrangerAutomaton.hpp"
#include "AttackContext.hpp"
#include "exceptions/AnalysisError.hpp"
#include "ImageComputer.hpp"
#include "SemRepairDebugger.hpp"
#include "depgraph/DepGraph.hpp"
#include "depgraph/Metadata.hpp"

namespace fs = boost::filesystem;



class SemAttack {
public:
    SemAttack(const std::string& target_dep_graph_file_name, DepGraph target_dep_graph_, const std::string& input_field_name);
    SemAttack(const fs::path& target_dep_graph_file_name, DepGraph target_dep_graph_, const std::string& input_field_name);
    bool operator<(const SemAttack &other);
    virtual ~SemAttack();

    // Load the depgraph from file
    void init();

    // Compute the post image with sigma star input
    AnalysisResult computeTargetFWAnalysis();

    // Compute the post image with custom input
    AnalysisResult computeTargetFWAnalysis(const StrangerAutomaton* inputAuto, bool doConcat = false);

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
    void setPrint(bool print) { m_print = print; }
    
    std::string getFileName() const { return target_dep_graph_file_name.string(); }
    const fs::path& getFile() const { return target_dep_graph_file_name; }
    static PerfInfo& perfInfo;

private:
    fs::path target_dep_graph_file_name;
    std::string input_field_name;

    NodeOwningDepGraph target_dep_graph;
    DepGraph target_field_relevant_graph;

    DepGraphNode* target_uninit_field_node;

    const StrangerAutomaton* target_sink_auto;

    void message(const std::string& msg) const;
    void printAnalysisResults(AnalysisResult& result) const;
    void printNodeList(NodesList nodes) const;

    bool m_print_dots;
    bool m_print;    
};

// Class containing all revelant forward analysis results
class ForwardAnalysisResult {

public:
    // Do forward analysis and get result
    ForwardAnalysisResult(const fs::path& target_dep_graph_file_name,
                          const std::string& input_field_name,
                          DepGraph target_dep_graph_,
                          StrangerAutomaton* automaton);
        
    virtual ~ForwardAnalysisResult();

    void doAnalysis(bool doConcat = false);

    const SemAttack* getAttack() const { return m_attack; }
    SemAttack* getAttack() { return m_attack; }
    const StrangerAutomaton* getPostImage() const { return m_postImage; }
    const AnalysisResult& getFwAnalysisResult() const { return m_result; }
    bool isErrored() const;
    AnalysisError getError() const { return m_error; };

    void writeResultsToFile(const fs::path& dir) const;

    void finishAnalysis();
private:
  SemAttack* m_attack;
  AnalysisResult m_result;
  AnalysisError m_error;
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

    void doAnalysis(bool computePreImage = true, bool singletonIntersection = false, bool doPostAttack = false);
    void finishAnalysis();

    const StrangerAutomaton* getPreImage() const { return m_preimage; }
    const StrangerAutomaton* getIntersection() const { return m_intersection; }
    const StrangerAutomaton* getAttackPattern() const { return m_attack; }
    const StrangerAutomaton* getAttackPostImage() const { return m_post_attack; }

    bool isErrored() const;
    AnalysisError getError() const { return m_error; }
    bool isSafe() const;
    bool isContained() const;
    bool isVulnerable() const { return !isSafe(); }

    bool hasPostAttackImage() const { return m_post_attack != nullptr; }
    const std::string& getName() const { return m_name; }

    void printResult(std::ostream& os, bool printHeader) const;
    void writeResultsToFile(const fs::path& dir) const;

    const std::string& get_intersection_example() const { return m_intersection_example; }
    const std::string& get_preimage_example() const { return m_preimage_example; }

private:
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

    // Cached result information for fast printing
    AnalysisError m_error;
    bool m_isErrored;
    bool m_isSafe;
    bool m_isContained;

    std::string m_intersection_example;
    std::string m_preimage_example;
    std::string m_post_attack_example;
};

class CombinedAnalysisResult {

public:

    CombinedAnalysisResult(const fs::path& target_dep_graph_file_name,
                           DepGraph target_dep_graph_,
                           const std::string& input_field_name,
                           StrangerAutomaton* automaton);
    ~CombinedAnalysisResult();

    // For sorting entries
    bool operator< (const CombinedAnalysisResult &other) const;
    
    BackwardAnalysisResult* addBackwardAnalysis(AttackContext context);
    bool hasBackwardanalysisResult(AttackContext context) const;

    void doMetadataSpecificAnalysis(const fs::path& output_dir, bool computePreImage = true, bool singletonIntersection = false, bool outputDotfiles = true, bool attack_forward = false);

    const SemAttack* getAttack() const { return m_fwAnalysis.getAttack(); }
    SemAttack* getAttack() { return m_fwAnalysis.getAttack(); }

    const ForwardAnalysisResult& getFwAnalysis() const { return m_fwAnalysis; }
    ForwardAnalysisResult& getFwAnalysis() { return m_fwAnalysis; }

    std::string getFileName() const { return m_inputfile.string(); }
    const fs::path& getInputPath() const { return m_inputfile; }
    
    bool isFilterSuccessful(const AttackContext& context) const;
    bool isFilterContained(const AttackContext& context) const;

    const Metadata& getMetadata() const { return m_metadata.at(0); }
    AttackContext getSinkContext() const { return AttackContextHelper::getContextFromMetadata(getMetadata()); }
    bool isSinkContext(const AttackContext& context) const { return (context == getSinkContext()); }

    int getCountWithDuplicates() const { return m_duplicate_count; }
    int getCount() const { return m_metadata.size(); }
    bool addMetadata(const Metadata& metadata);
    std::set<std::string> getUniqueDomains() const;
    std::set<std::string> getUniqueDomainsWithPayload() const;
    std::set<std::string> getVulnerableDomainsWithPayload() const;
    std::set<int> getUniqueInjectionPoints() const;

    bool hasSuccessfulFwAnalysis() const { return !m_metadataAnalysisMap.empty(); }
    bool hasAtLeastOnePayload() const { return !m_stringAnalysisMap.empty(); }
    bool hasAtLeastOneVulnerablePayload() const { return m_atLeastOnePayloadVulnerable; }
    bool hasAllErroredPayloads() const { return m_allPayloadsErrored; }
    bool hasAtLeastOneBypass() const;

    void printResult(std::ostream& os, bool printHeader, const std::vector<AttackContext>& contexts) const;
    void printHeader(std::ostream& os, const std::vector<AttackContext>& contexts) const;
    void printGeneratedPayloads(std::ostream& os) const;
    static void printGeneratedPayloadHeader(std::ostream& os);
    void printUnmatchedUuids(std::ostream& os) const;
    void finishAnalysis();

    bool isDone() const { return m_done; }

private:
    BackwardAnalysisResult* doBackwardAnalysisForPayload(const std::string& payload, const fs::path& output_dir,
                                                         bool computePreImage, bool singletonIntersection, bool outputDotfiles, bool attack_forward);
    fs::path m_inputfile;
    std::string m_input_name;
    bool m_done;
    ForwardAnalysisResult m_fwAnalysis;
    std::unordered_map<AttackContext, BackwardAnalysisResult*> m_bwAnalysisMap;

    // Keep track of metadata for this result
    std::vector<Metadata> m_metadata;
    std::map<int, const Metadata*> m_finding_metadata_map;
    // For context specific payloads, keep a map of metadata to backwardanalysis
    std::map<const Metadata*, std::vector<BackwardAnalysisResult*> > m_metadataAnalysisMap;
    // Also keep track of which strings have been analysed
    std::map<std::string, BackwardAnalysisResult*> m_stringAnalysisMap;
    // Track if at least one BW analysis had an overlap 
    bool m_atLeastOnePayloadVulnerable;
    // Track if not all were successful
    bool m_allPayloadsVulnerable;
    // Did all the payload analysis cause errors?
    bool m_allPayloadsErrored;
    
    int m_duplicate_count;
};

#endif /* SEMATTACK_HPP_ */
