/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * AttackContext.hpp
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
#ifndef AUTOMATON_GROUPS_HPP_
#define AUTOMATON_GROUPS_HPP_

#include <ostream>
#include <string>
#include <vector>

#include "StrangerAutomaton.hpp"
#include "SemAttack.hpp"

// Create a class to group equal Automata
class AutomatonGroup {

   friend class AutomatonGroups;

public:
    AutomatonGroup(const StrangerAutomaton* automaton, const std::string& name, int id);
    AutomatonGroup(const StrangerAutomaton* automaton, int id);
    virtual ~AutomatonGroup();

    void setName(const std::string& name);
    std::string getName() const;
    const StrangerAutomaton* getAutomaton() const;
    void addCombinedAnalysisResult(const CombinedAnalysisResult* graph);
    unsigned int getEntries() const { return m_graphs.size(); }
    unsigned int getEntriesWithDuplicates() const;
    unsigned int getNonUniqueEntries() const;
    unsigned int getSuccessfulEntriesForContext(const AttackContext& context) const;
    unsigned int getContainedEntriesForContext(const AttackContext& context) const;
    unsigned int getSuccessfulValidated() const;
    unsigned int getEntriesForSinkContext(const AttackContext& context) const;
    unsigned int getValidatedEntriesForSinkContext(const AttackContext& context) const;
    std::set<std::string> getUniqueDomains() const;
  
    void printMembers(std::ostream& os, bool printAll, const std::vector<AttackContext>& contexts) const;
    void printSummary(std::ostream& os) const;
    void printHeaders(std::ostream& os, const std::vector<AttackContext>& contexts) const;

private:
    const StrangerAutomaton* m_automaton;
    std::vector<const CombinedAnalysisResult*> m_graphs;
    std::string m_name;
    int m_id;

    static std::vector<AttackContext> m_sink_contexts;
};

class AutomatonGroups {

public:
    AutomatonGroups();
    virtual ~AutomatonGroups();

    // Create an empty group with a name
    AutomatonGroup* createGroup(const StrangerAutomaton* automaton, const std::string& name);
    // If automaton exists in the group, add the depgraph to that grouping
    // otherwise add a new group with the automaton and graph
    AutomatonGroup* addAutomaton(const StrangerAutomaton* automaton, const CombinedAnalysisResult* graph);

    AutomatonGroup* addGroup(const StrangerAutomaton* automaton);

    AutomatonGroup* getGroupForAutomaton(const StrangerAutomaton* automaton);
    const AutomatonGroup* getGroupForAutomaton(const StrangerAutomaton* automaton) const;

    unsigned int getEntriesWithDuplicates() const;
    unsigned int getNonZeroGroups() const;
    unsigned int getEntries() const;
    unsigned int getNonUniqueEntries() const;
    unsigned int getSuccessfulEntriesForContext(const AttackContext& context) const;
    unsigned int getContainedEntriesForContext(const AttackContext& context) const;
    unsigned int getSuccessfulGroupsForContext(const AttackContext& context) const;
    unsigned int getSuccessfulValidated() const;
    unsigned int getEntriesForSinkContext(const AttackContext& context) const;
    unsigned int getValidatedEntriesForSinkContext(const AttackContext& context) const;
    std::set<std::string> getUniqueDomains() const;
  
    void printGroups(std::ostream& os, bool printAll, const std::vector<AttackContext>& contexts) const;
    void printStatus(std::ostream& os) const;

private:

    std::vector<AutomatonGroup> m_groups;
    int m_id;
    AutomatonGroup* addNewEntry(const StrangerAutomaton* automaton, const CombinedAnalysisResult* graph);
    void printTotals(std::ostream& os, const std::vector<AttackContext>& contexts) const;

};

#endif /* AUTOMATON_GROUPS_HPP_ */
