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

#include "AutomatonGroups.hpp"

#include <iostream>

std::vector<AttackContext> AutomatonGroup::m_sink_contexts = {
  AttackContext::Html,
  AttackContext::HtmlAttr,
  AttackContext::JavaScript,
  AttackContext::Url,
  AttackContext::HtmlUrlAttr,
  AttackContext::None
};

AutomatonGroup::AutomatonGroup(const StrangerAutomaton* automaton, const std::string& name, int id)
  : m_automaton(automaton)
  , m_graphs()
  , m_name(name)
  , m_id(id)
{

}

AutomatonGroup::AutomatonGroup(const StrangerAutomaton* automaton, int id)
  : m_automaton(automaton)
  , m_graphs()
  , m_name(std::to_string(id))
  , m_id(id)
{

}

AutomatonGroup::~AutomatonGroup()
{

}

void AutomatonGroup::setName(const std::string& name)
{
  m_name = name;
}

std::string AutomatonGroup::getName() const
{
  return m_name;
}

const StrangerAutomaton* AutomatonGroup::getAutomaton() const
{
  return m_automaton;
}

void AutomatonGroup::addCombinedAnalysisResult(const CombinedAnalysisResult* graph) {
  m_graphs.emplace_back(graph);
}

void AutomatonGroup::printHeaders(std::ostream& os, const std::vector<AttackContext>& contexts) const {
  os << "id, name, entries, deduplicated, unique hash, domains, validated";
  for (auto c : m_sink_contexts) {
    os << ", " << AttackContextHelper::getName(c) << " sink entries";
    os << ", " << AttackContextHelper::getName(c) << " sink validated";
  }
  os << ", ";
  // Get headers from first entry
  if (m_graphs.size() > 0) {
    m_graphs.at(0)->printHeader(os, contexts);
  }
  os << std::endl;
}

void AutomatonGroup::printSummary(std::ostream& os) const {
  os << m_id << ", "
     << getName() << ", "
     << getEntriesWithDuplicates() << ", "
     << getNonUniqueEntries() << ", "
     << getEntries() << ", "
     << getUniqueDomains().size() << ", "
     << getSuccessfulValidated();
  for (auto c : m_sink_contexts) {
    os << ", " << getEntriesForSinkContext(c);
    os << ", " << getValidatedEntriesForSinkContext(c);
  }
}

void AutomatonGroup::printMembers(std::ostream& os, bool printAll, const std::vector<AttackContext>& contexts) const {

  printSummary(os);
  os << ", ";
  // Get vulnerablility overlaps from first entry
  if (m_graphs.size() > 0) {
    m_graphs.at(0)->printResult(os, false, contexts);
  }
  for (const auto *iter : m_graphs) {
    os << iter->getFileName() << "; ";
    if (!printAll) {
      break;
    }
  }
  os << std::endl;
  //m_automaton->toDotAscii(0);
}

unsigned int AutomatonGroup::getSuccessfulValidated() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->getMetadata().is_exploit_successful() ? 1 : 0;
  }
  return total;
}

unsigned int AutomatonGroup::getEntriesForSinkContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->isSinkContext(context) ? 1 : 0;
  }
  return total;
}

unsigned int AutomatonGroup::getValidatedEntriesForSinkContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    if (iter->isSinkContext(context) && iter->getMetadata().is_exploit_successful()) {
      total += 1;
    }
  }
  return total;
}

std::set<std::string> AutomatonGroup::getUniqueDomains() const {
  std::set<std::string> domains;
  for (auto g : m_graphs) {
    std::set<std::string> s = g->getUniqueDomains();
    domains.insert(s.begin(), s.end());
  }
  return domains;
}

unsigned int AutomatonGroup::getNonUniqueEntries() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->getCount();
  }
  return total;
}

unsigned int AutomatonGroup::getEntriesWithDuplicates() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->getCountWithDuplicates();
  }
  return total;
}

unsigned int AutomatonGroup::getSuccessfulEntriesForContext(const AttackContext& context) const {
  unsigned int entries = this->getEntries();
  unsigned int total = 0;
  if (m_graphs.size() > 0) {
    // Get the first result in the group
    const CombinedAnalysisResult* result = m_graphs.at(0);
    total = (result->isFilterSuccessful(context) ? 1 : 0) * entries;
  }
  //std::cout << "Getting successful entries for: " << AttackContextHelper::getName(context) << " " << this->getName() << ": " << total << std::endl;
  return total;
}

unsigned int AutomatonGroup::getContainedEntriesForContext(const AttackContext& context) const {
  unsigned int entries = this->getEntries();
  unsigned int total = 0;
  if (m_graphs.size() > 0) {
    // Get the first result in the group
    const CombinedAnalysisResult* result = m_graphs.at(0);
    total = (result->isFilterContained(context) ? 1 : 0) * entries;
  }
  return total;
}

AutomatonGroups::AutomatonGroups()
  : m_groups()
  , m_id(0)
{

}


AutomatonGroups::~AutomatonGroups()
{
  // The group class doesn't own any of the pointers it is given
}

AutomatonGroup* AutomatonGroups::createGroup(const StrangerAutomaton* automaton, const std::string& name)
{
  AutomatonGroup* group = getGroupForAutomaton(automaton);
  if (group) {
    // Group already present, just change the name
    group->setName(name);
  } else {
    group = addGroup(automaton);
    group->setName(name);
  }
  return group;
}

AutomatonGroup* AutomatonGroups::addAutomaton(const StrangerAutomaton* automaton, const CombinedAnalysisResult* graph)
{
  AutomatonGroup* existingGroup = getGroupForAutomaton(automaton);
  if (existingGroup) {
    existingGroup->addCombinedAnalysisResult(graph);
  } else {
    existingGroup = addNewEntry(automaton, graph);
  }
  return existingGroup;
}

AutomatonGroup* AutomatonGroups::addGroup(const StrangerAutomaton* automaton) {
  AutomatonGroup group(automaton, m_id);
  m_id++;
  m_groups.push_back(group);
  return &m_groups.back(); 
}

AutomatonGroup* AutomatonGroups::addNewEntry(const StrangerAutomaton* automaton, const CombinedAnalysisResult* graph)
{
  AutomatonGroup* group = addGroup(automaton);
  group->addCombinedAnalysisResult(graph);
  return group;
}

AutomatonGroup* AutomatonGroups::getGroupForAutomaton(const StrangerAutomaton* automaton)
{
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    const StrangerAutomaton* existing = iter->getAutomaton();
    if ((automaton == existing) ||
        (automaton->equals(existing))) {
      return &(*iter);
    }
  }
  return nullptr;
}

const AutomatonGroup* AutomatonGroups::getGroupForAutomaton(const StrangerAutomaton* automaton) const
{
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    const StrangerAutomaton* existing = iter->getAutomaton();
    if (automaton->equals(existing)) {
      return &(*iter);
    }
  }
  return nullptr;
}

void AutomatonGroups::printStatus(std::ostream& os) const
{
  os << "#  DepGraph files --> Duplicates removed --> Unique Hash --> Domains --> Unique Post-images" << std::endl;
  os << "# " << getEntriesWithDuplicates()
     << " --> " << getNonUniqueEntries()
     << " --> " << getEntries()
     << " --> " << getUniqueDomains().size()
     << " --> " << getNonZeroGroups() << std::endl;
}

void AutomatonGroups::printGroups(std::ostream& os, bool printAll, const std::vector<AttackContext>& contexts) const {
  // Switch to decimal
  os << std::dec;
  printStatus(os);
  if (getNonZeroGroups() > 0) {
    m_groups.at(0).printHeaders(os, contexts);
  }
  this->printTotals(os, contexts);
  for (auto iter : m_groups) {
    iter.printMembers(os, printAll, contexts);
  }
}

void AutomatonGroups::printTotals(std::ostream& os, const std::vector<AttackContext>& contexts) const {
  unsigned int entries = getEntries();
  unsigned int exploited = getSuccessfulValidated();
  unsigned int duplicates = getEntriesWithDuplicates();
  unsigned int nonunique = getNonUniqueEntries();
  unsigned int domains = getUniqueDomains().size();
  os << "-1, ";
  os << "total, ";
  os << duplicates << ", " << nonunique << ", " << entries << ", " << domains << ", " << exploited << ", ";
  for (auto c : AutomatonGroup::m_sink_contexts) {
    os << getEntriesForSinkContext(c) << ", ";
    os << getValidatedEntriesForSinkContext(c) << ", ";   
  }
  for (auto context : contexts) {
    unsigned int success = getSuccessfulEntriesForContext(context);
    os << success << ", ";
    os << getContainedEntriesForContext(context) << ", ";
    os << entries - success << ", ";
    os << getSuccessfulGroupsForContext(context) << ", ";
  }
  os << ", " << std::endl;
}

unsigned int AutomatonGroups::getSuccessfulEntriesForContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getSuccessfulEntriesForContext(context);
  }
  return total;
}

unsigned int AutomatonGroups::getContainedEntriesForContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getContainedEntriesForContext(context);
  }
  return total;
}

unsigned int AutomatonGroups::getSuccessfulGroupsForContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += (iter->getSuccessfulEntriesForContext(context) > 0) ? 1 : 0;
  }
  return total;
}

unsigned int AutomatonGroups::getEntries() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getEntries();
  }
  return total;
}

unsigned int AutomatonGroups::getNonUniqueEntries() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getNonUniqueEntries();
  }
  return total;
}

unsigned int AutomatonGroups::getEntriesWithDuplicates() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getEntriesWithDuplicates();
  }
  return total;
}

unsigned int AutomatonGroups::getNonZeroGroups() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    if (iter->getEntries() > 0) {
      total++;
    }
  }
  return total;
}

unsigned int AutomatonGroups::getSuccessfulValidated() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getSuccessfulValidated();
  }
  return total;
}

unsigned int AutomatonGroups::getEntriesForSinkContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getEntriesForSinkContext(context);
  }
  return total;
}

unsigned int AutomatonGroups::getValidatedEntriesForSinkContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getValidatedEntriesForSinkContext(context);
  }
  return total;
}

std::set<std::string> AutomatonGroups::getUniqueDomains() const {
  std::set<std::string> domains;
  for (auto g : m_groups) {
    std::set<std::string> s = g.getUniqueDomains();
    domains.insert(s.begin(), s.end());
  }
  return domains;
}
