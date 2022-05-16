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
  AttackContext::HtmlSingleQuoteAttr,
  AttackContext::HtmlUrlAttr,
  AttackContext::HtmlSingleQuoteUrlAttr,
  AttackContext::HtmlUnknown,
  AttackContext::Url,
  AttackContext::JavaScript,
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
     << getUniqueDomainsSize() << ", "
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

void AutomatonGroup::printGeneratedPayloads(std::ostream& os) const {
  for (const auto *iter : m_graphs) {
    iter->printGeneratedPayloads(os);
  }
}

unsigned int AutomatonGroup::getSuccessfulValidated() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->getMetadata().is_exploit_successful() ? 1 : 0;
  }
  return total;
}

unsigned int AutomatonGroup::getErrored() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->getFwAnalysis().isErrored() ? 1 : 0;
  }
  return total;
}

unsigned int AutomatonGroup::getSanitizersForPayload() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += (!iter->getFwAnalysis().isErrored()) ? 1 : 0;
  }
  return total;
}

unsigned int AutomatonGroup::getSanitizersWithPayload() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += (iter->hasAtLeastOnePayload() && !iter->getFwAnalysis().isErrored()) ? 1 : 0;
  }
  return total;
}

unsigned int AutomatonGroup::getVulnerableSanitizersWithPayload() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    if (iter->hasAtLeastOnePayload() && !iter->getFwAnalysis().isErrored()) {
      total += iter->hasAtLeastOneVulnerablePayload() ? 1 : 0;
    }
  }
  return total;
}

unsigned int AutomatonGroup::getVulnerableSanitizersWithBypass() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->hasAtLeastOneBypass() ? 1 : 0;
  }
  return total;
}

std::set<std::string> AutomatonGroup::getDomainsForPayload() const {
  std::set<std::string> set;
  for (auto iter : m_graphs) {
    if (!iter->getFwAnalysis().isErrored()) {
      std::set<std::string> s = iter->getUniqueDomains();
      set.insert(s.begin(), s.end());
    }
  }
  return set;
}

std::set<std::string> AutomatonGroup::getDomainsWithPayload() const {
  std::set<std::string> set;
  for (auto iter : m_graphs) {
    if (!iter->getFwAnalysis().isErrored()) {
      std::set<std::string> s = iter->getUniqueDomainsWithPayload();
      set.insert(s.begin(), s.end());
    }
  }
  return set;
}

std::set<std::string> AutomatonGroup::getVulnerableDomainsWithPayload() const {
  std::set<std::string> set;
  for (auto iter : m_graphs) {
    if (!iter->getFwAnalysis().isErrored() && iter->hasAtLeastOneVulnerablePayload()) {
      std::set<std::string> s = iter->getVulnerableDomainsWithPayload();
      set.insert(s.begin(), s.end());
    }
  }
  return set;
}

unsigned int AutomatonGroup::getErroredSanitizersWithPayload() const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    if (iter->hasAtLeastOnePayload() && !iter->getFwAnalysis().isErrored()) {
      total += iter->hasAllErroredPayloads() ? 1 : 0;
    }
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

unsigned int AutomatonGroup::getErrorsForSinkContext(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    if (iter->isSinkContext(context) && iter->getFwAnalysis().isErrored()) {
      total++;
    }
  }
  return total;
}

unsigned int AutomatonGroup::getErrorsForSinkContextAndErrorType(const AttackContext& context, const AnalysisError& error) const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    if (iter->isSinkContext(context) && iter->getFwAnalysis().isErrored()) {
      if (iter->getFwAnalysis().getError() == error) {
        total++;
      }
    }
  }
  return total;
}

unsigned int AutomatonGroup::getEntriesForSinkContextWeighted(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->isSinkContext(context) ? iter->getCountWithDuplicates() : 0;
  }
  return total;
}

unsigned int AutomatonGroup::getEntriesForSinkContextDeduplicated(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter : m_graphs) {
    total += iter->isSinkContext(context) ? iter->getCount() : 0;
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

std::vector<std::set<std::string> > AutomatonGroup::getUniqueDomains() const {
  std::vector<std::set<std::string> > domains;
  for (auto g : m_graphs) {
    domains.push_back(g->getUniqueDomains());
  }
  return domains;
}

int AutomatonGroup::getUniqueDomainsSize() const {
  int n = 0;
  for (auto& s: getUniqueDomains()) {
    n += s.size();
  }
  return n;
}

std::vector<std::set<int> > AutomatonGroup::getUniqueInjectionPoints() const {
  std::vector<std::set<int> > ips;
  for (auto g : m_graphs) {
    ips.push_back(g->getUniqueInjectionPoints());
  }
  return ips;
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
    // std::cout << "Comparing insertion automaton (nstates: "
    //           << ((automaton != nullptr) ? automaton->get_num_of_states() : -2)
    //           <<" to group: " << iter->getName() << " with states: "
    //           << ((existing != nullptr) ? existing->get_num_of_states() : -2)
    //           << std::endl;
    // Both are null, found a match!
    if ((automaton == nullptr) && (existing == nullptr)) {
      return &(*iter);
    }
    // If one is null, but the other not don't match
    if ((automaton == nullptr) || (existing == nullptr)) {
      continue;
    }
    // Otherwise check
    if ((automaton == existing) ||
        ((automaton->get_num_of_states()  == existing->get_num_of_states())
         && automaton->equals(existing))) {
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
  os << "# DepGraph files --> Duplicates removed --> Unique Hash (errors) --> Unique Post-images" << std::endl;
  os << "# " << getEntriesWithDuplicates()
     << " --> " << getNonUniqueEntries()
     << " --> " << getEntries()
     << " (" << getErrored() << ")"
     << " --> " << getNonZeroGroups() << std::endl;
  // Summary of payload analysis
  os << "# Sanitizers --> Sanitizers with payload -> Vulnerable sanitizers -> Sanitizers with bypass (errored)" << std::endl;
  os << "# " << getSanitizersForPayload();
  os << " --> " << getSanitizersWithPayload();
  os << " --> " << getVulnerableSanitizersWithPayload();
  os << " --> " << getVulnerableSanitizersWithBypass();
  os << " (" << getErroredSanitizersWithPayload() << ")";
  os << std::endl; 
  // Summary of payload analysis
  os << "# Domains with sanitizer --> Domains with a sanitizer with payload -> Domains with a Vulnerable sanitizer" << std::endl;
  os << "# " << getDomainsForPayload();
  os << " --> " << getDomainsWithPayload();
  os << " --> " << getVulnerableDomainsWithPayload();
  os << std::endl; 
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

void AutomatonGroups::printErrorSummary(std::ostream& os) const
{
  // Print a table of columns containting attack patterns
  //                  rows containing injection contexts
  os << "Context, total, errors, ";

  // Count errors in different categories
  for (auto e : AnalysisErrorHelper::getAllEnums()) {
    os << AnalysisErrorHelper::getName(e) << ",";
  }

  os << std::endl;

  // Loop over sink contexts, one per line
  for (auto s : AutomatonGroup::m_sink_contexts) {
    os << AttackContextHelper::getName(s) << ",";

    // Total
    unsigned int total = 0;
    unsigned int errors = 0;
    // Loop over each group
    for (auto g : m_groups) {
      total += g.getEntriesForSinkContext(s);
      errors += g.getErrorsForSinkContext(s);
    }
    os << total << ", " << errors << ", ";

    // Loop over each error
    for (auto e : AnalysisErrorHelper::getAllEnums()) {
      errors = 0;
      for (auto& g : m_groups) {
        errors += g.getErrorsForSinkContextAndErrorType(s, e);
      }
      os << errors << ", ";     
    }
    
    os << std::endl;
  }
}

void AutomatonGroups::printHistogram(std::ostream& os, const std::vector<size_t>& data, size_t max) const
{
  std::vector<size_t> histogram(max + 1, 0);
  for (size_t count: data) {
    if (count < histogram.size()) {
      histogram.at(count) += 1;
    }
  }

  for (int i = 0; i < histogram.size(); i++) {
    os << i << ", " << histogram.at(i) << std::endl;
  }
}

void AutomatonGroups::printInjectionPointHistogram(std::ostream& os) const
{
  // Compute the number of injections points per sanitizer
  std::vector<size_t> injection_points;
  size_t max = 0;
  for (auto& g: m_groups) {
    for (auto& s: g.getUniqueInjectionPoints()) {
      // Set of injection points for this sanitizer
      size_t p = s.size();
      injection_points.push_back(p);
      max = std::max(max, p);
    }
  }
  printHistogram(os, injection_points, max);
}

void AutomatonGroups::printDomainHistogram(std::ostream& os) const
{
  // Compute the number of domains per sanitizer
  std::vector<size_t> domains;
  size_t max = 0;
  for (auto& g: m_groups) {
    for (auto& s: g.getUniqueDomains()) {
      // Set of domains for this sanitizer
      size_t p = s.size();
      domains.push_back(p);
      max = std::max(max, p);
    }
  }
  printHistogram(os, domains, max);
}

void AutomatonGroups::printSanitizersPerGroupHistogram(std::ostream& os) const
{
  // Compute the number of sanitizers per group
  std::vector<size_t> sanitizers;
  size_t max = 0;
  for (auto& g : m_groups) {
    sanitizers.push_back(g.getEntries());
    max = std::max(max, g.getEntries());
  }
  printHistogram(os, sanitizers, max);
}

void AutomatonGroups::printOverlapSummary(std::ostream& os, const std::vector<AttackContext>& contexts, bool percent) const
{
  // Print a table of columns containting attack patterns
  //                  rows containing injection contexts
  os << "Context, total, ";

  for (auto a : contexts) {
    os << AttackContextHelper::getName(a) << ",";
  }
  os << std::endl;

  // Loop over sink contexts, one per line
  for (auto s : AutomatonGroup::m_sink_contexts) {
    os << AttackContextHelper::getName(s) << ",";

    // Total
    unsigned int total = 0;
    unsigned int errors = 0;
    // Loop over each group
    for (auto g : m_groups) {
      total += g.getEntriesForSinkContext(s);
      errors += g.getErrorsForSinkContext(s);
    }
    os << total << ", " << errors << ", ";

    for (auto a : contexts) {
      unsigned int i = 0;
      // Loop over each group
      for (auto g : m_groups) {
        if (g.getSuccessfulEntriesForContext(a) > 0) {
          i += g.getEntriesForSinkContext(s);
        }
      }
      if (percent) {
        double pc = (total > 0) ? ((double) i * 100.0) / (double) total : 0.0;
        os << pc << ",";
      } else {
        os << i << ", ";
      }
    }
    os << std::endl;
  }
}

void AutomatonGroups::printTotals(std::ostream& os, const std::vector<AttackContext>& contexts) const {
  // All totals computed by number of unique sanitizers across multiple domains
  unsigned int entries = getEntries();
  unsigned int exploited = getSuccessfulValidated();
  unsigned int duplicates = getEntriesWithDuplicates();
  unsigned int nonunique = getNonUniqueEntries();
  unsigned int domains = getUniqueDomains().size();

  os << "-3, ";
  os << "total entries, ";
  os << duplicates << ", " << nonunique << ", " << entries << ", " << domains << ", " << exploited << ", ";

  for (auto c : AutomatonGroup::m_sink_contexts) {
    os << getEntriesForSinkContextWeighted(c) << ", ";
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

  os << "-2, ";
  os << "deduplicated entries, ";
  os << duplicates << ", " << nonunique << ", " << entries << ", " << domains << ", " << exploited << ", ";

  for (auto c : AutomatonGroup::m_sink_contexts) {
    os << getEntriesForSinkContextDeduplicated(c) << ", ";
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

  os << "-1, ";
  os << "unique total, ";
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

void AutomatonGroups::printGeneratedPayloads(std::ostream& os) const {
  // Some summary numbers
  printStatus(os);
  CombinedAnalysisResult::printGeneratedPayloadHeader(os);
  for (auto& g : m_groups) {
    g.printGeneratedPayloads(os);
  }
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

unsigned int AutomatonGroups::getErrored() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getErrored();
  }
  return total;
}

unsigned int AutomatonGroups::getSanitizersForPayload() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getSanitizersForPayload();
  }
  return total;
}

unsigned int AutomatonGroups::getSanitizersWithPayload() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getSanitizersWithPayload();
  }
  return total;
}

unsigned int AutomatonGroups::getVulnerableSanitizersWithPayload() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getVulnerableSanitizersWithPayload();
  }
  return total;
}

unsigned int AutomatonGroups::getDomainsForPayload() const {
  std::set<std::string> domains;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    std::set<std::string> s = iter->getDomainsForPayload();
    domains.insert(s.begin(), s.end());
  }
  return domains.size();
}

unsigned int AutomatonGroups::getDomainsWithPayload() const {
  std::set<std::string> domains;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    std::set<std::string> s = iter->getDomainsWithPayload();
    domains.insert(s.begin(), s.end());
  }
  return domains.size();
}

unsigned int AutomatonGroups::getVulnerableDomainsWithPayload() const {
  std::set<std::string> domains;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    std::set<std::string> s = iter->getVulnerableDomainsWithPayload();
    domains.insert(s.begin(), s.end());
  }
  return domains.size();
}


unsigned int AutomatonGroups::getVulnerableSanitizersWithBypass() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getVulnerableSanitizersWithBypass();
  }
  return total;
}

unsigned int AutomatonGroups::getErroredSanitizersWithPayload() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getErroredSanitizersWithPayload();
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

unsigned int AutomatonGroups::getEntriesForSinkContextWeighted(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getEntriesForSinkContextWeighted(context);
  }
  return total;
}

unsigned int AutomatonGroups::getEntriesForSinkContextDeduplicated(const AttackContext& context) const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getEntriesForSinkContextDeduplicated(context);
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
    for (auto& s : g.getUniqueDomains()) {
      domains.insert(s.begin(), s.end());
    }
  }
  return domains;
}
