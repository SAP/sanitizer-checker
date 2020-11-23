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

void AutomatonGroup::printHeaders() {
  std::cout << "Name "
            << "Entries ";
}

void AutomatonGroup::printSummary() const {
  std::cout << m_id << ": " <<getName()
            << " entries: "
            << getEntries();
}

void AutomatonGroup::printMembers(bool printAll) const {

  printSummary();
  std:: cout << ", ";
  // Get vulnerablility overlaps from first entry
  if (m_graphs.size() > 0) {
    m_graphs.at(0)->printResult();
  }
  if (printAll) {
    std::cout << std::endl << "Examples: ";
  } else {
    std::cout << ", Example: ";
  }
  for (auto iter : m_graphs) {
    std::cout << iter->getFileName() << ", ";
    if (!printAll) {
      break;
    }
  }
  std::cout << std::endl;
  //m_automaton->toDotAscii(0);
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

void AutomatonGroups::printGroups(bool printAll) const {
  // Switch to decimal
  std::cout << std::dec;
  //  SemAttack::perfInfo.print_operations_info();
  std::cout << "Total of " << m_groups.size() << " unique post-images with " << getEntries() << " entries." << std::endl;
  for (auto iter : m_groups) {
    iter.printMembers(printAll);
  }
}

unsigned int AutomatonGroups::getEntries() const {
  unsigned int total = 0;
  for (auto iter = m_groups.begin(); iter != m_groups.end(); ++iter) {
    total += iter->getEntries();
  }
  return total;
}
