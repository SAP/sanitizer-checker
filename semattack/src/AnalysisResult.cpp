/*
 * AnalysisResult.cpp
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
 * Authors: Thomas Barber
 */

#include "AnalysisResult.hpp"


AnalysisResult::AnalysisResult()
    : m_map()
{
}


AnalysisResult::~AnalysisResult()
{
    clear();
}

const StrangerAutomaton* AnalysisResult::get(int node) const
{
    if (m_map.count(node) > 0) {
        return m_map.at(node);
    }
    return nullptr;
}

void AnalysisResult::set(int node, const StrangerAutomaton* a)
{
    if (m_map[node] != nullptr) {
        delete m_map[node];
    }
    m_map[node] = a;
}

void AnalysisResult::clear()
{
    for (auto a : m_map) {
        if (a.second != nullptr) {
            delete a.second;
            a.second = nullptr;
        }
    }
    m_map.clear();
}

AnalysisResultConstIterator AnalysisResult::find(int node) const
{
    return m_map.find(node);
}

AnalysisResultConstIterator AnalysisResult::begin() const
{
    return m_map.begin();
}

AnalysisResultConstIterator AnalysisResult::end() const
{
    return m_map.end();
}

