/*
 * AnalysisResult.hpp
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
 * Authors: Abdulbaki Aydin, Muath Alkhalaf
 */

#ifndef ANALYSISRESULT_HPP_
#define ANALYSISRESULT_HPP_

#include "StrangerAutomaton.hpp"

typedef std::map<int, const StrangerAutomaton*>::iterator AnalysisResultIterator;
typedef std::map<int, const StrangerAutomaton*>::const_iterator AnalysisResultConstIterator;

class AnalysisResult {

public:

    AnalysisResult();
    virtual ~AnalysisResult();

    // Move operations
    AnalysisResult(AnalysisResult&& other) = default;
    AnalysisResult& operator=(AnalysisResult&& other) = default;

    // Prevent copying
    AnalysisResult(const AnalysisResult&) = delete;
    AnalysisResult& operator=(const AnalysisResult&) = delete;

    void set(int node, const StrangerAutomaton* a);
    const StrangerAutomaton* get(int node) const;
    void clear();

    AnalysisResultConstIterator find(int node) const;
    AnalysisResultConstIterator begin() const;
    AnalysisResultConstIterator end() const;

private:
    std::map<int, const StrangerAutomaton*> m_map;
};

#endif /* ANALYSISRESULT_HPP_ */
