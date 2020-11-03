/*
 * AttackPatterns.hpp
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

#ifndef ATTACKPATTERNS_HPP_
#define ATTACKPATTERNS_HPP_

#include "StrangerAutomaton.hpp"

class AttackPatterns {

public:
    static StrangerAutomaton* getLiteralPattern();
    static StrangerAutomaton* lessThanPattern();
    static StrangerAutomaton* getHtmlPattern();
    static StrangerAutomaton* getHtmlAttributePattern();
    static StrangerAutomaton* getJavascriptPattern();
    static StrangerAutomaton* getUrlPattern();
    
    static StrangerAutomaton* getUndesiredSQLTest();
    static StrangerAutomaton* getUndesiredMFETest();

private:
    static StrangerAutomaton* getAttackPatternFromAllowedRegEx(const std::string& regex);

};


#endif /* ATTACKPATTERNS_HPP_ */
