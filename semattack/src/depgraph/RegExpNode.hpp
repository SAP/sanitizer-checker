/*
 * Literal.hpp
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
 * Authors: Abdulbaki Aydin, Muath Alkhalaf
 */

#ifndef REGEXPNODE_HPP_
#define REGEXPNODE_HPP_

#include "TacPlace.hpp"

class RegExpNode: public TacPlace {
public:
    RegExpNode(){ literalValue = ""; };
    RegExpNode(std::string literalVal){ this->literalValue = literalVal;};
    RegExpNode(const RegExpNode& other):literalValue(other.literalValue){};
	virtual ~RegExpNode(){};
	std::string toString() const {return this->literalValue;};
    std::string getLiteralValue() const { return this->literalValue;};
	bool equals(const TacPlace* place) const {
		const RegExpNode* o = dynamic_cast<const RegExpNode*>(place);
		if (o == NULL) return false;
		return o->literalValue == this->literalValue;
	};
    RegExpNode* clone() const { return new RegExpNode(*this);};

private:
	std::string literalValue;
};


#endif /* REGEXPNODE_HPP_ */
