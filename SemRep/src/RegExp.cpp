/*
 * RegExp.cpp
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
#include "RegExp.hpp"

using namespace std;

//#define DEBUG_REGEX

#if defined(DEBUG_REGEX)
#define DEBUG_PRINT_FUNC(e)                                     \
    {                                                           \
        std::cout << __PRETTY_FUNCTION__ << std::endl;          \
        (e)->dump();                                            \
    }
#else
#define DEBUG_PRINT_FUNC(e) {}
#endif

int RegExp::id;

void RegExp::restID()
{
    id = 0;
}

void RegExp::simplify()
{
    if(exp1 != NULL) {
        exp1->simplify();
    }
    if(exp2 != NULL) {
        exp2->simplify();
    }
    {
        Kind v = kind;
        if(v == REGEXP_CHAR_RANGE) {
            if(from == to) {
                c = from;
                kind = REGEXP_CHAR;
            }
            goto end_switch0;;
        }
        if(v == REGEXP_UNION) {
            if(exp1->kind == REGEXP_EMPTY) {
                copy(exp2);
            } else if(exp2->kind == REGEXP_EMPTY) {
                copy(exp1);
            }
            goto end_switch0;;
        }
        if(v == REGEXP_REPEAT_STAR) {
            if(exp1->kind == REGEXP_EMPTY) {
                kind = REGEXP_STRING;
                s = "";
            }
            goto end_switch0;;
        }
        if(v == REGEXP_CONCATENATION) {
            if(exp1->kind == REGEXP_STRING && exp1->s == "") {
                copy(exp2);
            } else if(exp2->kind == REGEXP_STRING && exp2->s == "") {
                copy(exp1);
            }
            goto end_switch0;;
        }
end_switch0:;
    }

}

void RegExp::copy(RegExp* e)
{
    kind = e->kind;
    exp1 = e->exp1;
    exp2 = e->exp2;
    this->s = e->s;
    c = e->c;
    min = e->min;
    max = e->max;
    digits = e->digits;
    from = e->from;
    to = e->to;
    b = "";
}

RegExp::RegExp()
{
	// mimic implicit Java initialization semantics
    digits = 0;
    exp1 = NULL;
    exp2 = NULL;
    max = 0;
    min = 0;
    pos = 0;
    s = "";
    b = "";
    flags = 0;
    c = from = to = '\0';
    
}

RegExp::RegExp(std::string s)
{
	init(s, ALL);
}

RegExp::RegExp(std::string s, int syntax_flags)
{
	init(s, syntax_flags);

}

void RegExp::init(string s, int syntax_flags){
    // mimic implicit Java initialization semantics
    digits = 0;
    exp1 = NULL;
    exp2 = NULL;
    max = 0;
    min = 0;
    pos = 0;
    this->s = "";
    flags = 0;
    c = from = to = '\0';
    // explicit initialializion copied from Java code
    b = s;
    flags = syntax_flags;
    RegExp* e = parseUnionExp();
    if(pos < b.length()) {
        throw std::invalid_argument((stringbuilder() << "end-of-string expected at position " << pos << " was " << b.length()));
    }

    kind = e->kind;
    exp1 = e->exp1;
    exp2 = e->exp2;
    this->s = e->s;
    c = e->c;
    min = e->min;
    max = e->max;
    digits = e->digits;
    from = e->from;
    to = e->to;
    b = "";

}

void RegExp::dump()
{
    std::cout << "RegExp: " << hex << this << std::endl;
    std::cout << "        exp1: " << exp1 << ": " << (exp1 ? exp1->toString() : "") << std::endl;
    std::cout << "        exp2: " << exp2 << ": " << (exp2 ? exp2->toString() : "") << std::endl;
    std::cout << "        kind: " << kind << std::endl;
    std::cout << "        s: " << s << std::endl;
    std::cout << "        c: " << c << std::endl;
    std::cout << "        b: " << b << std::endl;
    std::cout << "        min: " << min << std::endl;
    std::cout << "        max: " << max << std::endl;
    std::cout << "        from: " << from << std::endl;
    std::cout << "        to: " << to << std::endl;
    std::cout << "        string: " << toString() << std::endl;
}

StrangerAutomaton* RegExp::toAutomaton() /* throws(IllegalArgumentException) */
{
    StrangerAutomaton* a = NULL;
    StrangerAutomaton* auto1;
    StrangerAutomaton* auto2;
    {
        Kind v = kind;
        if(v == REGEXP_UNION) {
            auto1 = exp1->toAutomaton();
            auto2 = exp2->toAutomaton();
            a = auto1->union_(auto2, ++id);
            delete auto1;
            delete auto2;
            goto end_switch1;;
        }
        if(v == REGEXP_CONCATENATION) {
            auto1 = exp1->toAutomaton();
            auto2 = exp2->toAutomaton();
            a = auto1->concatenate(auto2, ++id);
            delete auto1;
            delete auto2;
            goto end_switch1;;
        }
        if(v == REGEXP_INTERSECTION) {
            auto1 = exp1->toAutomaton();
            auto2 = exp2->toAutomaton();
            a = auto1->intersect(auto2, ++id);
            delete auto1;
            delete auto2;
            goto end_switch1;;
        }
        if(v == REGEXP_OPTIONAL) {
            auto1 = exp1->toAutomaton();
            a = auto1->optional(++id);
            delete auto1;
            goto end_switch1;;
        }
        if(v == REGEXP_REPEAT_STAR) {
            auto1 = exp1->toAutomaton();
            a = auto1->kleensStar(++id);
            delete auto1;
            goto end_switch1;;
        }
        if(v == REGEXP_REPEAT_PLUS) {
            auto1 = exp1->toAutomaton();
            a = auto1->closure(++id);
            delete auto1;
            goto end_switch1;;
        }
        if(v == REGEXP_REPEAT_MIN) {
            auto1 = exp1->toAutomaton();
            a = auto1->repeat(min, ++id);
            delete auto1;
            goto end_switch1;;
        }
        if(v == REGEXP_REPEAT_MINMAX) {
            auto1 = exp1->toAutomaton();
            a = auto1->repeat(min, max, ++id);
            delete auto1;
            goto end_switch1;;
        }
        if(v == REGEXP_COMPLEMENT) {
            auto1 = exp1->toAutomaton();
            a = auto1->complement(++id);
            delete auto1;
            goto end_switch1;;
        }
        if(v == REGEXP_CHAR) {
            a = StrangerAutomaton::makeChar(c, ++id);
            goto end_switch1;;
        }
        if(v == REGEXP_CHAR_RANGE) {
            a = StrangerAutomaton::makeCharRange(from, to, ++id);
            goto end_switch1;;
        }
        if(v == REGEXP_ANYCHAR) {
            a = StrangerAutomaton::makeDot(++id);
            goto end_switch1;;
        }
        if(v == REGEXP_EMPTY) {
            a = StrangerAutomaton::makeEmptyString(++id);
            goto end_switch1;;
        }
        if(v == REGEXP_STRING) {
            a = StrangerAutomaton::makeString(s, ++id);
            goto end_switch1;;
        }
        if(v == REGEXP_ANYSTRING) {
            a = StrangerAutomaton::makeAnyString(++id);
            goto end_switch1;;
        }
end_switch1:;
    }

    return a;
}

std::string RegExp::toString()
{
    std::string s;
    return toStringBuilder(s);
}

std::string RegExp::toStringBuilder(std::string &b)
{
    {
        std::string s1;
        std::string s2;
        {
            Kind v = kind;
            if(v == REGEXP_UNION) {
                b.append("(");
                exp1->toStringBuilder(b);
                b.append("|");
                exp2->toStringBuilder(b);
                b.append(")");
                goto end_switch2;;
            }
            if(v == REGEXP_CONCATENATION) {
                exp1->toStringBuilder(b);
                exp2->toStringBuilder(b);
                goto end_switch2;;
            }
            if(v == REGEXP_INTERSECTION) {
                b.append("(");
                exp1->toStringBuilder(b);
                b.append("&");
                exp2->toStringBuilder(b);
                b.append(")");
                goto end_switch2;;
            }
            if(v == REGEXP_OPTIONAL) {
                b.append("(");
                exp1->toStringBuilder(b);
                b.append(")?");
                goto end_switch2;;
            }
            if(v == REGEXP_REPEAT_STAR) {
                b.append("(");
                exp1->toStringBuilder(b);
                b.append(")*");
                goto end_switch2;;
            }
            if(v == REGEXP_REPEAT_MIN) {
                b.append("(");
                exp1->toStringBuilder(b);
                b.append("){").append(iToStr(min)).append(",}");
                goto end_switch2;;
            }
            if(v == REGEXP_REPEAT_MINMAX) {
                b.append("(");
                exp1->toStringBuilder(b);
                b.append("){").append(iToStr(min)).append(",").append(iToStr(max)).append("}");
                goto end_switch2;;
            }
            if(v == REGEXP_COMPLEMENT) {
                b.append("~(");
                exp1->toStringBuilder(b);
                b.append(")");
                goto end_switch2;;
            }
            if(v == REGEXP_CHAR) {
                b.append(1, c);
                goto end_switch2;;
            }
            if(v == REGEXP_CHAR_RANGE) {
                b.append("[\\").append(iToStr(from)).append("-\\").append(iToStr(to)).append("]");
                goto end_switch2;;
            }
            if(v == REGEXP_ANYCHAR) {
                b.append(".");
                goto end_switch2;;
            }
            if(v == REGEXP_EMPTY) {
                b.append("#");
                goto end_switch2;;
            }
            if(v == REGEXP_STRING) {
                b.append("\"").append(s).append("\"");
                goto end_switch2;;
            }
            if(v == REGEXP_ANYSTRING) {
                b.append("@");
                goto end_switch2;;
            }
            if(v == REGEXP_AUTOMATON) {
                b.append("<").append(s).append(">");
                goto end_switch2;;
            }
            if(v == REGEXP_INTERVAL) {
                std::string s1 = iToStr(min);
                std::string s2 = iToStr(max);
                b.append("<");
                if(digits > 0)
                    for (int i = (int)s1.length(); i < digits; i++)
                                                b.append("0");


                b.append(s1).append("-");
                if(digits > 0)
                    for (int i = (int)s2.length(); i < digits; i++)
                                                b.append("0");


                b.append(s2).append(">");
                goto end_switch2;;
            }
end_switch2:;
        }
    }

    return b;
}

//java::util::Set* RegExp::getIdentifiers()
//{
//    ::java::util::HashSet* set = (new ::java::util::HashSet());
//    getIdentifiers(set);
//    return set;
//}

//void RegExp::getIdentifiers(::java::util::Set* set)
//{
//    {
//        Kind v = kind;
//        if((v == REGEXP_UNION) || (v == REGEXP_CONCATENATION) || (v == REGEXP_INTERSECTION)) {
//            exp1->getIdentifiers(set);
//            exp2->getIdentifiers(set);
//            goto end_switch3;;
//        }
//        if((v == REGEXP_OPTIONAL) || (v == REGEXP_REPEAT_STAR) || (v == REGEXP_REPEAT_MIN) || (v == REGEXP_REPEAT_MINMAX) || (v == REGEXP_COMPLEMENT)) {
//            exp1->getIdentifiers(set);
//            goto end_switch3;;
//        }
//        if((v == REGEXP_AUTOMATON)) {
//            set)->add(static_cast< ::java::lang::Object* >(s));
//            goto end_switch3;;
//        }
//end_switch3:;
//    }
//
//}

RegExp* RegExp::makeUnion(RegExp* exp1, RegExp* exp2)
{
    RegExp* r = (new RegExp());
    r->kind = REGEXP_UNION;
    r->exp1 = exp1;
    r->exp2 = exp2;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeConcatenation(RegExp* exp1, RegExp* exp2)
{

    if((exp1->kind == REGEXP_CHAR || exp1->kind == REGEXP_STRING) && (exp2->kind == REGEXP_CHAR || exp2->kind == REGEXP_STRING))
        return makeString(exp1, exp2);

    RegExp* r = (new RegExp());
    r->kind = REGEXP_CONCATENATION;
    if(exp1->kind == REGEXP_CONCATENATION && (exp1->exp2->kind == REGEXP_CHAR || exp1->exp2->kind == REGEXP_STRING) && (exp2->kind == REGEXP_CHAR || exp2->kind == REGEXP_STRING)) {
        r->exp1 = exp1->exp1;
        r->exp2 = makeString(exp1->exp2, exp2);
    } else if((exp1->kind == REGEXP_CHAR || exp1->kind == REGEXP_STRING) && exp2->kind == REGEXP_CONCATENATION && (exp2->exp1->kind == REGEXP_CHAR || exp2->exp1->kind == REGEXP_STRING)) {
        r->exp1 = makeString(exp1, exp2->exp1);
        r->exp2 = exp2->exp2;
    } else {
        r->exp1 = exp1;
        r->exp2 = exp2;
    }
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeString(RegExp* exp1, RegExp* exp2)
{

    std::string b;
    if (exp1->kind == REGEXP_STRING)
        b.append(exp1->s);
    else
        b.append(1, exp1->c);
    if (exp2->kind == REGEXP_STRING)
        b.append(exp2->s);
    else
        b.append(1, exp2->c);
    RegExp* r = makeString(b);
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeIntersection(RegExp* exp1, RegExp* exp2)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_INTERSECTION;
    r->exp1 = exp1;
    r->exp2 = exp2;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeOptional(RegExp* exp)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_OPTIONAL;
    r->exp1 = exp;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeRepeatStar(RegExp* exp)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_REPEAT_STAR;
    r->exp1 = exp;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeRepeatPlus(RegExp* exp)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_REPEAT_PLUS;
    r->exp1 = exp;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeRepeat(RegExp* exp, int min)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_REPEAT_MIN;
    r->exp1 = exp;
    r->min = min;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeRepeat(RegExp* exp, int min, int max)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_REPEAT_MINMAX;
    r->exp1 = exp;
    r->min = min;
    r->max = max;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeComplement(RegExp* exp)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_COMPLEMENT;
    r->exp1 = exp;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeChar(char c)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_CHAR;
    r->c = c;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeCharRange(char from, char to)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_CHAR_RANGE;
    r->from = from;
    r->to = to;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeAnyChar()
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_ANYCHAR;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeEmpty()
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_EMPTY;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeString(std::string s)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_STRING;
    r->s = s;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeAnyString()
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_ANYSTRING;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeAutomaton(std::string s)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_AUTOMATON;
    r->s = s;
    DEBUG_PRINT_FUNC(r);
    return r;
}

RegExp* RegExp::makeInterval(int min, int max, int digits)
{

    RegExp* r = (new RegExp());
    r->kind = REGEXP_INTERVAL;
    r->min = min;
    r->max = max;
    r->digits = digits;
    DEBUG_PRINT_FUNC(r);
    return r;
}

bool RegExp::peek(std::string s, int offset)
{
    if ((pos + offset < b.length()) && (pos + offset >= 0)) {
        return s.find(b[pos + offset]) != string::npos;
    } else {
        return false;
    }
}

bool RegExp::match(char c)
{
    if(pos >= b.length())
        return false;

    if(b[pos] == c) {
        pos++;
        return true;
    }
    return false;
}

bool RegExp::more()
{
    return pos < b.length();
}

char RegExp::next() /* throws(IllegalArgumentException) */
{
    if(!more())
    	throw std::invalid_argument((stringbuilder() << "unexpected end-of-string"));

    return b[pos++];
}

bool RegExp::check(int flag)
{
    return (flags & flag) != 0;
}

RegExp* RegExp::parseUnionExp() /* throws(IllegalArgumentException) */
{
    RegExp* e = parseInterExp();
    if(match('|'))
        e = makeUnion(e, parseUnionExp());
    return e;
}

RegExp* RegExp::parseInterExp() /* throws(IllegalArgumentException) */
{
    RegExp* e = parseConcatExp();
    if(check(INTERSECTION) && match('&'))
        e = makeIntersection(e, parseInterExp());
    return e;
}

RegExp* RegExp::parseConcatExp() /* throws(IllegalArgumentException) */
{
    RegExp* e = parseRepeatExp();
    if(more() && !peek(")&|"))
        e = makeConcatenation(e, parseConcatExp());
    return e;
}

RegExp* RegExp::parseRepeatExp() /* throws(IllegalArgumentException) */
{
    RegExp* e = parseComplExp();
    while (peek("?*+{")) {
        if(match('?'))
            e = makeOptional(e);
        else if(match('*')) {
            e = makeRepeatStar(e);
        }
        else if(match('+'))
            e = makeRepeatPlus(e);
        else if(match('{')) {
            string::size_type start = pos;
            while (peek("0123456789"))
                                next();

            if(start == pos)
            	throw std::invalid_argument((stringbuilder() << "integer expected at position " << pos));

            int n = to_int(b.substr(start, pos - start));
            int m = -1;
            if(match(',')) {
                start = pos;
                while (peek("0123456789"))
                                        next();

                if(start != pos)
                    m = to_int(b.substr(start, pos - start));

            } else
                m = n;
            if(!match('}'))
            	throw std::invalid_argument((stringbuilder() << "expected '}' at position " << pos));

            if(m == -1)
                return makeRepeat(e, n);
            else
                return makeRepeat(e, n, m);
        }
    }
    return e;
}

RegExp* RegExp::parseComplExp() /* throws(IllegalArgumentException) */
{
    if(check(COMPLEMENT) && match('~'))
        return makeComplement(parseComplExp());
    else
        return parseCharClassExp();
}

RegExp* RegExp::parseCharClassExp() /* throws(IllegalArgumentException) */
{
    if(match('[')) {
        bool negate = false;
        if(match('^'))
            negate = true;

        RegExp* e = parseCharClasses();
        if (negate)
            e = makeIntersection(makeAnyChar(), makeComplement(e));

        if(!match(']'))
        	throw std::invalid_argument((stringbuilder() << "expected ']' at position " << pos));
        return e;
    } else {
        return parseSimpleExp();
    }
}

RegExp* RegExp::parseCharClasses() /* throws(IllegalArgumentException) */
{
    RegExp* e = parseCharClass();
    while (more() && !peek("]"))
                e = makeUnion(e, parseCharClass());
    return e;
}

RegExp* RegExp::parseCharClass() /* throws(IllegalArgumentException) */
{
    if (isShortHand()) {
        return parseShortHand();
    }
    char c = parseCharExp();
    if(match('-')) {
        if (isShortHand()) {
            // Need to match the - as a normal char
            return makeChar('-');
        }
        return makeCharRange(c, parseCharExp());
    } else {
        return makeChar(c);
    }
}

RegExp* RegExp::parseSimpleExp() /* throws(IllegalArgumentException) */
{
    if (match('^')) {
        // Anchor to the start of the string
        // TODO: this needs to be implemented...
        // Currently ignored
        return parseUnionExp();
    } else if (match('$')) {
        // Anchor to the end of the string
        // TODO: this needs to be implemented...
        // Currently ignored
        if (more()) {
            return parseUnionExp();
        } else {
            return makeString("");
        }
    } else if(match('.'))
        return makeAnyChar();
    else if(check(EMPTY) && match('#'))
        return makeEmpty();
    else if(check(ANYSTRING) && match('@')) {
        return makeAnyString();
    // else if(match('"')) {
    //     int start = (int)pos;
    //     while (more() && !peek("\""))
    //                     next();

    //     if(!match('"'))
    //     	throw std::invalid_argument((stringbuilder() << "expected '\"' at position " << pos));

    //     return makeString(b.substr(start, (pos - 1 - start)));
    } else if(match('(')) {
        if (match(')')) {
            return makeString("");
        }
        RegExp* e = parseUnionExp();
        if(!match(')')) {
        	throw std::invalid_argument((stringbuilder() << "expected ')' at position " << pos));
        }
        return e;
    } else if((check(AUTOMATON) || check(INTERVAL)) && match('<')) {
        int start = (int)pos;
        while (more() && !peek(">"))
                        next();

        if(!match('>'))
        	throw std::invalid_argument((stringbuilder() << "expected '>' at position " << pos));

        std::string s = b.substr(start, (pos - 1 - start));
        string::size_type i = s.find('-');
        if(i == string::npos) {
            if(!check(AUTOMATON))
            	throw std::invalid_argument((stringbuilder() << "interval syntax error at position " << (pos - 1)));
            return makeAutomaton(s);
        } else {
            if(!check(INTERVAL))
            	throw std::invalid_argument((stringbuilder() << "illegal identifier at position " << (pos - 1)));

            try {
                if(i == 0 || i == s.length() - 1 || i != s.find_last_of('-'))
                	throw std::invalid_argument((stringbuilder() << "Number Format Error"));

                std::string smin = s.substr(0, i);
                std::string smax = s.substr(i + 1, (s.length()-(i + 1)));
                int imin = to_int(smin);
                int imax = to_int(smax);
                int digits;
                if(smin.length() == smax.length())
                    digits = (int)smin.length();
                else
                    digits = 0;
                if(imin > imax) {
                    int t = imin;
                    imin = imax;
                    imax = t;
                }
                return makeInterval(imin, imax, digits);
            } catch (exception& e) {
                throw (std::invalid_argument((stringbuilder() << "interval syntax error at position " << (pos - 1))));
            }
        }
    } else {
        return parseCharOrShortHand();
    }
}


// Shorthand Character Classes: https://www.regular-expressions.info/shorthand.html
bool RegExp::isShortHand() {
    if (peek("\\")) {
        if (peek("dDsSwWp", 1)) {
            return true;
        }
    }
    return false;
}

RegExp* RegExp::parseShortHand() {
    if (match('\\')) {
        char c = next();
        switch (c) {
        case 'd':
            return new RegExp("[0-9]");
        case 'D':
            return new RegExp("[^0-9]");
        case 's':
            return new RegExp("[\\x20\\t\\r\\n\\f\\v]");
        case 'S':
            return new RegExp("[^\\s]");
        case 'w':
            return new RegExp("[0-9a-zA-Z]");
        case 'W':
            return new RegExp("[^\\w]");
        case 'p':
            return new RegExp("[\\r\\n]");
        default:
            // Maybe an error would be better?
            return makeChar(c);
        }
    }
    return makeChar(parseCharExp());
}

RegExp* RegExp::parseCharOrShortHand() {
    if (isShortHand()) {
        return parseShortHand();
    }
    return makeChar(parseCharExp());
}

char RegExp::parseCharExp() /* //throws(IllegalArgumentException) */
{
    // Loop for escaped chars...
    if (match('\\')) {
        // ... of the form \x26
        if (match('x')) {
            std::string allowedHexChars = "01234567890ABCDEFabcdef";
            if (peek(allowedHexChars)) {
                char first = next();
                if (peek(allowedHexChars)) {
                    // Match \xNM (= 0xNM)
                    char second = next();
                    return from_hex_chars(first, second);
                } else {
                    // Match \xN (= 0xN)
                    return from_hex_char(first);
                }
            } else {
                // Match \x alone (= 0)
                return 0;
            }
        } else if(match('f')) { // Form Feed
            return '\f';
        } else if(match('n')) { // Newline
            return '\n';
        } else if(match('r')) { // Carriage Return
            return '\r';
        } else if(match('t')) { // Tab
            return '\t';
        } else if(match('v')) { // Vertical Tab
            return '\v';
        } else {
            // Assume anything else is just esacped, return next character
            return next();
        }
    } else {
        return next();
    }
}



std::string RegExp::iToStr(int i){
	std::ostringstream convert;   // stream used for the conversion
	convert << i;      // insert the textual representation of 'Number' in the characters in the stream
	return convert.str();
}

string::size_type RegExp::indexOf(std::string s, char c){
	return s.find(c);
}

//int RegExp::parseInt(std::string s){
//	int i;
//	std::istringstream(s) >> i;
//	return i;
//}

int to_int(std::string input)
{
	const char *s = input.c_str();
     if ( s == NULL || s[0] == '\0' )
     {
        throw  std::invalid_argument("null or empty string argument");
     }
     bool negate = (s[0] == '-');
     if ( *s == '+' || *s == '-' )
          ++s;
     int result = 0;
     while(*s)
     {
          if ( *s >= '0' && *s <= '9' )
          {
              result = result * 10  - (*s - '0');  //assume negative number
          }
          else
              throw std::invalid_argument("invalid input string");
          ++s;
     }
     return negate ? result : -result; //-result is positive!
}

int from_hex_char(char c) {
    unsigned int x;
    std::stringstream ss;
    ss << std::hex << c;
    ss >> x;
    return x;
}

int from_hex_chars(char c1, char c2) {
    unsigned int x;
    std::stringstream ss;
    ss << std::hex << c1 << c2;
    ss >> x;
    return x;
}
