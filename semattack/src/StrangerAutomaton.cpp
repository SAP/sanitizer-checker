/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * StrangerAutomaton.cpp
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
#include "StrangerAutomaton.hpp"
#include "exceptions/StrangerException.hpp"

using namespace std;

StrangerAutomaton::StrangerAutomaton(DFA* dfa)
{
	init();
	this->dfa = dfa;
}

StrangerAutomaton::StrangerAutomaton(const StrangerAutomaton* other)
{
	init();        
	this->dfa = dfaCopy(other->dfa);
}

StrangerAutomaton::StrangerAutomaton()
{
	init();
}
void StrangerAutomaton::init()
{
    top = false;
    bottom = false;
    this->ID = -1;
    this->autoTraceID = traceID++;
}

StrangerAutomaton::~StrangerAutomaton()
{
    if (this->dfa != NULL ){
        dfaFree(this->dfa);
        this->dfa = NULL;
    }
}

// some static members
int StrangerAutomaton::num_ascii_track = NUM_ASCII_TRACKS;
int* StrangerAutomaton::indices_main = allocateAscIIIndexWithExtraBits(num_ascii_track, 2);
unsigned* StrangerAutomaton::u_indices_main = getUnsignedIndices(num_ascii_track);



int StrangerAutomaton::getID() const
{
    return ID;
}

void StrangerAutomaton::setID(int id)
{
    ID = id;
}


char StrangerAutomaton::slash = '/';

bool StrangerAutomaton::coarseWidening = false;

PerfInfo* StrangerAutomaton::perfInfo = &PerfInfo::getInstance();


DFA* StrangerAutomaton::getDfa()
{
    return this->dfa;
}

StrangerAutomaton* StrangerAutomaton::clone(int id) const
{
	debug(stringbuilder() << id << " = clone(" << this->ID << ")");
	if (isBottom())
		return makeBottom(id);
	else if (isTop())
		return makeTop(id);
        else {
		debugToFile(stringbuilder() << "M[" << traceID << "] = dfaCopy(M["  << this->autoTraceID << "]);//" << id << " = clone(" << this->ID << ")");
		StrangerAutomaton* retMe = new StrangerAutomaton(dfaCopy(this->dfa));
		{
			retMe->setID(id);
			retMe->debugAutomaton();
		}
		return retMe;
	}
}

StrangerAutomaton* StrangerAutomaton::clone() const
{
    return this->clone(-1);
}



/**
 * Creates a new automaton that holds the bottom value of the String Analysis lattice.
 * (bottom < phi). This artificial bottom is used to make things faster as we do not
 * need to create a native c library DFA which holds language phi - the empty language.
 * If you need to actually make the language phi then refer to {@link makeAnyString}
 * and {@link complement}.
 * This method should be used for:
 * 1- Variables of type string if they are uninitialized and the
 * semantics of the language consider them to hold an unknown or null value.
 * 2- Variables with unknown type in dynamically typed languages. In this case as soon
 * as type is detected then we should use another factory method.
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
StrangerAutomaton* StrangerAutomaton::makeBottom(int id)
{
    
	debug(stringbuilder() << id << " = makeBottom()");
//	StrangerAutomaton* retMe =  new StrangerAutomaton(NULL);
    StrangerAutomaton* retMe = StrangerAutomaton::makePhi(id);
	{
		retMe->setID(id);
	}
	retMe->bottom = true;
	return retMe;
}

/**
 * Creates a new automaton that holds the bottom value of the String Analysis lattice.
 * (bottom < phi). This artificial bottom is used to make things faster as we do not
 * need to create a native c library DFA which holds language phi - the empty language.
 * If you need to actually make the language phi then refer to {@link makeAnyString}
 * and {@link complement}.
 * This method should be used for:
 * 1- Variables of type string if they are uninitialized and the
 * semantics of the language consider them to hold an unknown or null value.
 * 2- Variables with unknown type in dynamically typed languages. In this case as soon
 * as type is detected then we should use another factory method.
 */
StrangerAutomaton* StrangerAutomaton::makeBottom()
{
    
    return makeBottom(traceID);
}

/**
 * Creates a new automaton that holds the top value of the String Analysis lattice
 * which is undefined (undefined > Sigma*).
 * It is used for variables in dynamically typed languages which may change their type from
 * a string type to another nonstring type.
 * If you need to create Sigma* (the actual top) then refer to {@link makeAnyString}.
 * Joining a variable x of type string with itself should yield top
 * only if the other copy of the variable has a different type (hold top
 * value).
 * If a variable is declared but with no value then it should be bottom.
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
StrangerAutomaton* StrangerAutomaton::makeTop(int id)
{
    
	debug(stringbuilder() << id << " = makeTop()");
//	StrangerAutomaton* retMe =  new StrangerAutomaton(NULL);
	StrangerAutomaton* retMe =  StrangerAutomaton::makeAnyString(id);
	retMe->top = true;
    
	{
		retMe->setID(id);
	}
	return retMe;
}

/**
 * Creates a new automaton that holds the top value of the String Analysis lattice
 * which is undefined (undefined > Sigma*).
 * It is used for variables in dynamically typed languages which may change their type from
 * a string type to another nonstring type.
 * If you need to create Sigma* (the actual top) then refer to {@link makeAnyString}.
 * Joining a variable x of type string with itself should yield top
 * only if the other copy of the variable has a different type (hold top
 * value).
 * If a variable is declared but with no value then it should be bottom.
 */
StrangerAutomaton* StrangerAutomaton::makeTop()
{
    
    return makeTop(traceID);
}

/**
 * Creates an automaton that accepts exactly the given string. It also
 * assigns this string to StrangerAutomaton.str. If parameter s is empty
 * string then it will call StrangerAutomaton.makeEmptyString
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
StrangerAutomaton* StrangerAutomaton::makeString(const std::string& s, int id)
{
    
	debug(stringbuilder() << id << " = makeString(" << s << ")");
    
	StrangerAutomaton* retMe;
	// We need to set the string explicitly because the current way we deal
	// with replace is with a string parameter for replace instead of an
	// automaton. Until we have a replace function with the replace
	// parameter
	// as a string we will keep this->
    
	// if the string is empty then make sure you generate an empty string
	// automaton
	// cause empty string needs special treatment
	if (s.empty()) {
		return StrangerAutomaton::makeEmptyString(id);
	} else {
        
		debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_construct_string(\"" << escapeSpecialChars(s) << "\", NUM_ASCII_TRACKS, indices_main);//" << id << " = makeString(" << escapeSpecialChars(s) << ")");
        
		retMe = new StrangerAutomaton(
                    dfa_construct_string(s.c_str(), num_ascii_track, indices_main));
		{
			retMe->setID(id);
			retMe->debugAutomaton();
		}
		return retMe;
	}
}

/**
 * Creates an automaton that accepts exactly the given string. It also
 * assigns this string to StrangerAutomaton.str. If parameter s is empty
 * string then it will call StrangerAutomaton.makeEmptyString
 */
StrangerAutomaton* StrangerAutomaton::makeString(const std::string& s)
{
    
    return makeString(s, traceID);
}

StrangerAutomaton* StrangerAutomaton::makeContainsString(const std::string& s, int id)
{
    StrangerAutomaton* aut = makeString(s, id);
    StrangerAutomaton* contained = new StrangerAutomaton(
        dfa_star_M_star(aut->dfa, num_ascii_track, indices_main));
    delete aut;
    return contained;
}

StrangerAutomaton* StrangerAutomaton::makeContainsString(const std::string& s)
{
    return makeContainsString(s, traceID);
}

/**
 * Creates an automaton that accepts exactly the given character. It also
 * assigns this character to StrangerAutomaton.str
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * */
StrangerAutomaton* StrangerAutomaton::makeChar(char c, int id)
{
    debug(stringbuilder() << id << " = makeChar(" << c << ") -- start");
    StrangerAutomaton* retMe = new StrangerAutomaton(
      dfa_construct_char(c, num_ascii_track, indices_main));
    debug(stringbuilder() << id << " = makeChar(" << c << ") -- end");
    //std::cout << std::hex << static_cast<int>(c) << std::dec << std::endl;
    //retMe->toDotAscii(1);
    {
    	retMe->setID(id);
    	retMe->debugAutomaton();
    }
    return retMe;
}
/**
 * Creates an automaton that accepts exactly the given character. It also
 * assigns this character to StrangerAutomaton.str
 * */
StrangerAutomaton* StrangerAutomaton::makeChar(char c)
{
    
    return makeChar(c, traceID);
}

/**
 * returns an automaton that accepts a single character in the range between
 * from and to
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
StrangerAutomaton* StrangerAutomaton::makeCharRange(char from, char to, int id) {
    debug(stringbuilder() << id <<  " = makeCharRange(" << from << ", " << to << ")");
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_construct_range('" << from << "', '" << to << "', NUM_ASCII_TRACKS, indices_main);//" << id << " = makeCharRange(" << from << ", " << to << ")");
    
    StrangerAutomaton* retMe = new StrangerAutomaton(
                                                     dfa_construct_range(from, to,
                                                                         num_ascii_track,
                                                                         indices_main));
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }
    return retMe;
}

/**
 * returns an automaton that accepts a single character in the range between
 * from and to
 */
StrangerAutomaton* StrangerAutomaton::makeCharRange(char from, char to) {
    return makeCharRange(from, to, traceID);
}

/**
 * Creates an automaton that accepts any string including empty string (.*)
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * */
StrangerAutomaton* StrangerAutomaton::makeAnyString(int id) {
    debug(stringbuilder() << id <<  " = makeAnyString()");
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfaAllStringASCIIExceptReserveWords(NUM_ASCII_TRACKS, indices_main);//" << id << " = makeAnyString()");
    
    StrangerAutomaton* retMe = new StrangerAutomaton(
                                                     dfaAllStringASCIIExceptReserveWords(
                                                                                         num_ascii_track,
                                                                                         indices_main));
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Creates an automaton that accepts any string including empty string (.*)
 * */
StrangerAutomaton* StrangerAutomaton::makeAnyString() {
    return makeAnyString(traceID);
}

/**
 * Creates an automaton that accepts everything (.*) within the length from
 * l1 to l2 l2 = -1, indicates unbounded upperbound l1 = -1, indicates
 * unbounded lowerbound StrangerAutomaton.str will be assigned null.
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
// TODO: check to see if l1 is allowed to be 0
StrangerAutomaton* StrangerAutomaton::makeAnyStringL1ToL2(int l1, int l2, int id) {
    debug(stringbuilder() << "makeAnyStringL1ToL2(" << l1 << "," << l2 << ")");
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfaSigmaC1toC2(" << l1 << "," << l2 << ",NUM_ASCII_TRACKS, indices_main);//" << id << " = dfaSigmaC1toC2()");
    
    StrangerAutomaton* retMe = new StrangerAutomaton(
                                                     dfaSigmaC1toC2(l1, l2,
                                                                    num_ascii_track,
                                                                    indices_main));
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Creates an automaton that accepts everything (.*) within the length from
 * l1 to l2 l2 = -1, indicates unbounded upperbound l1 = -1, indicates
 * unbounded lowerbound StrangerAutomaton.str will be assigned null.
 */
StrangerAutomaton* StrangerAutomaton::makeAnyStringL1ToL2(int l1, int l2) {
    return makeAnyStringL1ToL2(l1, l2, traceID);
}

/**
 * Creates an automaton that accepts only the empty string "epsilon". It
 * also assigns empty string ("") to StrangerAutomaton.str to be used later
 * with autoToString method.
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::makeEmptyString(int id) {
    debug(stringbuilder() << id <<  " = makeEmptyString()");
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfaASCIIOnlyNullString(NUM_ASCII_TRACKS, indices_main);//" << id << " = makeEmptyString()");
    
    StrangerAutomaton* retMe = new StrangerAutomaton(
                                                     dfaASCIIOnlyNullString(
                                                                            num_ascii_track,
                                                                            indices_main));
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Creates an automaton that accepts only the empty string "epsilon". It
 * also assigns empty string ("") to StrangerAutomaton.str to be used later
 * with autoToString method.
 * @return
 */
StrangerAutomaton* StrangerAutomaton::makeEmptyString() {
    return makeEmptyString(traceID);
}

/**
 * creates an automaton that represents a dot (.) in a regular expressions.
 * Dot means single character of any value in alphabet.
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::makeDot(int id) {
    debug(stringbuilder() << id <<  " = makeDot()");
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfaDot(NUM_ASCII_TRACKS, indices_main);//"<< id << " = makeDot()");
    
    StrangerAutomaton* retMe = new StrangerAutomaton(
                                                     dfaDot(
                                                            num_ascii_track,
                                                            indices_main));
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * creates an automaton that represents a dot (.) in a regular expressions.
 * Dot means single character of any value in alphabet.
 * @return
 */
StrangerAutomaton* StrangerAutomaton::makeDot() {
    return makeDot(traceID);
}

/**
 * creates an automaton that accepts nothing, not even empty string
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * */
StrangerAutomaton* StrangerAutomaton::makePhi(int id) {
    debug(stringbuilder() << id <<  " = makePhi");
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfaASCIINonString(NUM_ASCII_TRACKS, indices_main);//"<< id << " = makePhi()");
    
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaASCIINonString(num_ascii_track, indices_main));
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * creates an automaton that accepts nothing, not even empty string
 * */
StrangerAutomaton* StrangerAutomaton::makePhi() {
    return makePhi(traceID);
}

std::string StrangerAutomaton::generateSatisfyingExample() const
{
    std::string str;
    if (!this->isEmpty()) {
	char* example = dfaGenerateExample(this->dfa, num_ascii_track, u_indices_main);
	if (example != NULL) {
            str = example;
            free(example);
        }
    }
    return str;
}

StrangerAutomaton* StrangerAutomaton::generateSatisfyingSingleton() const
{
    DFA* dfa = dfaGenerateSingleton(this->dfa, num_ascii_track, u_indices_main);
    if (dfa) {
        return new StrangerAutomaton(dfa);
    }
    return nullptr;
}

//***************************************************************************************
//*                                  Unary Operations                                   *
//*									-------------------									*
//* These operations are given one automata and result in a newly created one.			*
//***************************************************************************************

/**
 * Returns a new automaton that accepts (empty_string) union L(this auto)).
 * @param id: id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::optional(int id) {
    debug(stringbuilder() << id <<  " = makeOptional("  << this->ID <<  ") -- start");
    
    StrangerAutomaton* retMe = this->unionWithEmptyString(id);
    
    debug(stringbuilder() << id <<  " = makeOptional("  << this->ID <<  ") -- end");
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Returns a new automaton that accepts (empty_string) union L(this auto)).
 * @return
 */
StrangerAutomaton* StrangerAutomaton::optional() {
    return this->optional(traceID);
}



/**
 * Returns a new automaton that accepts (empty_string) union closure(this auto)).
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::kleensStar(int id) {
    debug(stringbuilder() << id <<  " = kleensStar("  << this->ID <<  ") -- start");
    
    StrangerAutomaton* temp = this->closure(this->ID);
    StrangerAutomaton* retMe = temp->unionWithEmptyString(id);
    delete temp;
    debug(stringbuilder() << id <<  " = kleensStar("  << this->ID <<  ") -- end");
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Returns a new automaton that accepts (empty_string) union closure(this auto)).
 * @return
 */
StrangerAutomaton* StrangerAutomaton::kleensStar() {
    return this->kleensStar(traceID);
}

/**
 * Returns a new automaton that accepts (empty_string) union closure(auto)).
 * @param auto: input auto to do kleens star for
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::kleensStar(StrangerAutomaton* otherAuto, int id) {
    debug(stringbuilder() << id <<  " = kleensStar(" << otherAuto->ID << ")");
    
    StrangerAutomaton* retMe = otherAuto->kleensStar(id);
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Returns a new automaton that accepts (empty_string) union closure(auto)).
 * @param auto: input auto to do kleens star for
 * @return
 */
StrangerAutomaton* StrangerAutomaton::kleensStar(StrangerAutomaton* otherAuto) {
    return kleensStar(otherAuto, traceID);
}


/**
 * returns a new automaton with language L = closure(L(this auto))
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::closure(int id) {
    debug(stringbuilder() << id <<  " = closure("  << this->ID <<  ")");
    
    if (isTop() || isBottom()) return this->clone(id);
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_closure_extrabit(M["<< this->autoTraceID << "], NUM_ASCII_TRACKS, indices_main);//"<<id << " = closure("  << this->ID <<  ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_closure_extrabit(this->dfa, num_ascii_track, indices_main));
    perfInfo->closure_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_closure++;
    
    retMe->setID(id);
    retMe->debugAutomaton();
    return retMe;
}

/**
 * returns a new automaton with language L = closure(L(this auto))
 * @return
 */
StrangerAutomaton* StrangerAutomaton::closure() {
    return this->closure(traceID);
}

/**
 * returns a new automaton with language L = closure(L(auto))
 * @param auto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::closure(StrangerAutomaton* otherAuto, int id) {
    debug(stringbuilder() << id <<  " = closure(" << otherAuto->ID << ")");
    
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = otherAuto->closure(id);

    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * returns a new automaton with language L = closure(L(auto))
 * @param auto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::closure(StrangerAutomaton* otherAuto) {
    return closure(otherAuto, traceID);
}

/**
 * Returns new automaton that accepts <code>min</code> or more concatenated
 * repetitions of the language of this automaton.
 *
 * @param min: minimum number of concatenations
 * @param id: id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::repeat(unsigned min, int id) {
    debug(stringbuilder() << id <<  " = repeate(" << min << ","  << this->ID <<  ") -- start");
    
    StrangerAutomaton* retMe = NULL;
    if (min == 0)
        retMe = this->kleensStar(id);
    else if (min == 1)
        retMe = this->closure(id);
    else {
        StrangerAutomaton* temp = this->closure(id);
        
        StrangerAutomaton* unionAuto = this->clone(id);
        StrangerAutomaton* concatAuto = this->clone(id);
        for (unsigned int i = 2; i < min; i++) {
        	StrangerAutomaton* tempConcat = concatAuto;
			concatAuto = tempConcat->concatenate(this,id);
			delete tempConcat;
            
			StrangerAutomaton* tempUnion = unionAuto;
			unionAuto = tempUnion->union_(concatAuto, id);
			delete tempUnion;
        }
        
        StrangerAutomaton* complement = unionAuto->complement(id);
        retMe = temp->intersect(complement);
        
        delete complement;
        delete concatAuto;
        delete unionAuto;
        delete temp;
    }
    debug(stringbuilder() << id <<  " = repeate(" << min << ","  << this->ID <<  ") -- end");
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Returns new automaton that accepts <code>min</code> or more concatenated
 * repetitions of the language of this automaton.
 *
 * @param min: minimum number of concatenations
 * @return
 */
StrangerAutomaton* StrangerAutomaton::repeat(unsigned min) {
    return this->repeat(min, traceID);
}


/**
 * Returns new automaton that accepts between <code>min</code> and
 * <code>max</code> (including both) concatenated repetitions of the
 * language of this automaton.
 *
 * @param min: minimum number of concatenations
 * @param max: maximum number of concatenations
 *
 * @param id: id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::repeat(unsigned min, unsigned max, int id) {
    debug(stringbuilder() << id <<  " = repeate(" << min << ", " << max << ", " << this->ID << ") -- start");
    
    StrangerAutomaton* retMe = NULL;
    if (min > max) {
        retMe = makePhi(id);
    }
    else {
        StrangerAutomaton* unionAuto = NULL;
        StrangerAutomaton* concatAuto = NULL;
        
        // handle min
        if ( min == 0) { // {min, max} where min is 0
        	unionAuto = makeEmptyString(id);
        	concatAuto = makeEmptyString(id);
        } else { 								   	// {min, max} where min > 0
        	concatAuto = this->clone(id);			// {min, max} where min = 1
            for (unsigned int i = 2; i <= min; i++) { 		// {min, max} where min > 1
            	StrangerAutomaton* tempConcat = concatAuto;
				concatAuto = tempConcat->concatenate(this,id);
				delete tempConcat;
            }
            unionAuto = concatAuto->clone(id);
        }
        
        // handle min + 1, max
    	for (unsigned int i = min + 1; i <= max; i++){
    		StrangerAutomaton* tempConcat = concatAuto;
    		concatAuto = tempConcat->concatenate(this,id);
    		delete tempConcat;
            
    		StrangerAutomaton* tempUnion = unionAuto;
    		unionAuto = tempUnion->union_(concatAuto, id);
    		delete tempUnion;
    	}
        
    	delete concatAuto;
    	retMe = unionAuto;
    }
    
    debug(stringbuilder() << id <<  " = repeate(" <<  min << ", " << max << ", " << this->ID << ") -- end");
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    
    return retMe;
}

/**
 * Returns new automaton that accepts between <code>min</code> and
 * <code>max</code> (including both) concatenated repetitions of the
 * language of this automaton.
 * @param min: minimum number of concatenations
 * @param max: maximum number of concatenations
 * @return
 */
StrangerAutomaton* StrangerAutomaton::repeat1(unsigned min, unsigned max) {
    return this->repeat(min, max, traceID);
}

/**
 * Returns a new automaton auto with L(auto)= the complement of the language of current automaton
 * @param id: id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::complement(int id) const {
    debug(stringbuilder() << id <<  " = complement("  << this->ID <<  ")");
    if (isTop())
        // top is an unknown type so can not be complemented
        return makeTop(id);
    else if (isBottom())
        // bottom is efficient phi so complement is Sigma*
        return makeAnyString(id);
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_negate(M[" << this->autoTraceID << "], NUM_ASCII_TRACKS, indices_main);//"<<id << " = complement("  << this->ID <<  ")");
    
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_negate(this->dfa, num_ascii_track, indices_main));
    perfInfo->complement_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_complement++;
    
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    
    return retMe;
}

/**
 * Returns a new automaton auto with L(auto)= the complement of the language of current automaton
 * @return
 */
StrangerAutomaton* StrangerAutomaton::complement() const {
    return this->complement(traceID);
}

//***************************************************************************************
//*                                  Binary Operations                                  *
//*									-------------------									*
//* These operations are given two automata and result in a newly created one.			*
//***************************************************************************************


/**
 * Returns a new automaton auto with L(auto)= L(this) union L(auto)
 * @param auto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::union_(const StrangerAutomaton* otherAuto, int id) const {
    debug(stringbuilder() << id <<  " = union_("  << this->ID <<  ", " << otherAuto->ID << ")");
    
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isTop() || otherAuto->isTop())
        return makeTop(id);
    else if (this->isBottom())
        return otherAuto->clone(id);
    else if (otherAuto->isBottom())
        return this->clone(id);
    
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_union_with_emptycheck(M[" << this->autoTraceID << "], M["<< otherAuto->autoTraceID  << "], NUM_ASCII_TRACKS, indices_main);//"<<id << " = union_("  << this->ID <<  ", " << otherAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_union_with_emptycheck(this->dfa, otherAuto->dfa, num_ascii_track, indices_main));
    perfInfo->union_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_union++;
    
    
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Returns a new automaton auto with L(auto)= L(this) union L(auto)
 * @param auto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::union_(const StrangerAutomaton* otherAuto) const {
    return this->union_(otherAuto, traceID);
}

/**
 * Returns a new automaton auto with L(auto)= L(this) union L2 where L2 contains only empty string (epsilon)
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::unionWithEmptyString(int id) {
    debug(stringbuilder() << id <<  " = unionWithEmptyString("  << this->ID <<  ") -- start");
    
    StrangerAutomaton* empty = StrangerAutomaton::makeEmptyString(-100);
    StrangerAutomaton* retMe = this->union_(empty, id);
    delete empty;
    
    debug(stringbuilder() << id <<  " = unionWithEmptyString("  << this->ID <<  ") -- end");
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Returns a new automaton auto with L(auto)= L(this) union L2 where L2 contains only empty string (epsilon)
 * @return
 */
StrangerAutomaton* StrangerAutomaton::unionWithEmptyString() {
    return this->unionWithEmptyString(traceID);
}


/**
 * Returns a new automaton auto with L(auto)= L(this) intersect L(auto)
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
StrangerAutomaton* StrangerAutomaton::intersect(const StrangerAutomaton* otherAuto, int id) const {
    debug(stringbuilder() << id <<  " = intersect("  << this->ID <<  ", " << otherAuto->ID << ")");
    
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isBottom() || otherAuto->isBottom())
        return makeBottom(id);
    else if (this->isTop())
        return otherAuto->clone(id);
    else if (otherAuto->isTop())
        return this->clone(id);
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_intersect(M[" << this->autoTraceID << "], M["<< otherAuto->autoTraceID  << "]);//"<<id << " = intersect("  << this->ID <<  ", " << otherAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_intersect(this->dfa, otherAuto->dfa));
    perfInfo->intersect_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_intersect++;
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::productImpl(StrangerAutomaton* otherAuto, int id) {
    debug(stringbuilder() << id <<  " = intersect("  << this->ID <<  ", " << otherAuto->ID << ")");

    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isBottom() || otherAuto->isBottom())
        return makeBottom(id);
    else if (this->isTop())
        return otherAuto->clone(id);
    else if (otherAuto->isTop())
        return this->clone(id);

    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_product_impl(M[" << this->autoTraceID << "], M["<< otherAuto->autoTraceID  << "]);//"<<id << " = intersect("  << this->ID <<  ", " << otherAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_product_impl(this->dfa, otherAuto->dfa));
    perfInfo->product_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_product++;

    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Returns a new automaton auto with L(auto)= L(this) intersect L(auto)
 */
StrangerAutomaton* StrangerAutomaton::intersect(const StrangerAutomaton* otherAuto) const {
    return intersect(otherAuto, traceID);
}


//***************************************************************************************
//*                                  Widening operations                                *
//***************************************************************************************

/**
 * This will do widen(this, auto). L(this) should_be_subset_of L(auto)
 * We first apply union, then this widening for a while then the
 * coarse one.
 * @param auto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::preciseWiden(const StrangerAutomaton* otherAuto, int id) const {
    debug(stringbuilder() << id <<  " = precise_widen("  << this->ID <<  ", " << otherAuto->ID << ")");
    
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isTop() || otherAuto->isTop())
        return makeTop(id);
    else if (this->isBottom())
        return otherAuto->clone(id);
    else if (otherAuto->isBottom())
        return this->clone(id);
    
    if (coarseWidening) {
        debugToFile(stringbuilder() << "setPreciseWiden();");
        setPreciseWiden();
        coarseWidening = false;
    }
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfaWiden(M[" << this->autoTraceID << "], M["<< otherAuto->autoTraceID  << "]);//"<<id << " = precise_widen("  << this->ID <<  ", " << otherAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaWiden(this->dfa, otherAuto->dfa));
    perfInfo->precisewiden_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_precisewiden++;
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * This will do widen(this, auto). L(this) should_be_subset_of L(auto)
 * We first apply union, then this widening for a while then the
 * coarse one.
 * @param auto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::preciseWiden(const StrangerAutomaton* otherAuto) const {
    return preciseWiden(otherAuto, traceID);
}

/**
 * This will do widen(this, auto). L(this) should_be_subset_of L(auto)
 * We first apply union, then precise widening for a while then this
 * coarse one.
 * @param auto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::coarseWiden(const StrangerAutomaton* otherAuto, int id) const {
    debug(stringbuilder() << id <<  " = coarse_widen("  << this->ID <<  ", " << otherAuto->ID << ")");
    
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isTop() || otherAuto->isTop())
        return makeTop(id);
    else if (this->isBottom())
        return otherAuto->clone(id);
    else if (otherAuto->isBottom())
        return this->clone(id);
    
    if (!coarseWidening) {
        debugToFile(stringbuilder() << "setCoarseWiden();");
        setCoarseWiden();
        coarseWidening = true;
    }
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfaWiden(M[" << this->autoTraceID << "], M["<< otherAuto->autoTraceID  << "]);//"<<id << " = coarse_widen("  << this->ID <<  ", " << otherAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaWiden(this->dfa, otherAuto->dfa));
    perfInfo->coarsewiden_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_coarsewiden++;
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * This will do widen(this, auto). L(this) should_be_subset_of L(auto)
 * We first apply union, then precise widening for a while then this
 * coarse one.
 * @param auto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::coarseWiden(const StrangerAutomaton* otherAuto) const {
    return coarseWiden(otherAuto, traceID);
}

//***************************************************************************************
//*                                  Forwards Concatenation                             *
//***************************************************************************************

/**
 * Concatenates current automaton with otherAuto-> New automaton will be
 * this+otherAuto-> If both automatons' strings are not null, they will be
 * concatenated too otherwise set null. id : id of node associated with this
 * auto; used for debugging purposes only
 *
 * @param auto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::concatenate(const StrangerAutomaton* otherAuto, int id) const
{
    debug(stringbuilder() << id <<  " = concatenate("  << this->ID <<  ", " << otherAuto->ID << ")");
    
    // TODO: this is different than javascrit semantics. check http://www.quirksmode.org/js/strings.html
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isTop() || otherAuto->isTop())
        return makeTop(id);
    else if (this->isBottom() || otherAuto->isBottom())
        return makeBottom(id);
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_concat(M[" << this->autoTraceID << "], M["<< otherAuto->autoTraceID  << "], NUM_ASCII_TRACKS, indices_main);//"<<id << " = concatenate("  << this->ID <<  ", " << otherAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    // dfa_concat_extrabit returns new dfa structure in memory so no need to
    // worry about the two dfas of this and auto
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_concat(this->dfa, otherAuto->dfa, num_ascii_track, indices_main));
    perfInfo->concat_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_concat++;

    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }
    return retMe;
}

/**
 * Concatenates current automaton with otherAuto-> New automaton will be
 * this+otherAuto-> If both automatons' strings are not null, they will be
 * concatenated too otherwise set null. id : id of node associated with this
 * auto; used for debugging purposes only
 *
 * @param auto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::concatenate(const StrangerAutomaton* otherAuto) const
{
    return concatenate(otherAuto, traceID);
}

//***************************************************************************************
//*                                  Backwards Concatenation                            *
//***************************************************************************************
/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the left side of a
 * concat operation that results in the concatAuto.
 *
 * @param rightSiblingAuto
 * @param concatAuto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::leftPreConcat(const StrangerAutomaton* rightSiblingAuto, int id) const
{
    debug(stringbuilder() << id <<  " = leftPreConcat("  << this->ID <<  ", " << rightSiblingAuto->ID << ")");
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isBottom() || rightSiblingAuto->isBottom())
        return makeBottom(id);
    else if (this->isTop() || rightSiblingAuto->isTop())
        return makeTop(id);
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_pre_concat(M[" << this->autoTraceID << "], M[" << rightSiblingAuto->autoTraceID << "], 1, NUM_ASCII_TRACKS, indices_main);//" << id << " = leftPreConcat("  << this->ID <<  ", " << rightSiblingAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_pre_concat(this->dfa, rightSiblingAuto->dfa, 1, num_ascii_track, indices_main));
    perfInfo->pre_concat_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_pre_concat++;
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the left side of a
 * concat operation that results in the concatAuto.
 *
 * @param rightSiblingAuto
 * @param concatAuto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::leftPreConcat(const StrangerAutomaton* rightSiblingAuto) const
{
    return leftPreConcat(rightSiblingAuto, traceID);
}


/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the left side of a
 * concat operation that results in the concatAuto.
 *
 * @param rightSiblingAuto
 * @param concatAuto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::leftPreConcatConst(std::string rightSiblingString, int id) const
{
    debug(stringbuilder() << id <<  " = rightPreConcatConst("  << this->ID <<  ", " << rightSiblingString << ")");
    
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isBottom())
        return makeBottom(id);
    else if (this->isTop())
        return makeTop(id);
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_pre_concat_const(M[" << this->autoTraceID << "], \"" << escapeSpecialChars(rightSiblingString) << "\", 1, NUM_ASCII_TRACKS, indices_main);//" <<id << " = rightPreConcatConst("  << this->ID <<  ", " << escapeSpecialChars(rightSiblingString) << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_pre_concat_const(this->dfa, rightSiblingString.c_str(), 1, num_ascii_track, indices_main));
    perfInfo->const_pre_concat_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_const_pre_concat++;
    
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the left side of a
 * concat operation that results in the concatAuto.
 *
 * @param rightSiblingAuto
 * @param concatAuto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::leftPreConcatConst(std::string rightSiblingString) const {
    return leftPreConcatConst(rightSiblingString, traceID);
}

/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the right side of a
 * concat operation that results in the concatAuto.
 *
 * @param leftSiblingAuto
 * @param concatAuto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::rightPreConcat(const StrangerAutomaton* leftSiblingAuto, int id) const
{
    debug(stringbuilder() << id <<  " = rightPreConcat("  << this->ID <<  ", " << leftSiblingAuto->ID<< ")");
    
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isBottom() || leftSiblingAuto->isBottom())
        return makeBottom(id);
    else if (this->isTop() || leftSiblingAuto->isTop())
        return makeTop(id);
    
    debugToFile(stringbuilder() << "M[" << (traceID) << "] = dfa_pre_concat(M[" << this->autoTraceID << "], M[" << leftSiblingAuto->autoTraceID << "], 2, NUM_ASCII_TRACKS, indices_main);//"<<id << " = rightPreConcat("  << this->ID <<  ", " << leftSiblingAuto->ID
				<< ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_pre_concat(this->dfa, leftSiblingAuto->dfa, 2, num_ascii_track, indices_main));
    perfInfo->pre_concat_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_pre_concat++;
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the right side of a
 * concat operation that results in the concatAuto.
 *
 * @param leftSiblingAuto
 * @param concatAuto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::rightPreConcat(const StrangerAutomaton* leftSiblingAuto) const
{
    return rightPreConcat(leftSiblingAuto, traceID);
}

/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the right side of a
 * concat operation that results in the concatAuto.
 *
 * @param leftSiblingString
 * @param concatAuto
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::rightPreConcatConst(std::string leftSiblingString, int id) const
{
    debug(stringbuilder() << id <<  " = rightPreConcatConst("  << this->ID <<  ", " << leftSiblingString << ")");
    
    // if top or bottom then do not use the c library as dfa == NULL
    if (this->isBottom())
        return makeBottom(id);
    else if (this->isTop())
        return makeTop(id);
    
    debugToFile(stringbuilder() << "M[" << traceID << "] = dfa_pre_concat_const(M[" << this->autoTraceID << "], \"" << escapeSpecialChars(leftSiblingString) << "\", 2, NUM_ASCII_TRACKS, indices_main);//" << id << " = rightPreConcatConst("  << this->ID <<  ", "
				<< escapeSpecialChars(leftSiblingString) << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_pre_concat_const(this->dfa, leftSiblingString.c_str(), 2, num_ascii_track, indices_main));
    perfInfo->const_pre_concat_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_const_pre_concat++;
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * For current automaton concatAuto (this) , method returns an automaton
 * retMe such that L(retME) = all possible strings to be the right side of a
 * concat operation that results in the concatAuto.
 *
 * @param leftSiblingString
 * @param concatAuto
 * @return
 */
StrangerAutomaton* StrangerAutomaton::rightPreConcatConst(std::string leftSiblingString) {
    return rightPreConcatConst(leftSiblingString, traceID);
}

//***************************************************************************************
//*                                  Forward Replacement                                *
//***************************************************************************************

/**
 * Parses a PHP regular expression and converts it into stranger automaton.
 * For allowed regular expressions check {@link RegExp}.
 * @param phpRegexOrig: the string literal representing the regular expression
 * @param preg: if following preg or ereg (now only supports preg)
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::regExToAuto(std::string phpRegexOrig,
                                                  bool preg, int id) {
    debug(stringbuilder() << "============");
    debug(stringbuilder() << id <<  " = regExToAuto(" << phpRegexOrig << ") -- start");
    
    StrangerAutomaton* retMe = NULL;
    
    if (phpRegexOrig.empty()) {
        throw StrangerException(AnalysisError::InvalidArgument, stringbuilder() << "regular expression is empty");
    } else {
        std::string phpRegex = phpRegexOrig;
        if (preg) {
            // if the preg regex is not delimited...
            char first = phpRegex[0];
            if (!first == StrangerAutomaton::slash){
                throw StrangerException(AnalysisError::InvalidArgument, stringbuilder() << "Undelimited preg regexp: \"" << phpRegexOrig << "\"");
            }
            std::string::size_type last = phpRegex.substr(1).find_last_of(StrangerAutomaton::slash);
            if (last == std::string::npos)
                throw StrangerException(AnalysisError::InvalidArgument, stringbuilder() << "Undelimited preg regexp: \"" << phpRegexOrig << "\"");
            // peel off delimiter
            phpRegexOrig = phpRegex.substr(1, last);
            debug(stringbuilder() << id <<  ": regular expression after removing delimeters = \""
                  << phpRegexOrig << "\"");
        }
        RegExp::restID();// for debugging purposes only
        try {
            RegExp* regExp = new RegExp(phpRegexOrig, RegExp::NONE);
            std::string regExpStringVal;
            debug(stringbuilder() << id <<  ": regExToString = "
                  << regExp->toStringBuilder(regExpStringVal));
            retMe = regExp->toAutomaton();
            delete regExp;
        } catch (...) {
            std::cout << "Exception thrown parsing RegExp: " << phpRegexOrig << std::endl;
            throw;
        }
    }
    
    debug(stringbuilder() << id <<  " = regExToAuto(" << phpRegexOrig << ") -- end");
    debug(stringbuilder() << "============");
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * Parses a PHP regular expression and converts it into stranger automaton.
 * Regualr expression should follow preg syntax.
 * For allowed regular expressions check {@link RegExp}.
 * @param phpRegexOrig: the string literal representing the regular expression
 * @return
 */
StrangerAutomaton* StrangerAutomaton::regExToAuto(std::string phpRegexOrig) {
    return regExToAuto(phpRegexOrig, true, traceID);
}

/**
 * constructs a StrangerAutomaton that accepts the result of replacing every
 * occurrence of a string of patternAuto language in subjectAuto language
 * with replaceStr. var and indices is the depth of the BDD (number of
 * variables in the BDD) and ordering of them
 * If patternAuto or subjectAuto are bottom then it will throw StrangerAutomatonException
 * IF patternAuto is top then it will throw StrangerAutomatonException
 * If subjectAuto is top then it will return top as replacing something in top which is not
 * guaranteed to be a string variable may cause errors
 *
 * @param patternAuto
 *            : search auto (of type StrangerAutomaton) , replace substrings
 *            which match elements in L(searchAuto)
 * @param replaceStr
 *            : the replace string (of type String) , replace with this
 *            string
 * @param subjectAuto
 *            : target auto (of type StrangerAutomaton) , replace substrings
 *            in L(subjectAuto)
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
//TODO: merge this with str_replace as we no longer need preg
StrangerAutomaton* StrangerAutomaton::reg_replace(const StrangerAutomaton* patternAuto,
                                                  const std::string& replaceStr, const StrangerAutomaton* subjectAuto, int id) {
    
    debug(stringbuilder() << id <<  " = reg_replace(" << patternAuto->ID << ", " << replaceStr << ", " << subjectAuto->ID << ")");
    // Note: the replaceAuto parameter should be of type
    // Automaton not String. We changed it
    // to use the replace function from StrangerLibrary.
    // TODO: Otherwise we need a method to accept all three parameters as
    // automaton in Stranger Library
    debug(stringbuilder() << "calling reg_replace with the following order (" << subjectAuto->ID << ", " << patternAuto->ID << ", " << replaceStr << ")");
    if (patternAuto->isBottom() || subjectAuto->isBottom())
        throw StrangerException(AnalysisError::InvalidArgument,
                                "SNH: In StrangerAutoatmon.reg_replace: either patternAuto or subjectAuto is bottom element (phi) which can not be used in replace.");
    else if (patternAuto->isTop())
        throw StrangerException(AnalysisError::InvalidArgument,
                                "SNH: In StrangerAutoatmon.reg_replace: patternAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
    else if (subjectAuto->isTop())
        throw StrangerException(AnalysisError::InvalidArgument,
                                "SNH: In StrangerAutoatmon.reg_replace: subjectAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
    
    debugToFile(stringbuilder() << "M[" << (traceID) << "] = dfa_replace_extrabit(M["<< subjectAuto->autoTraceID  << "], M[" << patternAuto->autoTraceID << "], \"" << replaceStr << "\" , NUM_ASCII_TRACKS, indices_main);//"<<id << " = reg_replace(" << patternAuto->ID << ", " << replaceStr
				<< ", " << subjectAuto->ID << ")");

    
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_replace_extrabit(subjectAuto->dfa, patternAuto->dfa, replaceStr.c_str(), num_ascii_track, indices_main));
    perfInfo->replace_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_replace++;
    
    {
        retMe->ID = id;
//        retMe->debugAutomaton();
    }
    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }
    return retMe;
}


StrangerAutomaton* StrangerAutomaton::general_replace(const StrangerAutomaton* patternAuto, const StrangerAutomaton* replaceAuto, const StrangerAutomaton* subjectAuto, int id) {

    debug(stringbuilder() << id <<  " = reg_replace(" << patternAuto->ID << ", " << replaceAuto->ID << ", " << subjectAuto->ID << ")");
    // Note: the replaceAuto parameter should be of type
    // Automaton not String. We changed it
    // to use the replace function from StrangerLibrary.
    // TODO: Otherwise we need a method to accept all three parameters as
    // automaton in Stranger Library
    debug(stringbuilder() << "calling reg_replace with the following order (" << subjectAuto->ID << ", " << patternAuto->ID << ", " << replaceAuto->ID << ")");
    if (patternAuto->isBottom() || subjectAuto->isBottom())
        throw StrangerException(AnalysisError::InvalidArgument,
                                "SNH: In StrangerAutoatmon.reg_replace: either patternAuto or subjectAuto is bottom element (phi) which can not be used in replace.");
    else if (patternAuto->isTop())
        throw StrangerException(AnalysisError::InvalidArgument,
                                "SNH: In StrangerAutoatmon.reg_replace: patternAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
    else if (subjectAuto->isTop())
        throw StrangerException(AnalysisError::InvalidArgument,
                                "SNH: In StrangerAutoatmon.reg_replace: subjectAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");

    debugToFile(stringbuilder() << "M[" << (traceID) << "] = dfa_replace_extrabit(M["<< subjectAuto->autoTraceID  << "], M[" << patternAuto->autoTraceID << "], \"" << replaceAuto->ID << "\" , NUM_ASCII_TRACKS, indices_main);//"<<id << " = reg_replace(" << patternAuto->ID << ", " << replaceAuto->ID
				<< ", " << subjectAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = nullptr;
    if (replaceAuto->isSingleton()) {
      std::string replaceStr = replaceAuto->getStr();
      if (patternAuto->isSingleton()) {
        std::string patternStr = patternAuto->getStr();
        //std::cout << patternAuto->isEmpty() << ", " << patternStr.length() << ", " <<  replaceStr.length() << std::endl;
        if ( ((patternStr.length() == 0) && (patternAuto->isEmpty())) || (replaceStr == patternStr)) {
          retMe = new StrangerAutomaton(subjectAuto);
        } else if (((patternStr.length() == 1) ||  // Single character
                    ((patternStr.length() == 0) && (!patternAuto->isEmpty()))) // Single NULL character (e.g. \x00)
                   && (replaceStr.length() > 0)) { // Not deleting
          std::cout << "Trying: replace_char_with_string: 0x" << std::hex << static_cast<int>(patternStr[0]) << std::dec << " --> " << replaceStr << std::endl;
          retMe = new StrangerAutomaton(dfa_replace_char_with_string(subjectAuto->dfa, num_ascii_track, indices_main, patternStr[0], replaceStr.c_str()));
        } else {
          retMe = new StrangerAutomaton(dfa_replace_extrabit(subjectAuto->dfa, patternAuto->dfa, replaceStr.c_str(), num_ascii_track, indices_main));
        }
      } else {
        retMe = new StrangerAutomaton(dfa_replace_extrabit(subjectAuto->dfa, patternAuto->dfa, replaceStr.c_str(), num_ascii_track, indices_main));
      } 
    } else {
        retMe = new StrangerAutomaton(dfa_general_replace_extrabit(subjectAuto->dfa, patternAuto->dfa, replaceAuto->dfa, num_ascii_track, indices_main));
    }
    perfInfo->replace_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_replace++;

    {
        retMe->ID = id;
//        retMe->debugAutomaton();
    }
    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }
    return retMe;
}

/**
 * constructs a StrangerAutomaton that accepts the result of replacing every
 * occurrence of a string of patternAuto language in subjectAuto language
 * with replaceStr. var and indices is the depth of the BDD (number of
 * variables in the BDD) and ordering of them
 *
 * @param patternAuto
 *            : search auto (of type StrangerAutomaton) , replace substrings
 *            which match elements in L(searchAuto)
 * @param replaceStr
 *            : the replace string (of type String) , replace with this
 *            string
 * @param subjectAuto
 *            : target auto (of type StrangerAutomaton) , replace substrings
 *            in L(subjectAuto)
 */
//TODO: merge this with str_replace as we no longer need preg
StrangerAutomaton* StrangerAutomaton::reg_replace(const StrangerAutomaton* patternAuto,
                                                  const std::string& replaceStr, const StrangerAutomaton* subjectAuto) {
    return reg_replace(patternAuto, replaceStr, subjectAuto, traceID);
}

/**
 * constructs a StrangerAutomaton that accepts the result of replacing every
 * occurrence of a string of searchAuto language in subjectAuto language
 * with replaceStr. var and indices is the depth of the BDD (number of
 * variables in the BDD) and ordering of them
 *
 * @param searchAuto
 *            : search auto (of type StrangerAutomaton) , replace substrings
 *            which match elements in L(searchAuto)
 * @param replaceStr
 *            : the replace string (of type String) , replace with this
 *            string
 * @param subjectAuto
 *            : target auto (of type StrangerAutomaton) , replace substrings
 *            in L(subjectAuto)
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 */
StrangerAutomaton* StrangerAutomaton::str_replace(const StrangerAutomaton* searchAuto,
                                                  const std::string& replaceStr, const StrangerAutomaton* subjectAuto, int id) {
    
    debug(stringbuilder() << id <<  " = str_replace(" << searchAuto->ID << ", " << replaceStr << ", " << subjectAuto->ID << ")");
    // Note: the original replaceAuto parameter in FSAAutomaton is of type
    // Automaton not String. We changed it
    // to use the replace function from StrangerLibrary which only accepts a
    // string literal.
    debug(stringbuilder() << "calling str_replace with the following order (" << subjectAuto->ID << ", " << searchAuto->ID << ", " << replaceStr << ")");
    
    if (searchAuto->isBottom() || subjectAuto->isBottom())
        throw StrangerException(AnalysisError::InvalidArgument,
                                         "SNH: In StrangerAutoatmon.str_replace: either searchAuto or subjectAuto is bottom element (phi) which can not be used in replace.");
    else if (searchAuto->isTop())
        throw StrangerException(AnalysisError::InvalidArgument,
                                         "SNH: In StrangerAutoatmon.str_replace: searchAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
    else if (subjectAuto->isTop())
        throw StrangerException(AnalysisError::InvalidArgument,
                                         "SNH: In StrangerAutoatmon.str_replace: subjectAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
       
    debugToFile(stringbuilder() << "M[" << (traceID) << "] = dfa_replace_extrabit(M["<< subjectAuto->autoTraceID  << "], M[" << searchAuto->autoTraceID << "], \"" << replaceStr << "\" , NUM_ASCII_TRACKS, indices_main);//"<<id << " = str_replace(" << searchAuto->ID << ", " << replaceStr << ", "
				<< subjectAuto->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_replace_extrabit(subjectAuto->dfa,searchAuto->dfa, replaceStr.c_str(), num_ascii_track, indices_main));
    perfInfo->replace_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_replace++;
    
    {
        retMe->ID = id;
    }
    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }
    return retMe;
}

/**
 * constructs a StrangerAutomaton that accepts the result of replacing every
 * occurrence of a string of searchAuto language in subjectAuto language
 * with replaceStr. var and indices is the depth of the BDD (number of
 * variables in the BDD) and ordering of them
 *
 * @param searchAuto
 *            : search auto (of type StrangerAutomaton) , replace substrings
 *            which match elements in L(searchAuto)
 * @param replaceStr
 *            : the replace string (of type String) , replace with this
 *            string
 * @param subjectAuto
 *            : target auto (of type StrangerAutomaton) , replace substrings
 *            in L(subjectAuto)
 */
StrangerAutomaton* StrangerAutomaton::str_replace(const StrangerAutomaton* searchAuto,
                                                  const std::string& replaceStr, const StrangerAutomaton* subjectAuto) {
    return str_replace(searchAuto, replaceStr, subjectAuto, traceID);
}

StrangerAutomaton* StrangerAutomaton::str_replace_once(const StrangerAutomaton* str, const StrangerAutomaton* replaceAuto, const StrangerAutomaton* subjectAuto, int id) {
    boost::posix_time::ptime start_time = perfInfo->current_time();
    std::string replaceStr = replaceAuto->getStr();
    StrangerAutomaton* retMe = new StrangerAutomaton(
        dfa_replace_once_extrabit(subjectAuto->dfa, str->dfa, replaceStr.c_str(), num_ascii_track, indices_main)
        );
    perfInfo->replace_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_replace++;

    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }

    {
        retMe->ID = id;
        //        retMe->debugAutomaton();
    }
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::str_replace_once(const StrangerAutomaton* str, const StrangerAutomaton* replaceAuto, const StrangerAutomaton* subjectAuto) {
    return str_replace_once(str, replaceAuto, subjectAuto, traceID);
}


StrangerAutomaton* StrangerAutomaton::match(const StrangerAutomaton* pattern, int group, const StrangerAutomaton* subjectAuto, int id)
{
    // Simple assumption
    StrangerAutomaton* retMe = subjectAuto->intersect(pattern, id);
    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }
    return retMe;
}

//***************************************************************************************
//*                                  Backward Replacement                               *
//***************************************************************************************

/**
 * This is for backward analysis to compute the preimage of replace
 * @param searchAuto
 *            : search auto (of type StrangerAutomaton) , replace substrings
 *            which match elements in L(searchAuto)
 * @param replaceStr
 *            : the replace string (of type String) , replace with this
 *            string
 * @param id
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
StrangerAutomaton* StrangerAutomaton::preReplace(const StrangerAutomaton* searchAuto,
                                                 std::string replaceString, int id) const {
    debug(stringbuilder() << id <<  " = preReplace("  << this->ID <<  ", " << searchAuto->ID << ")");
    if (searchAuto->isBottom() || this->isBottom())
        throw StrangerException(AnalysisError::MonaException,
                                "SNH: In StrangerAutoatmon.preReplace: either searchAuto or subjectAuto is bottom element (phi) which can not be used in replace.");
    else if (searchAuto->isTop())
        throw StrangerException(AnalysisError::MonaException,
                                "SNH: In StrangerAutoatmon.preReplace: searchAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
    else if (this->isTop())
        throw StrangerException(AnalysisError::MonaException,
                                "SNH: In StrangerAutoatmon.preReplace: subjectAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
    
    debugToFile(stringbuilder() << "M[" << (traceID) << "] = dfa_pre_replace_str(M[" << this->autoTraceID << "], M[" << searchAuto->autoTraceID << "], \"" << replaceString << "\" , NUM_ASCII_TRACKS, indices_main);//"<<id << " = preReplace("  << this->ID <<  ", " << searchAuto->ID << ")");
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_pre_replace_str(this->dfa, searchAuto->dfa, replaceString.c_str(), num_ascii_track, indices_main));
    perfInfo->pre_replace_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_pre_replace++;

    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }
    
    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

/**
 * This is for backward analysis to compute the preimage of replace
 * @param searchAuto
 *            : search auto (of type StrangerAutomaton) , replace substrings
 *            which match elements in L(searchAuto)
 * @param replaceStr
 *            : the replace string (of type String) , replace with this
 *            string
 * @return
 */
StrangerAutomaton* StrangerAutomaton::preReplace(const StrangerAutomaton* searchAuto,
                                                 std::string replaceString) const {
    return this->preReplace(searchAuto, replaceString, traceID);
}

StrangerAutomaton* StrangerAutomaton::preReplaceOnce(const StrangerAutomaton* searchAuto,
                                                     std::string replaceString, int id) const {
    debug(stringbuilder() << id <<  " = preReplace("  << this->ID <<  ", " << searchAuto->ID << ")");
    if (searchAuto->isBottom() || this->isBottom())
        throw StrangerException(AnalysisError::MonaException,
            "SNH: In StrangerAutoatmon.preReplace: either searchAuto or subjectAuto is bottom element (phi) which can not be used in replace.");
    else if (searchAuto->isTop())
        throw StrangerException(AnalysisError::MonaException,
            "SNH: In StrangerAutoatmon.preReplace: searchAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");
    else if (this->isTop())
        throw StrangerException(AnalysisError::MonaException,
            "SNH: In StrangerAutoatmon.preReplace: subjectAuto is top (indicating that the variable may no longer be of type string) and can not be used in replacement");

    
    debugToFile(stringbuilder() << "M[" << (traceID) << "] = dfa_pre_replace_str(M[" << this->autoTraceID << "], M[" << searchAuto->autoTraceID << "], \"" << replaceString << "\" , NUM_ASCII_TRACKS, indices_main);//"<<id << " = preReplace("  << this->ID <<  ", " << searchAuto->ID << ")");
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_pre_replace_once_str(this->dfa, searchAuto->dfa, replaceString.c_str(), num_ascii_track, indices_main));
    perfInfo->pre_replace_total_time += perfInfo->current_time() - start_time;
    perfInfo->num_of_pre_replace++;

    if (retMe->isNull()) {
        throw StrangerException(AnalysisError::MonaException, "Null DFA pointer returned from MONA");
    }

    {
        retMe->setID(id);
        retMe->debugAutomaton();
    }
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::preReplaceOnce(const StrangerAutomaton* searchAuto,
                                                 std::string replaceString) const {
    return this->preReplaceOnce(searchAuto, replaceString, traceID);
}

StrangerAutomaton* StrangerAutomaton::preMatch(const StrangerAutomaton* pattern, int group, int id) const
{
    // As the FW analysis already does the match, nothing neede here
    return this->clone(id);
}


//***************************************************************************************
//*                                  Length Operations                                  *
//*									-------------------									*
//* These operations retrieve or restrict length of current automaton language.			*
//***************************************************************************************

StrangerAutomaton* StrangerAutomaton::getUnaryAutomaton(int id) const {
    debug(stringbuilder() << id <<  " = dfa_string_to_unaryDFA("  << this->ID << ")");
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_string_to_unaryDFA(this->dfa, num_ascii_track, indices_main));
    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}


StrangerAutomaton* StrangerAutomaton::restrictLengthByOtherAutomaton(const StrangerAutomaton* otherAuto, int id) const {
    StrangerAutomaton* uL = otherAuto->getUnaryAutomaton();
    StrangerAutomaton* retMe = this->restrictLengthByUnaryAutomaton(uL);
    delete uL;
    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::restrictLengthByOtherAutomatonFinite(const StrangerAutomaton *otherAuto, int id) const {
    P_DFAFiniteLengths pDFAFiniteLengths = dfaGetLengthsFiniteLang(otherAuto->dfa, num_ascii_track, indices_main);
    unsigned *lengths = pDFAFiniteLengths->lengths;
    const unsigned size = pDFAFiniteLengths->size;

    unsigned i;
    for(i = 0; i < size; i++)
        cout << lengths[i] << ", ";
    cout << endl;

//    vector<unsigned> vec(lengths, lengths + size);
	debug(stringbuilder() << id <<  " = dfaRestrictByFiniteLengths("  << this->ID << ", " << otherAuto->ID << ")");
//    cout << "lengths are: " << vec << endl;
	StrangerAutomaton* retMe = new StrangerAutomaton(dfaRestrictByFiniteLengths(this->dfa, lengths, size, false, num_ascii_track, indices_main));
	retMe->ID = id;
	retMe->debugAutomaton();

    free(pDFAFiniteLengths->lengths);
    free(pDFAFiniteLengths);
    
    return retMe;
}


StrangerAutomaton* StrangerAutomaton::restrictLengthByUnaryAutomaton(const StrangerAutomaton* uL, int id) const {
    debug(stringbuilder() << id <<  " = dfa_restrict_by_unaryDFA("  << this->ID << ", " << uL->ID << ")");
    StrangerAutomaton* retMe = new StrangerAutomaton(dfa_restrict_by_unaryDFA(this->dfa, uL->dfa, num_ascii_track, indices_main));
    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}


//***************************************************************************************
//*                                  Automata checks                                    *
//*									-------------------									*
//* These operations only check current automaton without creating a new one.			*
//***************************************************************************************
/**
 * returns true if L(this auto) intersect L(auto) != phi (empty language)
 * @param auto
 * @param id1
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @param id2
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @return
 */
bool StrangerAutomaton::checkIntersection(const StrangerAutomaton* otherAuto, int id1, int id2) {
    std::string debugStr = stringbuilder() << "checkIntersection("  << this->ID <<  ", " << otherAuto->ID << ") = ";
    
    if (this->isTop() || otherAuto->isTop()){
        debug(stringbuilder() << debugStr << "true");
        return true;
    } else if (this->isBottom() || otherAuto->isBottom()){
        debug(stringbuilder() << debugStr << "false");
        return false;
    }
    
    
    debugToFile(stringbuilder() << "check_intersection(M[" << this->autoTraceID << "],M["<< otherAuto->autoTraceID  << "], NUM_ASCII_TRACKS, indices_main);//check_intersection("  << this->ID <<  ", " << otherAuto->ID << ")");
    int result = check_intersection(this->dfa,
                                    otherAuto->dfa, num_ascii_track,
                                    indices_main);
    
    {
        debug(stringbuilder() << debugStr <<  (result == 0 ? false : true));
    }
    
    if (result == 0) {
        return false;
    } else if (result == 1) {
        return true;
    } else {
        throw StrangerException(AnalysisError::MonaException,
                                "Error in checkIntersection result for StrangerAutomaton.");
    }
}

/**
 * returns true if L(this auto) intersect L(auto) != phi (empty language)
 * @param auto
 * @return
 */
bool StrangerAutomaton::checkIntersection(const StrangerAutomaton* otherAuto) {
    return this->checkIntersection(otherAuto, -1, -1);
}

/**
 * return true if parameter auto includes this otherAuto-> i.e. returns true if L(this auto)
 * is_subset_of L(parameter auto)
 *
 * @param auto
 * @param id1
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @param id2
 *            : id of node associated with this auto; used for debugging
 *            purposes only * @return
 */
bool StrangerAutomaton::checkInclusion(const StrangerAutomaton* otherAuto, int id1, int id2) const {
    std::string debugStr = stringbuilder() << "checkInclusion("  << this->ID <<  ", " << otherAuto->ID << ") = ";
    if ((otherAuto == nullptr) || this->isNull() || otherAuto->isNull()) {
        return false;
    } else if (this->isBottom() || otherAuto->isTop()){
        // phi is always a subset of any other set, top is always superset of anything
        debug(stringbuilder() << debugStr << "true");
        return true;
    } else if (otherAuto->isBottom() || this->isTop()){
        debug(stringbuilder() << debugStr << "false");
        return false;
    }
    
    debugToFile(stringbuilder() << "check_inclusion(M[" << this->autoTraceID << "],M["<< otherAuto->autoTraceID  << "], NUM_ASCII_TRACKS, indices_main);//check_inclusion("  << this->ID <<  ", " << otherAuto->ID << ")");
    int result = check_inclusion(this->dfa,
                                 otherAuto->dfa, num_ascii_track,
                                 indices_main);
    
    {
        debug(stringbuilder() << debugStr <<  (result == 0 ? false : true));
    }
    
    if (result == 0) {
        return false;
    } else if (result == 1) {
        return true;
    } else {
        throw StrangerException(AnalysisError::MonaException,
                                "Error in checkInclusion result for StrangerAutomaton.");
    }
}

/**
 * return true if parameter auto includes this otherAuto-> i.e. returns true if L(this auto)
 * is_subset_of L(parameter auto)
 *
 * @param auto
 * @return
 */
bool StrangerAutomaton::checkInclusion(const StrangerAutomaton* otherAuto) const {
    return this->checkInclusion(otherAuto, -1, -1);
}

/**
 * returns true if this auto is equivalent to parameter otherAuto-> i.e. returns true if
 * L(parameter auto) == L(this auto)
 *
 * @param auto
 * @param id1
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 * @param id2
 *            : id of node associated with this auto; used for debugging
 *            purposes only * @return
 */
bool StrangerAutomaton::checkEquivalence(const StrangerAutomaton* otherAuto, int id1, int id2) const {
    std::string debugStr = stringbuilder() << "checkEquivalence("  << this->ID <<  ", " << otherAuto->ID << ") = ";
    
    if ((this->isTop() && otherAuto->isTop()) || (this->isBottom() && otherAuto->isBottom())){
        debug(stringbuilder() << debugStr << "true");
        return true;
    }
    else if (this->isTop() || this->isBottom() || otherAuto->isTop() || otherAuto->isBottom()){
        debug(stringbuilder() << debugStr << "false");
        return false;
    }
    
    debugToFile(stringbuilder() << "check_equivalence(M[" << this->autoTraceID << "],M["<< otherAuto->autoTraceID  << "], NUM_ASCII_TRACKS, indices_main);//check_equivalence("  << this->ID <<  ", " << otherAuto->ID << ")");
    int result = check_equivalence(this->dfa,
                                   otherAuto->dfa,
                                   num_ascii_track,
                                   indices_main);
    
    {
        debug(stringbuilder() << debugStr << (result == 0 ? false : true));
    }
    
    if (result == 0) {
        return false;
    } else if (result == 1) {
        // They should both either include or exclude empty string
        //			return (this->empty == otherAuto->empty);
        return true;
    } else {
        // TODO: we should have our own exception for StrangerAutomaton
        throw StrangerException(AnalysisError::MonaException,
                                "Error in checkInclusion result for StrangerAutomaton.");
    }
}

/**
 * returns true if this auto is equivalent to parameter otherAuto i.e. returns true if
 * L(parameter auto) == L(this auto)
 *
 * @param auto
 * @return
 */
bool StrangerAutomaton::checkEquivalence(const StrangerAutomaton* otherAuto) const {
    return this->checkEquivalence(otherAuto, -1, -1);
}

/**
 * returns true (1) if {|w| < n: w elementOf L(M) && n elementOf Integers}
 * In other words length of all strings in the language is bounded by a value n
 */
bool StrangerAutomaton::isLengthFinite() const {
    std::string debugString = stringbuilder() << "isLengthFinite("  << this->ID << ") = ";
    int result = ::isLengthFiniteTarjan(this->dfa, num_ascii_track, indices_main);
    debug(stringbuilder() << debugString << ( result == 0 ? false : true ));
    if (result == 0)
        return false;
    else
        return true;
}

/**
 * returns maximum length if length is finite, exception otherwise
 */
unsigned StrangerAutomaton::getMaxLength() const {
	if( !(this->isLengthFinite()) ) {
            throw StrangerException(AnalysisError::InfiniteLength, "Length of this automaton is infinite! ID: " + this->ID);
	}

	P_DFAFiniteLengths finiteLengths = dfaGetLengthsFiniteLang(this->dfa, num_ascii_track, indices_main);
	const unsigned size = finiteLengths->size;
	unsigned *lengths = finiteLengths->lengths;
	unsigned max_length = lengths[size-1];

	free(finiteLengths->lengths);
	free(finiteLengths);

	return max_length;
}

/**
 * returns minimum length, if length is finite, otherwise handle it
 * TODO update this function to return min length even the length is infinite
 */
unsigned StrangerAutomaton::getMinLength() const {
	if( !(this->isLengthFinite()) ) {
            throw StrangerException(AnalysisError::InfiniteLength, "Length of this automaton is infinite! ID: " + this->ID);
	}

	P_DFAFiniteLengths finiteLengths = dfaGetLengthsFiniteLang(this->dfa, num_ascii_track, indices_main);
	unsigned *lengths = finiteLengths->lengths;
	unsigned min_length = lengths[0];

	free(finiteLengths->lengths);
	free(finiteLengths);

	return min_length;
}

/**
 * returns the result of this->checkEquivalence(other)
 */
bool StrangerAutomaton::equals(const StrangerAutomaton* otherAuto) const {
    return (otherAuto != NULL) &&
    this->checkEquivalence(otherAuto);
}

/**
 * returns true if this auto is empty. i.e. returns true if
 * L(this auto) == phi (empty set)
 *
 * @param id1
 *            : id of node associated with this auto; used for debugging
 *            purposes only
 *
 */
bool StrangerAutomaton::checkEmptiness() const {
    std::string debugStr = stringbuilder() << "checkEmptiness("  << this->ID <<  ") = ";
    if (this->isBottom()){
        debug(stringbuilder() << debugStr << "true");
        return true;
    } else if (this->isTop()){
        debug(stringbuilder() << debugStr << "false");
        return false;
    } else if (this->dfa == nullptr){
        return true;
    }

    debugToFile(stringbuilder() << "check_emptiness(M[" << this->autoTraceID << "], NUM_ASCII_TRACKS, indices_main);//check_emptiness("  << this->ID <<  ")");
    int result = check_emptiness(this->dfa, num_ascii_track,
                                 indices_main);
    {
        debug(stringbuilder() << debugStr << (result == 0 ? false : true));
    }
    
    if (result == 0) {
        return false;
    } else if (result == 1) {
        // if it contains empty string then it is not Phi
        return true;
    } else {
        // TODO: we should have our own exception for StrangerAutomaton
        throw StrangerException(AnalysisError::MonaException,
                                "Error in checkEmptiness result for StrangerAutomaton.");
    }
}

/**
 * returns true if this L(automaton) == bottom
 * if you need to check if the language is actual phi use {@link checkEmptiness}
 */
bool StrangerAutomaton::isEmpty() const {
    return checkEmptiness();
}

bool StrangerAutomaton::isNull() const {
    return (this->dfa == nullptr);
}


/**
 * check if this automaton only accepts empty string i.e. string of length
 * 0.
 *
 * @return
 */
bool StrangerAutomaton::checkEmptyString() const {
    if (this->isBottom() || this->isTop())
        return false;
    debugToFile(stringbuilder() << "checkEmptyString(M[" << this->autoTraceID << "]);//checkEmptyString("  << this->ID <<  ")");
    if (::checkEmptyString(this->dfa) == 1)
        return true;
    else
        return false;
}

bool StrangerAutomaton::isSingleton() const {
  char *s = ::isSingleton(this->dfa, num_ascii_track, indices_main);
  if (s == NULL) {
    return false;
  } else {
    free(s);
    return true;
  }
}

string StrangerAutomaton::getStr() const {
    char* result = ::isSingleton(this->dfa, num_ascii_track, indices_main);
    if (result == NULL){
        throw StrangerException(AnalysisError::MonaException, "Trying to get a string for an automaton with a nonSingleton language.");
    }
    string retMe(result);
    free(result);
    return retMe;
}

/**
 * check if this automaton represents the bottom of the lattice.
 * @return
 */
bool StrangerAutomaton::isBottom() const {
    //TODO: checkEmptiness causes lots of crashes so be careful here
    return (this->bottom == true);
}

/**
 * check if this automaton represents the top of the lattice.
 * @return
 */
bool StrangerAutomaton::isTop() const {
    return (this->top == true);
}


StrangerAutomaton* StrangerAutomaton::toUpperCase(int id) const
{
    debug(stringbuilder() << id <<  " = dfaToUpperCase("  << this->ID << ")");
	boost::posix_time::ptime start_time = perfInfo->current_time();
	StrangerAutomaton* retMe = new StrangerAutomaton(dfaToUpperCase(this->dfa, num_ascii_track, indices_main));
	perfInfo->to_uppercase_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_to_uppercase++;

    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::toLowerCase(int id) const
{
    debug(stringbuilder() << id <<  " = dfaToLowerCase("  << this->ID << ")");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaToLowerCase(this->dfa, num_ascii_track, indices_main));
	perfInfo->to_lowercase_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_to_lowercase++;

    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::preToUpperCase(int id) const {

    debug(stringbuilder() << id <<  " = dfaPreToUpperCase("  << this->ID << ")");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreToUpperCase(this->dfa, num_ascii_track, indices_main));
	perfInfo->pre_to_uppercase_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_to_uppercase++;

    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::preToLowerCase(int id) const {

    debug(stringbuilder() << id <<  " = dfaPreToLowerCase("  << this->ID << ")");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreToLowerCase(this->dfa, num_ascii_track, indices_main));
	perfInfo->pre_to_lowercase_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_to_lowercase++;

    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::trimSpaces(int id) const
{

    debug(stringbuilder() << id <<  " = dfaTrim(' ', "  << this->ID << ")");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaTrim(this->dfa, ' ', num_ascii_track, indices_main));
	perfInfo->trim_spaces_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_trim_spaces++;
    retMe->setID(id);
    return retMe;
//	char ws[3] = {' ', '\n', '\t'};
//	StrangerAutomaton* ret2 = trim(ws,id);
//	ret2->setID(id);
//	return ret2;
}

StrangerAutomaton* StrangerAutomaton::trimSpacesLeft(int id) const {

    debug(stringbuilder() << id <<  " = dfaLeftTrim(' ', "  << this->ID << ")");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaLeftTrim(this->dfa, ' ', num_ascii_track, indices_main));
	perfInfo->trim_spaces_left_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_trim_spaces_left++;

    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::trimSpacesRight(int id) const {

    debug(stringbuilder() << id <<  " = dfaRightTrim(' ', "  << this->ID << ")");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaRightTrim(this->dfa, ' ', num_ascii_track, indices_main));
	perfInfo->trim_spaces_right_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_trim_spaces_rigth++;

    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::trim(char c, int id) const {

    debug(stringbuilder() << id <<  " = dfaTrim(" << this->ID << "," << c << ")");

//    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaTrim(this->dfa, c, num_ascii_track, indices_main));

    retMe->setID(id);
    return retMe;
}
StrangerAutomaton* StrangerAutomaton::trimLeft(char c, int id) const {

    debug(stringbuilder() << id <<  " = dfaLeftTrim(" << this->ID << "," << c << ")");

//	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaLeftTrim(this->dfa, c, num_ascii_track, indices_main));


    retMe->setID(id);
    return retMe;
}
StrangerAutomaton* StrangerAutomaton::trimRight(char c, int id) const {

    debug(stringbuilder() << id <<  " = dfaRightTrim(" << this->ID << "," << c << ")");

//    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaRightTrim(this->dfa, c, num_ascii_track, indices_main));

    retMe->setID(id);
    return retMe;
}
StrangerAutomaton* StrangerAutomaton::trim(char chars[], int id) const {

    debug(stringbuilder() << id <<  " = dfaTrimSet(" << this->ID << ",chars )\n");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaTrimSet(this->dfa, chars, (int)strlen(chars), num_ascii_track, indices_main));
	perfInfo->trim_set_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_trim_set++;

    retMe->setID(id);
    return retMe;
}
//	    StrangerAutomaton* StrangerAutomaton::trimLeft(char chars[]){
//	    	return new StrangerAutomaton(dfaTrimLeftSet(this->dfa, chars, strlen(chars), num_ascii_track, indices_main));
//	    }
//	    StrangerAutomaton* StrangerAutomaton::trimRight(char chars[]){
//	    	return new StrangerAutomaton(dfaTrimSet(this->dfa, chars, strlen(chars), num_ascii_track, indices_main));
//	    }

StrangerAutomaton* StrangerAutomaton::preTrimSpaces(int id) const
{
    debug(stringbuilder() << id <<  " = dfaPreTrim(" << this->ID << ",' ')\n");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreTrim(this->dfa, ' ', num_ascii_track, indices_main));
//    StrangerAutomaton* a1 = new StrangerAutomaton(dfaPreTrim(retMe->dfa, '\n', num_ascii_track, indices_main));
//    delete retMe;
//    retMe = new StrangerAutomaton(dfaPreTrim(a1->dfa, '\t', num_ascii_track, indices_main));
//    delete a1;
    perfInfo->pre_trim_spaces_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_trim_spaces++;

    retMe->setID(id);
    return retMe;

}

StrangerAutomaton* StrangerAutomaton::preTrimSpacesLeft(int id) const
{

    debug(stringbuilder() << id <<  " = dfaPreTrimLeft(" << this->ID << ",' ')\n");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreLeftTrim(this->dfa, ' ', num_ascii_track, indices_main));
	perfInfo->pre_trim_spaces_left_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_trim_spaces_left++;

    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::preTrimSpacesRigth(int id) const
{
    debug(stringbuilder() << id <<  " = dfaPreTrim(" << this->ID << ",' ')\n");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreRightTrim(this->dfa, ' ', num_ascii_track, indices_main));
	perfInfo->pre_trim_spaces_rigth_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_trim_spaces_rigth++;
    retMe->setID(id);
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::substr_first_part(int start, int id) const  {
    if (start < 0) {
        throw StrangerException(AnalysisError::InvalidArgument, "current substr model does not support negative parameters!!!");
    }
    // Create a string with length up to start
    StrangerAutomaton* len1Auto = StrangerAutomaton::makeAnyStringL1ToL2(start, start);
    StrangerAutomaton* empty = StrangerAutomaton::makeEmptyString(id);
    // Replace the first start characters with the empty string (once)
    StrangerAutomaton* chopped = StrangerAutomaton::str_replace_once(len1Auto, empty, this, id);

    delete len1Auto;
    delete empty;
    return chopped;
}

StrangerAutomaton* StrangerAutomaton::substr(int start, int id) const  {
    boost::posix_time::ptime start_time = perfInfo->current_time();

    StrangerAutomaton* retMe = this->substr_first_part(start, id);

    perfInfo->substr_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_substr++;
    return retMe;
}


StrangerAutomaton* StrangerAutomaton::substr(int start, int length, int id) const  {
    if (length < 0) {
        throw StrangerException(AnalysisError::InvalidArgument, "current substr model does not support negative parameters!!!");
    }
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = NULL;
    if (length == 0) {
        retMe = StrangerAutomaton::makeEmptyString(id);
    } else {
        // First remove the characters from start -> start + length
        StrangerAutomaton* chopped =  this->substr_first_part(start, id);
        // Now make an automaton which accepts all strings of a certain length
        StrangerAutomaton* len2Auto = StrangerAutomaton::makeAnyStringL1ToL2(length, length);
        // Copy the chopped automaton and accept ALL states
        StrangerAutomaton* rejectAll = new StrangerAutomaton(dfaSetAllStatesTo(chopped->getDfa(), '+', num_ascii_track, indices_main));
        // Intersect the length and chopped automata
        StrangerAutomaton* substring = rejectAll->intersect(len2Auto, id);
        delete rejectAll;
        delete chopped;
        delete len2Auto;
        retMe = substring;
    }
    perfInfo->substr_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_substr++;
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::pre_substr(int start, int length, int id) const  {
    if (start < 0 || length < 0) {
        throw StrangerException(AnalysisError::InvalidArgument, "current substr model does not support negative parameters!!!");
    }
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = NULL;
    if (length == 0) {
        // Here we can do a short cut - if length is zero,
        // the output string will be empty, and the input
        // could be anything!
        retMe = StrangerAutomaton::makeAnyString(id);
    } else {
        // substr operation selects part of a string
        // s = "abcdefghij", start = 3, length = 3
        //         +++
        // s.substr(start, length) = "def"
        // The pre-image is constructed from three parts:
        // 1) Any chars, length "start"
        // 2) The output string
        // 3) Any string (we do not know the original length)
        StrangerAutomaton* left_side = StrangerAutomaton::makeAnyStringL1ToL2(start, start);
        StrangerAutomaton* left_middle = left_side->concatenate(this,id);
        StrangerAutomaton* right_side = StrangerAutomaton::makeAnyString(id);
        retMe = left_middle->concatenate(right_side, id);
        delete right_side;
        delete left_side;
        delete left_middle;
    }
    perfInfo->pre_substr_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_pre_substr++;
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::pre_substr(int start, int id) const  {
    if (start < 0) {
        throw StrangerException(AnalysisError::InvalidArgument, "current substr model does not support negative parameters!!!");
    }
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = NULL;

    // substr operation selects part of a string
    // with one argument, it removes first s chars
    // s = "abcdefghij", start = 3
    //         +++++++
    // s.substr(start) = "defghij"
    // The pre-image is constructed from three parts:
    // 1) Any chars, length "start"
    // 2) The output string
    StrangerAutomaton* left_side = StrangerAutomaton::makeAnyStringL1ToL2(start, start);
    retMe = left_side->concatenate(this,id);
    delete left_side;

    perfInfo->pre_substr_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_pre_substr++;
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::addslashes(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = addSlashes(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaAddSlashes(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->addslashes_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_addslashes++;

	retMe->ID = id;
	retMe->debugAutomaton();
    return retMe;
}



StrangerAutomaton* StrangerAutomaton::pre_addslashes(const StrangerAutomaton* subjectAuto, int id)
{

	debug(stringbuilder() << id << " = pre_addSlashes(" << subjectAuto->ID << ");");

	boost::posix_time::ptime start_time = perfInfo->current_time();
	StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreAddSlashes(subjectAuto->dfa, num_ascii_track, indices_main));
	perfInfo->pre_addslashes_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_addslashes++;

	retMe->ID = id;
	retMe->debugAutomaton();
	return retMe;
}

StrangerAutomaton* StrangerAutomaton::encodeAttrString(const StrangerAutomaton* subjectAuto, int id)
{

    debug(stringbuilder() << id << " = encodeAttrString(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaEncodeAttrString(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->encodeattrstring_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_encodeattrstring++;

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::pre_encodeAttrString(const StrangerAutomaton* subjectAuto, int id)
{

    debug(stringbuilder() << id << " = pre_encodeAttrString(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreEncodeAttrString(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->pre_encodeattrstring_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_pre_encodeattrstring++;

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::encodeTextFragment(const StrangerAutomaton* subjectAuto, int id)
{

    debug(stringbuilder() << id << " = encodeTextFragment(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaEncodeTextFragment(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->encodetextfragment_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_encodetextfragment++;

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::pre_encodeTextFragment(const StrangerAutomaton* subjectAuto, int id)
{

    debug(stringbuilder() << id << " = pre_encodeTextFragment(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreEncodeTextFragment(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->pre_encodetextfragment_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_pre_encodetextfragment++;

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::escapeHtmlTags(const StrangerAutomaton* subjectAuto, int id)
{

    debug(stringbuilder() << id << " = escapeHtmlTags(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaHtmlEscapeTags(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->escapehtmltags_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_escapehtmltags++;

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::pre_escapeHtmlTags(const StrangerAutomaton* subjectAuto, int id)
{

    debug(stringbuilder() << id << " = pre_escapeHtmlTags(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreHtmlEscapeTags(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->pre_escapehtmltags_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_pre_escapehtmltags++;

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::htmlSpecialChars(const StrangerAutomaton* subjectAuto, string flag, int id)
{
    hscflags_t _flag;
    if (flag == "ENT_COMPAT")
		_flag = ENT_COMPAT;
    else if (flag == "ENT_QUOTES")
		_flag = ENT_QUOTES;
    else if (flag == "ENT_NOQUOTES")
		_flag = ENT_NOQUOTES;
    else if (flag == "ENT_SLASH")
		_flag = ENT_SLASH;
    else
        throw StrangerException(AnalysisError::InvalidArgument, stringbuilder() << "htmlspecialchar is not supporting the flag: " << flag);

    debug(stringbuilder() << id << " = htmlSpecialChars(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaHtmlSpecialChars(subjectAuto->dfa, num_ascii_track, indices_main, _flag));
    perfInfo->htmlspecialchars_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_htmlspecialchars++;

	retMe->ID = id;
	retMe->debugAutomaton();
    return retMe;
}



StrangerAutomaton* StrangerAutomaton::preHtmlSpecialChars(const StrangerAutomaton* subjectAuto, string flag, int id)
{

    hscflags_t _flag;
    if (flag == "ENT_COMPAT")
		_flag = ENT_COMPAT;
    else if (flag == "ENT_QUOTES")
		_flag = ENT_QUOTES;
    else if (flag == "ENT_NOQUOTES")
		_flag = ENT_NOQUOTES;
    else
        throw StrangerException(AnalysisError::InvalidArgument, stringbuilder() << "htmlspecialchar is not supporting the flag: " << flag);

    debug(stringbuilder() << id << " = preHtmlSpecialChars(" << subjectAuto->ID << ");");
    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreHtmlSpecialChars(subjectAuto->dfa, num_ascii_track, indices_main, _flag));
    perfInfo->pre_htmlspecialchars_total_time += perfInfo->current_time() - start_time;
    perfInfo->number_of_pre_htmlspecialchars++;

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}


StrangerAutomaton* StrangerAutomaton::stripslashes(const StrangerAutomaton* subjectAuto, int id)
{
	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton *sigmaStar = StrangerAutomaton::regExToAuto("/(.*('|\\\"|\\\\).*)+/", true, id);
//    sigmaStar->toDotAscii(0);
    StrangerAutomaton *sigmaStarSlashed = addslashes(sigmaStar, id);
//    sigmaStarSlashed->toDotAscii(0);
    delete sigmaStar;
    StrangerAutomaton *sigmaStarNotSlashed = sigmaStarSlashed->complement(id);
//    sigmaStarNotSlashed->toDotAscii(0);
    StrangerAutomaton *slashed = subjectAuto->intersect(sigmaStarSlashed, id);
//    slashed->toDotAscii(0);
    delete sigmaStarSlashed;
    StrangerAutomaton *notSlashed = subjectAuto->intersect(sigmaStarNotSlashed, id);
//    notSlashed->toDotAscii(0);
    delete sigmaStarNotSlashed;
    StrangerAutomaton *slashedPre = pre_addslashes(slashed, id);
//    slashedPre->toDotAscii(0);
    delete slashed;
    StrangerAutomaton *retMe = notSlashed->union_(slashedPre, id);
    delete slashedPre;

    perfInfo->stripslashes_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_stripslashes++;


	retMe->ID = id;
	retMe->debugAutomaton();

    return retMe;
}

StrangerAutomaton* StrangerAutomaton::pre_stripslashes(const StrangerAutomaton* subjectAuto, int id)
{

    StrangerAutomaton *slashed = addslashes(subjectAuto, id);

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton *result = slashed->union_(subjectAuto, id);
    perfInfo->pre_stripslashes_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_stripslashes++;

    delete slashed;
    return result;
}

StrangerAutomaton* StrangerAutomaton::mysql_escape_string(const StrangerAutomaton* subjectAuto, int id) {

    debug(stringbuilder() << id << " = mysql_escape_string(" << subjectAuto->ID << ");");

	boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaMysqlEscapeString(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->mysql_escape_string_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_mysql_escape_string++;

	retMe->ID = id;
	retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::pre_mysql_escape_string(const StrangerAutomaton* subjectAuto, int id) {

	debug(stringbuilder() << id << " = pre_mysql_escape_string(" << subjectAuto->ID << ");");

	boost::posix_time::ptime start_time = perfInfo->current_time();
	StrangerAutomaton* retMe = new StrangerAutomaton(dfaPreMysqlEscapeString(subjectAuto->dfa, num_ascii_track, indices_main));
    perfInfo->pre_mysql_escape_string_total_time += perfInfo->current_time() - start_time;
	perfInfo->number_of_pre_mysql_escape_string++;


	retMe->ID = id;
	retMe->debugAutomaton();
	return retMe;
}

StrangerAutomaton* StrangerAutomaton::mysql_real_escape_string(const StrangerAutomaton* subjectAuto, int id)
{
    
    //    debug(::java::lang::StringBuilder().append(id)->append(" = mysql_real_escape_string(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- start")->toString());
    //    StrangerAutomaton* searchAuto = StrangerAutomaton::makeString("\\", int32_t(1));
    //    std::string replaceStr = "\\\\";
    //    StrangerAutomaton* retMe = str_replace(searchAuto, replaceStr, subjectAuto, int32_t(2));
    //    searchAuto = StrangerAutomaton::makeString("'", int32_t(3));
    //    replaceStr = "\\'";
    //    retMe = str_replace(searchAuto, replaceStr, retMe, int32_t(4));
    //    searchAuto = StrangerAutomaton::makeString("\"", int32_t(5));
    //    replaceStr = "\\\"";
    //    retMe = str_replace(searchAuto, replaceStr, retMe, int32_t(6));
    //    debug(::java::lang::StringBuilder().append(id)->append(" = mysql_real_escape_string(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- end")->toString());
    //{
    //        npc(subjectAuto)->ID = id;
    //        npc(subjectAuto)->debugAutomaton();
    //    }
    //
    //    return retMe;
    throw StrangerException(AnalysisError::NotImplemented, "not implemented");
    
}

StrangerAutomaton* StrangerAutomaton::pre_mysql_real_escape_string(const StrangerAutomaton* subjectAuto, int id)
{
    
    //    debug(::java::lang::StringBuilder().append(id)->append(" = pre_mysql_real_escape_string(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- start")->toString());
    //    StrangerAutomaton* searchAuto = StrangerAutomaton::makeString("\\", int32_t(1));
    //    std::string replaceStr = "\\\\";
    //    StrangerAutomaton* retMe = npc(subjectAuto)->preReplace(searchAuto, replaceStr, int32_t(2));
    //    searchAuto = StrangerAutomaton::makeString("'", int32_t(5));
    //    replaceStr = "\\'";
    //    retMe = retMe->preReplace(searchAuto, replaceStr, int32_t(2));
    //    searchAuto = StrangerAutomaton::makeString("\"", int32_t(5));
    //    replaceStr = "\\\"";
    //    retMe = retMe->preReplace(searchAuto, replaceStr, int32_t(2));
    //    debug(::java::lang::StringBuilder().append(id)->append(" = pre_mysql_real_escape_string(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- end")->toString());
    //{
    //        npc(subjectAuto)->ID = id;
    //        npc(subjectAuto)->debugAutomaton();
    //    }
    //
    //    return retMe;
    throw StrangerException(AnalysisError::NotImplemented, "not implemented");
}

StrangerAutomaton* StrangerAutomaton::nl2br(const StrangerAutomaton* subjectAuto, int id)
{
    
    //    debug(::java::lang::StringBuilder().append(id)->append(" = nl2br(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- start")->toString());
    //    StrangerAutomaton* searchAuto = StrangerAutomaton::makeString("\\n", int32_t(1));
    //    std::string replaceStr = "<br/>";
    //    StrangerAutomaton* retMe = StrangerAutomaton::str_replace(searchAuto, replaceStr, subjectAuto, int32_t(2));
    //    debug(::java::lang::StringBuilder().append(id)->append(" = nl2br(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- end")->toString());
    //{
    //        npc(subjectAuto)->ID = id;
    //        npc(subjectAuto)->debugAutomaton();
    //    }
    //
    //    return retMe;
    throw StrangerException(AnalysisError::NotImplemented, "not implemented");
}

StrangerAutomaton* StrangerAutomaton::pre_nl2br(const StrangerAutomaton* subjectAuto, int id)
{
    
    //    debug(::java::lang::StringBuilder().append(id)->append(" = pre_nl2br(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- start")->toString());
    //    StrangerAutomaton* searchAuto = StrangerAutomaton::makeString("\\n", int32_t(1));
    //    std::string replaceStr = "<br/>";
    //    StrangerAutomaton* retMe = npc(subjectAuto)->preReplace(searchAuto, replaceStr, int32_t(2));
    //    debug(::java::lang::StringBuilder().append(id)->append(" = pre_nl2br(")
    //        ->append(npc(subjectAuto)->ID)
    //        ->append(") -- end")->toString());
    //{
    //        npc(subjectAuto)->ID = id;
    //        npc(subjectAuto)->debugAutomaton();
    //    }
    //
    //    return retMe;
    throw StrangerException(AnalysisError::NotImplemented, "not implemented");
}

StrangerAutomaton* StrangerAutomaton::encodeURIComponent(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = encodeURIComponent(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaEncodeUriComponent(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::decodeURIComponent(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = decodeURIComponent(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaDecodeUriComponent(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::encodeURI(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = encodeURI(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaEncodeUri(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::decodeURI(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = decodeURI(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaDecodeUri(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::escape(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = escape(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaEscape(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::unescape(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = unescape(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaUnescape(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::jsonStringify(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = jsonStringify(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaJsonStringify(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

StrangerAutomaton* StrangerAutomaton::jsonParse(const StrangerAutomaton* subjectAuto, int id)
{
    debug(stringbuilder() << id << " = jsonParse(" << subjectAuto->ID << ");");

    boost::posix_time::ptime start_time = perfInfo->current_time();
    StrangerAutomaton* retMe = new StrangerAutomaton(dfaJsonParse(subjectAuto->dfa, num_ascii_track, indices_main));

    retMe->ID = id;
    retMe->debugAutomaton();
    return retMe;
}

void StrangerAutomaton::printAutomaton()
{
	std::cout.flush();
    debugToFile(stringbuilder() << "dfaPrintVerbose(M[" << this->autoTraceID << "]);");
    dfaPrintVerbose(this->dfa);
    debugToFile(stringbuilder() << "flush_output();");
    std::cout.flush();
}

void StrangerAutomaton::printAutomatonVitals()
{
	std::cout.flush();
    debugToFile(stringbuilder() << "dfaPrintVitals(M[" << this->autoTraceID << "]);");
    dfaPrintVitals(this->dfa);
    debugToFile(stringbuilder() << "flush_output();");
    std::cout.flush();
}

/**
 * specifically done to be passed to dfaPrintGraphviz
 */
unsigned *StrangerAutomaton::getUnsignedIndices(int length){
	unsigned i;
	unsigned* indices;
	indices = new unsigned[length + 1];
	for (i = 0; i <= (unsigned)length; i++)
		indices[i] = i;
	return indices;
    
}


/**
 * Prints the current automaton to the out stream in a dot format (see Graphviz).
 * Unfortunately until now there is no interface to provide a file to the C library
 * to print the output into yet :-(
 */
void StrangerAutomaton::toDot() const
{
	unsigned* indices_main_unsigned = getUnsignedIndices(num_ascii_track);
	std::cout.flush();
    debugToFile(stringbuilder() << "dfaPrintGraphviz(M[" << this->autoTraceID << "], NUM_ASCII_TRACKS, indices_main);//dfaPrintGraphviz( this->ID)");
    dfaPrintGraphviz(this->dfa, num_ascii_track, indices_main_unsigned);
    delete[] indices_main_unsigned;
    debugToFile(stringbuilder() << "flush_output();");
    std::cout.flush();
}

void StrangerAutomaton::toDotFile(std::string file_name) const {
	unsigned* indices_main_unsigned = getUnsignedIndices(num_ascii_track);
    debugToFile(stringbuilder() << "dfaPrintGraphvizFile(M[" << this->autoTraceID << "], NUM_ASCII_TRACKS, indices_main);//dfaPrintGraphviz( this->ID)");
    dfaPrintGraphvizFile(this->dfa, file_name.c_str(), num_ascii_track, indices_main_unsigned);
    delete[] indices_main_unsigned;
}

void StrangerAutomaton::toDotBDDFile(std::string file_name) const {

    debugToFile(stringbuilder() << "dfaPrintBDD(M[" << this->autoTraceID << "], NUM_ASCII_TRACKS);");
    dfaPrintBDD(this->dfa, file_name.c_str(), num_ascii_track);

}


/**
 * Prints the current automaton to the out stream in a dot format (see Graphviz).
 * Unfortunately until now there is no interface to provide a file to the C library
 * to print the output into yet :-(
 */
void StrangerAutomaton::toDotAscii(int printSink) const
{
	unsigned* indices_main_unsigned = getUnsignedIndices(num_ascii_track);
	std::cout.flush();
    debugToFile(stringbuilder() << "dfaPrintGraphviz(M[" << this->autoTraceID << "], NUM_ASCII_TRACKS, indices_main);//dfaPrintGraphviz( this->ID)");
    //if the automaton is the empty language then we must enable printing the sink
    // if there is one state and it is a rejecting state
    if (this->dfa->ns == 1 && this->dfa->f[0] == -1)
        printSink = 2;
    dfaPrintGraphvizAsciiRange(this->dfa, num_ascii_track, indices_main, printSink);
    delete[] indices_main_unsigned;
    debugToFile(stringbuilder() << "flush_output();");
    std::cout.flush();
}

void StrangerAutomaton::toDotFileAscii(std::string file_name, int printSink) const {
    unsigned* indices_main_unsigned = getUnsignedIndices(num_ascii_track);
    debugToFile(stringbuilder() << "dfaPrintGraphvizAsciiRangeFile(M[" << this->autoTraceID << "], NUM_ASCII_TRACKS, indices_main);//dfaPrintGraphviz( this->ID)");
    //if the automaton is the empty language then we must enable printing the sink
    // if there is one state and it is a rejecting state
    if (this->dfa) {
        if (this->dfa->ns == 1 && this->dfa->f[0] == -1)
            printSink = 2;
        dfaPrintGraphvizAsciiRangeFile(this->dfa, file_name.c_str(), num_ascii_track, indices_main, printSink);
    } else {
        std::cout << "StrangerAutomaton::toDotFileAscii: this->dfa is null" << std::endl;
    }
    delete[] indices_main_unsigned;
}

void StrangerAutomaton::exportToFile(const std::string& file_name) const
{
    if (this->dfa) {
        dfaExportBddTable(this->dfa, file_name.c_str(), num_ascii_track);
    }
}

StrangerAutomaton* StrangerAutomaton::importFromFile(const std::string& file_name)
{
    return new StrangerAutomaton(dfaImportBddTable(file_name.c_str(), num_ascii_track));
}

int StrangerAutomaton::debugLevel = 0;

void StrangerAutomaton::debug(std::string s)
{
    
    if(debugLevel >= 1)
       std::cout << s << endl;
    
}

void StrangerAutomaton::debugAutomaton()
{
//    if(debugLevel >= 3) {
//        this->toDotAscii(0);
//    }
}


int StrangerAutomaton::traceID = 0;


int StrangerAutomaton::baseTraceID = 0;

int StrangerAutomaton::tempTraceID = 0;

int StrangerAutomaton::baseTempTraceID = 0;



void StrangerAutomaton::resetTraceID()
{
    traceID = baseTraceID;
    tempTraceID = baseTempTraceID;
}

void StrangerAutomaton::openCtraceFile(std::string name)
{
    //
    //    try {
    //        resetTraceID();
    //        fstream_ = (new ::java::io::FileWriter(name));
    //        out_ = (new ::java::io::BufferedWriter(fstream_));
    //        npc(out_)->write("int* indices_main = (int *) allocateAscIIIndexWithExtraBit(NUM_ASCII_TRACKS);\nint i;\nDFA* M[1000];\nfor (i = 0; i < 1000; i++)\n\t M[i] = 0;\n");
    //    } catch (::java::lang::Exception* e) {
    //        throw (StrangerAutomatonException("exec_trace.c file can not be opened."));
    //    }
}

void StrangerAutomaton::appendCtraceFile(std::string name)
{
    //
    //    try {
    //        resetTraceID();
    //        fstream_ = (new ::java::io::FileWriter(name, true));
    //        out_ = (new ::java::io::BufferedWriter(fstream_));
    //    } catch (::java::lang::Exception* e) {
    //        throw (StrangerAutomatonException(::java::lang::StringBuilder().append("exec_trace.c file can not be opened.")->append(npc(e)->getMessage())->toString()));
    //    }
}

void StrangerAutomaton::closeCtraceFile()
{
    //
    //    if(fstream_ != NULL)
    //        try {
    //            npc(out_)->write("for (i = 0; i < 1000; i++)\n\tif (M[i] != 0){\n\t\tdfaFree(M[i]);\n\t\tM[i] = 0;\n}\nprintf(\"Finished execution.\");\n");
    //            npc(out_)->flush();
    //            npc(fstream_)->close();
    //        } catch (::java::io::IOException* e) {
    //            throw (StrangerAutomatonException("Can not close file exec_trace.c"));
    //        }
    
}

void StrangerAutomaton::debugToFile(std::string str)
{

    debug(str);
    //
    //    if(fstream_ == NULL) {
    //        std::string property = "java.io.tmpdir";
    //        std::string tempDir = ::java::lang::System::getProperty(property);
    //        openCtraceFile(::java::lang::StringBuilder().append(tempDir)->append("/stranger_automaton_exec_trace.c")->toString());
    //    }
    //    try {
    //        npc(out_)->write(::java::lang::StringBuilder().append(str)->append("\n")->toString());
    //        npc(out_)->flush();
    //    } catch (::java::io::IOException* e) {
    //        throw (StrangerAutomatonException("Can not write to exec_trace.c file"));
    //    }
}

StrangerAutomaton* StrangerAutomaton::difference(const StrangerAutomaton* auto_, int id) const {
	StrangerAutomaton* complementAuto = auto_->complement(id);
	StrangerAutomaton* differenceAuto = this->intersect(complementAuto, id);
	delete complementAuto;
	return differenceAuto;
}



std::string StrangerAutomaton::escapeSpecialChars(std::string s)
{
    //	std::string b;
    //    bool skip = false;
    //    for (int i = int32_t(0); i < npc(s)->length(); i++) {
    //        char c = npc(s)->charAt(i);
    //        if(c == u'\u000a') {
    //            if(!skip)
    //                npc(b)->append("\\n");
    //            else
    //                skip = false;
    //        } else if(c == u'\u000d') {
    //            npc(b)->append("\\n");
    //            skip = true;
    //        } else if(c == u'"')
    //            npc(b)->append("\\\"");
    //        else if(c == u'\\')
    //            npc(b)->append("\\\\");
    //        else
    //            npc(b)->append(c);
    //    }
    //    return npc(b)->toString();
	return s;
}
