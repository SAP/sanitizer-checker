/*
 * StrangerAutomaton.hpp
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

#ifndef STRANGERAUTOMATON_HPP_
#define STRANGERAUTOMATON_HPP_

#include "PerfInfo.hpp"
#include "StringBuilder.hpp"
#include "exceptions/StrangerAutomatonException.hpp"
#include "RegExp.hpp"
#define export _export_
#include "stranger/stranger_lib_internal.h"
#include "stranger/stranger.h"
#undef export

#include <stdexcept>
#include <vector>

class RegExp;

class StrangerAutomaton
{
public:
    StrangerAutomaton(const StrangerAutomaton* other);
    StrangerAutomaton(DFA* dfa);
    virtual ~StrangerAutomaton();
    StrangerAutomaton* clone(int id) const;
    StrangerAutomaton* clone() const;
    int getID() const;
    void setID(int id);
    DFA* getDfa();
    static StrangerAutomaton* makeBottom(int id);
    static StrangerAutomaton* makeBottom();
    static StrangerAutomaton* makeTop(int id);
    static StrangerAutomaton* makeTop();
    static StrangerAutomaton* makeString(std::string s, int id);
    static StrangerAutomaton* makeString(std::string s);
    static StrangerAutomaton* makeChar(char c, int id);
    static StrangerAutomaton* makeChar(char c);
    static StrangerAutomaton* makeCharRange(char from, char to, int id);
    static StrangerAutomaton* makeCharRange(char from, char to);
    static StrangerAutomaton* makeAnyString(int id);
    static StrangerAutomaton* makeAnyString();
    static StrangerAutomaton* makeAnyStringL1ToL2(int l1, int l2, int id);
    static StrangerAutomaton* makeAnyStringL1ToL2(int l1, int l2);
    static StrangerAutomaton* makeEmptyString(int id);
    static StrangerAutomaton* makeEmptyString();
    static StrangerAutomaton* makeDot(int id);
    static StrangerAutomaton* makeDot();
    static StrangerAutomaton* makePhi(int id);
    static StrangerAutomaton* makePhi();
    std::string generateSatisfyingExample() const;
    StrangerAutomaton* generateSatisfyingSingleton() const;
    StrangerAutomaton* optional(int id);
    StrangerAutomaton* optional();
    StrangerAutomaton* kleensStar(int id);
    StrangerAutomaton* kleensStar();
    static StrangerAutomaton* kleensStar(StrangerAutomaton* auto_, int id);
    static StrangerAutomaton* kleensStar(StrangerAutomaton* auto_);
    StrangerAutomaton* closure(int id);
    StrangerAutomaton* closure();
    static StrangerAutomaton* closure(StrangerAutomaton* auto_, int id);
    static StrangerAutomaton* closure(StrangerAutomaton* auto_);
    StrangerAutomaton* repeat(unsigned min, int id);
    StrangerAutomaton* repeat(unsigned min);
    StrangerAutomaton* repeat(unsigned min, unsigned max, int id);
    StrangerAutomaton* repeat1(unsigned min, unsigned max);
    StrangerAutomaton* complement(int id) const;
    StrangerAutomaton* complement() const;
    StrangerAutomaton* difference(const StrangerAutomaton* auto_, int id) const;
    StrangerAutomaton* union_(const StrangerAutomaton* auto_, int id) const;
    StrangerAutomaton* union_(const StrangerAutomaton* auto_) const;
    StrangerAutomaton* unionWithEmptyString(int id);
    StrangerAutomaton* unionWithEmptyString();
    StrangerAutomaton* intersect(const StrangerAutomaton* auto_, int id) const;
    StrangerAutomaton* intersect(const StrangerAutomaton* auto_) const;
    StrangerAutomaton* productImpl(StrangerAutomaton* otherAuto, int id);
    StrangerAutomaton* preciseWiden(const StrangerAutomaton* auto_, int id) const;
    StrangerAutomaton* preciseWiden(const StrangerAutomaton* auto_) const;
    StrangerAutomaton* coarseWiden(const StrangerAutomaton* auto_, int id) const;
    StrangerAutomaton* coarseWiden(const StrangerAutomaton* auto_) const;
    StrangerAutomaton* concatenate(const StrangerAutomaton* auto_, int id) const;
    StrangerAutomaton* concatenate(const StrangerAutomaton* auto_) const;
    StrangerAutomaton* leftPreConcat(const StrangerAutomaton* rightSiblingAuto, int id) const;
    StrangerAutomaton* leftPreConcat(const StrangerAutomaton* rightSiblingAuto) const;
    StrangerAutomaton* leftPreConcatConst(std::string rightSiblingString, int id) const;
    StrangerAutomaton* leftPreConcatConst(std::string rightSiblingString) const;
    StrangerAutomaton* rightPreConcat(const StrangerAutomaton* leftSiblingAuto, int id) const;
    StrangerAutomaton* rightPreConcat(const StrangerAutomaton* leftSiblingAuto) const;
    StrangerAutomaton* rightPreConcatConst(std::string leftSiblingString, int id) const;
    StrangerAutomaton* rightPreConcatConst(std::string leftSiblingString);
    static StrangerAutomaton* regExToAuto(std::string phpRegexOrig, bool preg, int id);
    static StrangerAutomaton* regExToAuto(std::string phpRegexOrig);
    static StrangerAutomaton* reg_replace(const StrangerAutomaton* patternAuto, const std::string& replaceStr, const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* reg_replace(const StrangerAutomaton* patternAuto, const std::string& replaceStr, const StrangerAutomaton* subjectAuto);
    static StrangerAutomaton* general_replace(const StrangerAutomaton* patternAuto, const StrangerAutomaton* replaceAuto, const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* str_replace(const StrangerAutomaton* searchAuto, const std::string& replaceStr, const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* str_replace(const StrangerAutomaton* searchAuto, const std::string& replaceStr, const StrangerAutomaton* subjectAuto);
    static StrangerAutomaton* str_replace_once(const StrangerAutomaton* str, const StrangerAutomaton* replaceAuto, const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* str_replace_once(const StrangerAutomaton* str, const StrangerAutomaton* replaceAuto, const StrangerAutomaton* subjectAuto);
    StrangerAutomaton* preReplace(const StrangerAutomaton* searchAuto, std::string replaceString, int id) const;
    StrangerAutomaton* preReplace(const StrangerAutomaton* searchAuto, std::string replaceString) const;
    StrangerAutomaton* preReplaceOnce(const StrangerAutomaton* searchAuto, std::string replaceString, int id) const;
    StrangerAutomaton* preReplaceOnce(const StrangerAutomaton* searchAuto, std::string replaceString) const;
    StrangerAutomaton* getUnaryAutomaton(int id) const;
    StrangerAutomaton* getUnaryAutomaton() const { return getUnaryAutomaton(traceID); };
    StrangerAutomaton* restrictLengthByOtherAutomaton(const StrangerAutomaton* otherAuto, int id) const;
    StrangerAutomaton* restrictLengthByOtherAutomaton(const StrangerAutomaton* otherAuto) const
    {
        return restrictLengthByOtherAutomaton(otherAuto, traceID);
    };
    StrangerAutomaton* restrictLengthByOtherAutomatonFinite(const StrangerAutomaton *otherAuto, int id) const;
    StrangerAutomaton* restrictLengthByOtherAutomatonFinite(const StrangerAutomaton *otherAuto) const
    {
        return restrictLengthByOtherAutomatonFinite(otherAuto, traceID);
    };
    StrangerAutomaton* restrictLengthByUnaryAutomaton(const StrangerAutomaton* uL, int id) const;
    StrangerAutomaton* restrictLengthByUnaryAutomaton(const StrangerAutomaton* uL) const {
        return restrictLengthByUnaryAutomaton(uL, traceID);
    };
    bool checkIntersection(const StrangerAutomaton* auto_, int id1, int id2);
    bool checkIntersection(const StrangerAutomaton* auto_);
    bool checkInclusion(const StrangerAutomaton* auto_, int id1, int id2) const;
    bool checkInclusion(const StrangerAutomaton* auto_) const;
    bool checkEquivalence(const StrangerAutomaton* auto_, int id1, int id2) const;
    bool checkEquivalence(const StrangerAutomaton* auto_) const;
    bool isLengthFinite() const;
    unsigned getMaxLength() const;
    unsigned getMinLength() const;
    bool equals(const StrangerAutomaton* other) const;
    bool checkEmptiness() const;
    bool isEmpty() const;
    bool isNull() const;
    bool checkEmptyString() const;
    bool isSingleton() const;    
    std::string getStr() const;
    bool isBottom() const;
    bool isTop() const;
    StrangerAutomaton* toUpperCase(int id) const;
    StrangerAutomaton* toUpperCase() const { return toUpperCase(traceID);};
    StrangerAutomaton* toLowerCase(int id) const;
    StrangerAutomaton* toLowerCase() const { return toLowerCase(traceID);};
    StrangerAutomaton* preToUpperCase(int id) const;
    StrangerAutomaton* preToUpperCase() const { return preToUpperCase(traceID);};
    StrangerAutomaton* preToLowerCase(int id) const;
    StrangerAutomaton* preToLowerCase() const { return preToLowerCase(traceID);};
    StrangerAutomaton* trimSpaces(int id) const;
    StrangerAutomaton* trimSpacesLeft(int id) const;
    StrangerAutomaton* trimSpacesRight(int id) const;
    StrangerAutomaton* trim(char c, int id) const;
    StrangerAutomaton* trimLeft(char c, int id) const;
    StrangerAutomaton* trimRight(char c, int id) const;
    StrangerAutomaton* trim(char chars[], int id) const;
    StrangerAutomaton* trimSpaces() const { return trimSpaces(traceID); };
    StrangerAutomaton* trimSpacesLeft() const { return trimSpacesLeft(traceID); };
    StrangerAutomaton* trimSpacesRight() const { return trimSpacesRight(traceID); };
    StrangerAutomaton* trim(char c) const { return trim(c, traceID); };
    StrangerAutomaton* trimLeft(char c) const { return trimLeft(c, traceID); };
    StrangerAutomaton* trimRight(char c) const { return trimRight(c, traceID); };
    StrangerAutomaton* trim(char chars[]) const { return trim(chars, traceID); };
//    StrangerAutomaton* trimLeft(char chars[]);
//    StrangerAutomaton* trimRight(char chars[]);
    StrangerAutomaton* preTrimSpaces(int id) const;
    StrangerAutomaton* preTrimSpaces() const { return preTrimSpaces(traceID);} ;
    StrangerAutomaton* preTrimSpacesLeft(int id) const;
    StrangerAutomaton* preTrimSpacesRigth(int id) const;
    // Modelling the JavaScript substr function
    StrangerAutomaton* substr(int start, int length, int id) const;
    StrangerAutomaton* substr(int start, int id) const;
    StrangerAutomaton* pre_substr(int start, int length, int id) const;
    StrangerAutomaton* pre_substr(int start, int id) const;

    static StrangerAutomaton* addslashes(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* addslashes(const StrangerAutomaton* subjectAuto){return addslashes(subjectAuto, traceID);};
    static StrangerAutomaton* pre_addslashes(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_addslashes(const StrangerAutomaton* subjectAuto){return pre_addslashes(subjectAuto, traceID);};
    static StrangerAutomaton* htmlSpecialChars(const StrangerAutomaton* subjectAuto, std::string flag, int id);
    static StrangerAutomaton* htmlSpecialChars(const StrangerAutomaton* subjectAuto, std::string flag){return htmlSpecialChars(subjectAuto,flag, traceID);};
    static StrangerAutomaton* preHtmlSpecialChars(const StrangerAutomaton* subjectAuto, std::string flag, int id);
    static StrangerAutomaton* preHtmlSpecialChars(const StrangerAutomaton* subjectAuto, std::string flag){return preHtmlSpecialChars(subjectAuto, flag, traceID);};
    static StrangerAutomaton* stripslashes(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* stripslashes(const StrangerAutomaton* subjectAuto){return stripslashes(subjectAuto, traceID);};
    static StrangerAutomaton* pre_stripslashes(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_stripslashes(const StrangerAutomaton* subjectAuto){return pre_stripslashes(subjectAuto, traceID);};
    static StrangerAutomaton* mysql_escape_string(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_mysql_escape_string(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* mysql_real_escape_string(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_mysql_real_escape_string(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* nl2br(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_nl2br(const StrangerAutomaton* subjectAuto, int id);
//    std::set<char> mincut();
    static StrangerAutomaton* encodeAttrString(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* encodeAttrString(const StrangerAutomaton* subjectAuto){return encodeAttrString(subjectAuto, traceID);};
    static StrangerAutomaton* pre_encodeAttrString(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_encodeAttrString(const StrangerAutomaton* subjectAuto){return pre_encodeAttrString(subjectAuto, traceID);};

    static StrangerAutomaton* encodeTextFragment(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* encodeTextFragment(const StrangerAutomaton* subjectAuto){return encodeTextFragment(subjectAuto, traceID);};
    static StrangerAutomaton* pre_encodeTextFragment(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_encodeTextFragment(const StrangerAutomaton* subjectAuto){return pre_encodeTextFragment(subjectAuto, traceID);};

    static StrangerAutomaton* escapeHtmlTags(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* escapeHtmlTags(const StrangerAutomaton* subjectAuto){return escapeHtmlTags(subjectAuto, traceID);};
    static StrangerAutomaton* pre_escapeHtmlTags(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* pre_escapeHtmlTags(const StrangerAutomaton* subjectAuto){return pre_escapeHtmlTags(subjectAuto, traceID);};

    static StrangerAutomaton* encodeURIComponent(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* encodeURIComponent(const StrangerAutomaton* subjectAuto){return encodeURIComponent(subjectAuto, traceID);};
    static StrangerAutomaton* decodeURIComponent(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* decodeURIComponent(const StrangerAutomaton* subjectAuto){return decodeURIComponent(subjectAuto, traceID);};

    static StrangerAutomaton* encodeURI(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* encodeURI(const StrangerAutomaton* subjectAuto){return encodeURI(subjectAuto, traceID);};
    static StrangerAutomaton* decodeURI(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* decodeURI(const StrangerAutomaton* subjectAuto){return decodeURI(subjectAuto, traceID);};

    static StrangerAutomaton* escape(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* escape(const StrangerAutomaton* subjectAuto){return escape(subjectAuto, traceID);};
    static StrangerAutomaton* unescape(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* unescape(const StrangerAutomaton* subjectAuto){return unescape(subjectAuto, traceID);};

    static StrangerAutomaton* jsonStringify(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* jsonStringify(const StrangerAutomaton* subjectAuto){return jsonStringify(subjectAuto, traceID);};
    static StrangerAutomaton* jsonParse(const StrangerAutomaton* subjectAuto, int id);
    static StrangerAutomaton* jsonParse(const StrangerAutomaton* subjectAuto){return jsonParse(subjectAuto, traceID);};

    void printAutomaton();
    void printAutomatonVitals();
    void toDot() const;
    void toDotAscii(int printSink) const;
    void toDotFile(std::string file_name) const;
    void toDotFileAscii(std::string file_name, int printSink) const;
    void toDotBDDFile(std::string file_name) const;
    void exportToFile(const std::string& file_name) const;
    static StrangerAutomaton* importFromFile(const std::string& file_name);
    static void openCtraceFile(std::string name);
    static void appendCtraceFile(std::string name);
    static void closeCtraceFile();
    void debugAutomaton();
    static void debugToFile(std::string str);
    static void debug(std::string s);
    static int getVar(){ return num_ascii_track;};
    static unsigned *getUnsignedIndices(int length);
    int get_num_of_states() const {
		return this->dfa->ns;
    }

    unsigned get_num_of_bdd_nodes() const{
        return bdd_size(this->dfa->bddm);
    }

    static PerfInfo* perfInfo;

    StrangerAutomaton* restrict(const StrangerAutomaton* otherAuto, int id){
        StrangerAutomaton* retMe = this->intersect(otherAuto);
        retMe->ID = id;
        return retMe;
    };

    StrangerAutomaton* restrict(const StrangerAutomaton* otherAuto){
        return this->restrict(otherAuto, traceID);
    };

    StrangerAutomaton* restrict(std::string regExp, int id){
        StrangerAutomaton* regExpAuto = regExToAuto(regExp);
        StrangerAutomaton* retMe = this->intersect(regExpAuto);
        delete regExpAuto;
        retMe->ID = id;
        return retMe;
    };

    StrangerAutomaton* restrict(std::string regExp){
        return this->restrict(regExp, traceID);
    }

    StrangerAutomaton* preRestrict(std::string regExp, int id){
        StrangerAutomaton* regExpAuto = regExToAuto(regExp);
        StrangerAutomaton* regExpAutoComplement = regExpAuto->complement();
        delete regExpAuto;
        StrangerAutomaton* retMe = this->union_(regExpAutoComplement);
        delete regExpAutoComplement;
        retMe->ID = id;
        return retMe;
    };

    StrangerAutomaton* preRestrict(std::string regExp){
        return this->preRestrict(regExp, traceID);
    };

    StrangerAutomaton* preRestrict(const StrangerAutomaton* otherAuto, int id){
        StrangerAutomaton* otherAutoComplement = otherAuto->complement();
        StrangerAutomaton* retMe = this->union_(otherAutoComplement);
        delete otherAutoComplement;
        retMe->ID = id;
        return retMe;
    };

    StrangerAutomaton* preRestrict(const StrangerAutomaton* otherAuto){
        return this->preRestrict(otherAuto, traceID);
    };
    DFA* dfa;
private:

    int ID;
    int autoTraceID;
    bool top;
    bool bottom;
    static int num_ascii_track;
    static int* indices_main;
    static unsigned* u_indices_main;
    static int traceID;
    static int baseTraceID;
    static int tempTraceID;
    static int baseTempTraceID;
    static int debugLevel;
    static bool coarseWidening;
    static char slash;
	StrangerAutomaton();
	void init();
    static bool& initialized();
    static void resetTraceID();
    static std::string escapeSpecialChars(std::string s);
    StrangerAutomaton* substr_first_part(int start, int id) const;
};


#endif /* STRANGERAUTOMATON_HPP_ */
