/*
 * Stranger
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
 * Authors: Fang Yu
 */
 
/************************************************************

Backward Analysis

1. dfa_pre_concat(DFA* ML, DFA* MR, int pos, int var, int* indices)
2. dfa_pre_concat_const(DFA* ML, char* str, int pos, int var, int* indices)
3. dfa_pre_replace(DFA* M1, DFA* M2, char* str, int var, int* indices)

*************************************************************/

//for external.c
#include "mona/bdd_external.h"
#include "mona/mem.h"
//for bddDump
#include "mona/bdd_dump.h"
#include "stranger.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//for arithmetic automata
#include <math.h>
#include "stranger_lib_internal.h"


//pos == 1, return the preimage of X for XL := X. XR
//pos == 2. return the preimage of X for XL := XR. X
 DFA* dfa_pre_concat(DFA* ML, DFA* MR, int pos, int var, int* indices){
  if (!ML || !MR) {
    return NULL;
  }
  assert(pos==1 || pos ==2); //Computing pre-image for concatenation of two arguments
  DFA* Mtrans;
  DFA* M1;
  DFA* M2;
  DFA* result;
  DFA* Ma = dfaAllStringASCIIExceptReserveWords(var, indices);

  if(check_emptiness(MR, var, indices)) return dfaCopy(ML);

  if(pos==1){
    M1 = mdfaOneToManyTrackNoLambda(ML, 3, 0, var, indices);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(M1);
    M2 = mdfaGPrefixM(MR, 0, 1, 2, 3, var, indices);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(M2);
    Mtrans = dfa_intersect(M1,M2);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(Mtrans);
    dfaFree(M1);
    dfaFree(M2);
    result = dfaGetTrack(Mtrans, pos, 3, var, indices);
  }else{
    // Mtrans = mdfaMEqualLRR(ML, MR, Ma, 0, 1, 2, 3, var, indices);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(ML);
    M1 = mdfaOneToManyTrackNoLambda(ML, 3, 0, var, indices);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(M1);

    M2 = mdfaGSuffixM(MR, 0, 1, 2, 3, var, indices);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(M2);
    Mtrans = dfa_intersect(M1,M2);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(Mtrans);
    dfaFree(M1);
    dfaFree(M2);
    result = dfaGetTrackNoPreLambda(Mtrans, pos, 3, var, indices);
  }


  dfaFree(Mtrans);
  dfaFree(Ma);
	if( DEBUG_SIZE_INFO )
		printf("\t peak : pre_concat : states %d : bddnodes %u \n", result->ns, bdd_size(result->bddm) );
  return dfaMinimize(result);
 }



//pos == 1, return the preimage of X for XL := X. XR
//pos == 2. return the preimage of X for XL := XR. X
DFA* dfa_pre_concat_const(DFA* ML, const char* str, int pos, int var, int* indices){
  if (!ML) {
    return NULL;
  }
  assert(1==pos || pos==2); //Computing pre-image for concatenation of two arguments
  DFA* Mtrans;
  DFA* result;
  DFA* suf;
  DFA* pre;
  DFA* Ma = dfaAllStringASCIIExceptReserveWords(var, indices);
  int n = (int)strlen(str);
  if(n==0) return dfaCopy(ML);
  if(pos==1){ //Precise Construction
	pre = dfa_intersect(ML, dfa_concat_extrabit(Ma, dfa_construct_string(str, var, indices), var, indices));
    Mtrans = mdfaMEqualLRc(pre, Ma, str, 0, 1, 2, var, indices);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(Mtrans);
    result = dfaGetTrack(Mtrans, pos, 2, var, indices);
    if(_FANG_DFA_DEBUG) dfaPrintVerbose(result);
    dfaFree(pre);
	 //return dfa_pre_concat(ML, dfa_construct_string(str, var, indices), pos, var, indices);
  }else if(pos==2){ //Approximation: Using LRR construction
    suf = dfa_concat_extrabit(dfa_construct_string(str, var, indices), Ma, var, indices);
    Mtrans = dfa_intersect(ML, suf);
    result = dfa_Suffix(Mtrans, n, n, var, indices);
    dfaFree(suf);
  }else{
    printf("\n\nError on dfa_pre_concat_const: pos ==1 or pos ==2!\n\n");
    exit(0);
  }
  dfaFree(Ma);
  dfaFree(Mtrans);
	if( DEBUG_SIZE_INFO )
		printf("\t peak : pre_const_concat : states %d : bddnodes %u \n", result->ns, bdd_size(result->bddm) );
  return dfaMinimize(result);
 }

DFA* dfa_pre_replace(DFA* M1, DFA* M2, DFA* M3, int var, int* indices){
  return dfa_general_replace_extrabit(M1, M3, dfa_union(M2, M3), var, indices);
}

DFA* dfa_pre_replace_str(DFA* M1, DFA* M2, const char *str, int var, int* indices){
  if (!M1 || !M2) {
    return NULL;
  }
  DFA *result=NULL;
  DFA *M3 = dfa_construct_string(str, var, indices);

 // Check if we are replacing the search auto with the replace string
  char* M2_singleton = isSingleton(M2, var, indices);
  if (M2_singleton != NULL) {
    if (strcmp(str, M2_singleton) == 0) {
      free(M2_singleton);
      return dfaCopy(M1);
    }
    free(M2_singleton);
  }

  if((str ==NULL)||strlen(str)==0){
      if (checkOnlyEmptyString(M2, var, indices)) {
          // If we are replacing an empty string with empty string
          // inserting the empty string everywhere will change nothing
          result = dfaCopy(M1);
      } else {
          result = dfa_insert_everywhere(M1, M2, var, indices, 0);
      }
  } else {
    DFA* U = dfa_union(M2, M3);
    result = dfa_general_replace_extrabit(M1, M3, U, var, indices);
    dfaFree(U);
  }
  dfaFree(M3);
  return result;
}

DFA* dfa_pre_replace_once_str(DFA* M1, DFA* M2, const char *str, int var, int* indices){
  if (!M1 || !M2) {
    return NULL;
  }
  DFA *result=NULL;
  DFA *M3 = dfa_construct_string(str, var, indices);
  // Union here as the replaced string could have been replaced or not
  // Check if this assumption is OK for replace_once
  DFA* U = dfa_union(M2, M3);
  // Check empty replace string

 // Check if we are replacing the search auto with the replace string
  char* M2_singleton = isSingleton(M2, var, indices);
  if (M2_singleton != NULL) {
    if (strcmp(str, M2_singleton) == 0) {
      free(M2_singleton);
      return dfaCopy(M1);
    }
  }
  // Deletion case
  if((str == NULL) || strlen(str) == 0) {
      // Check empty intersection
      if (checkOnlyEmptyString(U, var, indices)) {
          // If we are replacing an empty string with empty string
          // inserting the empty string everywhere will change nothing
          result = dfaCopy(M1);
      } else {
          // Check the complexity of the target string
          // This is an arbitrary limit
          if ((M1->ns < 10000) && ((M1->ns * M2->ns) < 100000)) {
              // In the replace_once case, just add the replace string to the start
              result = dfa_insert_everywhere(M1, M2, var, indices, 1);
              // Approximate, just add the string to the start
              // This is much faster
          } else {
              printf("%s: Input automaton too complex (M1_ns = %d, M2_ns = %d), using single insert approximation\n",
                     __func__, M1->ns, M2->ns);
              DFA* sMs = dfa_star_M_star(M2, var, indices);
              DFA* I = dfa_intersect(M1, sMs);
              if (!check_emptiness(I, var, indices)) {
                  result = dfa_concat(M2, M1, var, indices);
              } else {
                  // No intersection between target and search strings
                  result = dfaCopy(M1);
              }
              dfaFree(I);
              dfaFree(sMs);
          }
      }
      // Replace
  } else {
      if (M2_singleton != NULL) {
          result = dfa_replace_once_extrabit(M1, M3, M2_singleton, var, indices);
      } else {
          // TODO: this is probably still not correct
          result = dfa_general_replace_once_extrabit(M1, M3, M2, var, indices);
      }
  }
  dfaFree(U);
  dfaFree(M3);
  if (M2_singleton != NULL) {
    free(M2_singleton);
  }
  return result;
}

