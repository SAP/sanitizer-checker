/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * Stranger
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
 * Authors: Fang Yu, Muath Alkhalaf
 */


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

//for internal
#include "stranger_lib_internal.h"


/***************************************************

Replace function

***************************************************/


void print_value(paths pp, int var, int *indices, int len) {
    int j;
    trace_descr tp;
    for (j = 0; j < len; j++) {
        //the following for loop can be avoided if the indices are in order
        for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);
        if (tp) {
            if (tp->value) {
                printf("1");
            } else {
                printf("0");
            }
        } else {
            printf("X");
        }
    }
    for (j = var; j < len; j++) {
        printf("0");
    }
    printf("\n");
}

void print_exep_value(char *exep, int len) {
    int j;
    for (j = 0; j < len; j++) {
        printf("%c", exep[j]);
    }
    printf("\n");
}

void print_transitions(int i, int* to_states, int k, char* exp, int len) {
    for (int j = 0; j < k; j++) {
        printf("state: %d -> %d value: ", i, to_states[j]);
        print_exep_value(exp + j*(len+1), len);
    }
}

int is_sharp1(paths pp, int var, int *indices) {
    char *sharp1;
   sharp1 = getSharp1WithExtraBit(var);
    int j;
    trace_descr tp;
    int yes = 1;

    for (j = 0; j < var + 1; j++) {
        for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);
        if (tp) {
            if (tp->value) {
                if (sharp1[j] != '1') {
                    yes = 0;
                    break;
                }
            } else {
                if (sharp1[j] != '0') {
                    yes = 0;
                    break;
                }
            }
        } else {
            if (sharp1[j] != 'X') {
                yes = 0;
                break;
            }
        }
    }

    free(sharp1);
    return yes;
}

int state_already_included(char* exeps, int k, int len, int var) {
    int l, j;
    // Check whether this transition is already included
    int match = 0;
    // k has already been incremented, so use k-1 as the index
    int m = k - 1;
    // Loop over all the transitions
    //printf("Comparing: \n");
    //print_exep_value(&exeps[m*(len+1)], len);
    for (l = 0; l < m; l++) {
        int matchFound = 1;
        //printf("Transition %d\n", l);
        //print_exep_value(&exeps[l*(len+1)], len);
        for (j = 0; j < len; j++) {
            //printf("Checking transition value %d of %d compare with %d values: %c, %c\n",
            //      l, m, j, exeps[m*(len+1)+j], exeps[l*(len+1)+j]);
            if ((exeps[m*(len+1)+j] == 'X') ||
                (exeps[l*(len+1)+j] == 'X') ||
                (exeps[m*(len+1)+j] == exeps[l*(len+1)+j])) {
                // State bit matches
                //  printf("Matched bit\n");
            } else {
                //printf("UNMatched bit\n");
                matchFound = 0;
                break;
            }
        }
        // Was this state transition a match?
        if (matchFound == 1) {
            //printf("Found a match states\n");
            match = 1;
            break;
        }
    }
    //printf("match: %u\n", match);
    return match;
}

static DFA* project_away_sharps(DFA *M, int aux, int len) {
    DFA *tmpM1;
    DFA *tmpM2;
    tmpM2 = dfaMinimize(M);
    for(unsigned int i = len - aux; i < len; i++){
        tmpM1 = dfaProject(tmpM2, i);
        dfaFree(tmpM2);
        if (!tmpM1) {
            return NULL;
        }
        tmpM2 = dfaMinimize(tmpM1);
        dfaFree(tmpM1);
    }
    return tmpM2;
}

//Replace any c \in {sharp1} \vee bar \vee {sharp2} with \epsilon (Assume 00000000000)
DFA *dfa_replace_delete(DFA *M, int var, int *oldindices, int remove_loops)
{
//  dfaPrintGraphvizAsciiRange(M, var, oldindices, 1);
  DFA *result = NULL;
  DFA *tmpM2 = NULL;
  DFA *tmpM1 = NULL;
  int aux=0;
  struct int_list_type **pairs=NULL;
  int maxCount;

  paths state_paths, pp;
  trace_descr tp;
  int i, j, o, z, k, l;
  char *exeps;
  int *to_states;
  long max_exeps;
  char *statuces;
  int len=var;
  int sink;
  int *indices=oldindices;
  char *auxbit=NULL;
  struct int_type *tmp=NULL;

  //dfaPrintGraphvizAsciiRange(M, var, indices, 1);  
  //printf("Start get match exclude\n");
  pairs = get_match_exclude_self(M, var, indices); //for deletion, exclude self state from the closure
  //printf("End get match exclude\n");
  maxCount = get_maxcount(pairs, M->ns);
  if(maxCount>0){ //Need auxiliary bits when there exist some outgoing edges
    //printf("Deletion [insert auxiliary bits]!\n");
    aux = get_hsig(maxCount);
    len = var+aux;
    auxbit = (char *) calloc(aux, sizeof(char));
    indices = allocateArbitraryIndex(len);
  }

  max_exeps=1<<len; //maybe exponential
  sink=find_sink(M);
  assert(sink >-1);

  //pairs[i] is the list of all reachable states by \sharp1 \bar \sharp0 from i


  DFABuilder *b = dfaSetup(M->ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)calloc((M->ns+1), sizeof(char));

  // For the starting state we need to do something special as there is no
  // "from" transition to look for.
  // Check whether there are any closure paths from state 0
  k = 0;
  if(pairs[0]!=NULL && pairs[0]->count>0) {
      // Loop over states reachable from state 0
      for(z=0, tmp=pairs[0]->head;z<pairs[0]->count; z++, tmp = tmp->next) {
          i = tmp->value;
          // Loop over all the paths attached to the closure state
          state_paths = pp = make_paths(M->bddm, M->q[i]);
          while (pp) {
              if ((pp->to != sink) && (pp->to != 0)) {
                  for (tp = pp->trace; tp && (tp->index != indices[var]); tp = tp->next);
                  if (!tp || !(tp->value)) { // pp->value indicates a bar value

                  // Check if the transition is a loop to the same state
                  if (pp->to == i) {
                      to_states[k] = 0;
                  } else {
                      to_states[k]=pp->to;
                  }
                  for (j = 0; j < var; j++) {
                  //the following for loop can be avoided if the indices are in order
                  for (tp = pp->trace; tp && (tp->index != indices[j]); tp = tp->next);
                  if (tp) {
                    if (tp->value) exeps[k*(len+1)+j]='1';
                    else exeps[k*(len+1)+j]='0';
                  }
                  else
                    exeps[k*(len+1)+j]='X';
                }
                set_bitvalue(auxbit, aux, z+1); // aux = 3, z=4, auxbit 001
                for (j = var; j < len; j++) { //set to xxxxxxxx100 (= not bar?)
                    exeps[k*(len+1)+j]=auxbit[len-j-1];
                }
                exeps[k*(len+1)+len]='\0';
                k++;
                if ((pp->to == i) && remove_loops) {
                    k--;
                    //printf("Loop removed\n");
                } else {
                    //printf("Stating state has closure to state %d -> %d\n", i, pp->to);
                    //print_exep_value( &exeps[(k-1)*(len+1)], len);
                }
              }
            }
            pp = pp->next;
          }
          kill_paths(state_paths);
      }
  }

  // Now loop over each state and look for closure paths
  for (i = 0; i < M->ns; i++) {
    state_paths = pp = make_paths(M->bddm, M->q[i]);
    // Do not reset k here, as we want to add states from the special case above
    while (pp) {
      if(pp->to!=sink) {
        for (tp = pp->trace; tp && (tp->index != indices[var]); tp = tp->next);
	if (!tp || !(tp->value)) { // it is a bar value
	  to_states[k]=pp->to;
	  for (j = 0; j < var; j++) {
	    //the following for loop can be avoided if the indices are in order
	    for (tp = pp->trace; tp && (tp->index != indices[j]); tp = tp->next);
	    if (tp) {
	      if (tp->value) exeps[k*(len+1)+j]='1';
	      else exeps[k*(len+1)+j]='0';
	    }
	    else
	      exeps[k*(len+1)+j]='X';
	  }
	  for (j = var; j < len; j++) {
            exeps[k*(len+1)+j]='0';
	  }
	  exeps[k*(len+1)+len]='\0';
          k++;
          if(pairs[pp->to]!=NULL && pairs[pp->to]->count>0) { // Need to add extra edges to states in reachable closure
            o=k-1; //the original path
            for(z=0, tmp=pairs[pp->to]->head;z<pairs[pp->to]->count; z++, tmp = tmp->next){
              // Add an extra edge to the reachable closure state directly
              // bypassing the other states and in effect deleting the characters
              to_states[k]=tmp->value;
              //printf("state %d: z: %d o: %d  to_states[%d] = %d\n", i, z, o, k, to_states[k]);
              //print_exep_value( &exeps[o*(len+1)], len);

              // Create the new transition value
              for (j = 0; j < var; j++) exeps[k*(len+1)+j]=exeps[o*(len+1)+j];
                set_bitvalue(auxbit, aux, z+1); // aux = 3, z=4, auxbit 001
              for (j = var; j < len; j++) { //set to xxxxxxxx100 (= not bar?)
                exeps[k*(len+1)+j]=auxbit[len-j-1];
              }
              exeps[k*(len+1)+len]='\0';
              k++;
              if (state_already_included(exeps, k, len, var)) {
                  //printf("State already included!\n");
                  k--;
              }
            }
          }
	}
      }
      pp = pp->next;
    }//end while

    dfaAllocExceptions(b, k);
    for(k--;k>=0;k--) {
//        printf("%2d to %2d with value ", i, to_states[k]);
//        print_exep_value(&exeps[k*(len+1)], len);
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    }
    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);
    k = 0;
  }

  statuces[M->ns]='\0';
  tmpM2=dfaBuild(b, statuces);

  //dfaPrintGraphvizAsciiRange(tmpM2, var, indices, 1);  
  //dfaPrintVitals(result);
  result = project_away_sharps(tmpM2, aux, len);
  dfaFree(tmpM2);

  free(exeps);
  //printf("FREE ToState\n");
  free(to_states);
  //printf("FREE STATUCES\n");
  free(statuces);

  if(maxCount>0) free(auxbit);

  for(i=0; i<M->ns; i++)
    free_ilt(pairs[i]);
  free(pairs);
  if( DEBUG_SIZE_INFO )
	  printf("\t peak : replace_delete : states %d : bddnodes %u \n", tmpM2->ns, bdd_size(tmpM2->bddm) );
  return result;
}




//Replace sharp1 bar sharp2 to str. str is a single char
//for all i, if pairs[i]!=NULL, add path to each state in pairs[i]
DFA *dfa_replace_char(DFA *M, char a, int var, int *oldindices)
{
    DFA *result = NULL;
  DFA *tmpM1 = NULL;
  DFA *tmpM2 = NULL;
  int aux=0;
  struct int_list_type **pairs=NULL;
  int maxCount = 0;

  paths state_paths, pp;
  trace_descr tp;
  int i, j, z, k;
  char *exeps;
  int *to_states;
  long max_exeps;
  char *statuces;
  int len=var;
  int sink;
  int *indices=oldindices;
  char *auxbit=NULL;
  struct int_type *tmp=NULL;
  char *apath =bintostr(a, var);

  pairs = get_match(M, var, indices);
  maxCount = get_maxcount(pairs, M->ns);

  if(maxCount>0){ //Need auxiliary bits when there exist some outgoing edges
    aux = get_hsig(maxCount);
    //	printf("Replace one char: %d hits, need to add %d auxiliary bits\n", maxCount, aux);
    auxbit = (char *) calloc(aux, sizeof(char));
    len = var+aux; // extra aux bits
    indices = allocateArbitraryIndex(len);
  }



  max_exeps=1<<len; //maybe exponential
//    printf("len in dfa_replace_char = %d, max_exeps = %ld\n", len, max_exeps);
  sink=find_sink(M);
  assert(sink >-1);

  //pairs[i] is the list of all reachable states by \sharp1 \bar \sharp0 from i


  DFABuilder *b = dfaSetup(M->ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)calloc((M->ns+1), sizeof(char));

  //printf("Before Replace Char\n");
  //dfaPrintVerbose(M);

  for (i = 0; i < M->ns; i++) {

    state_paths = pp = make_paths(M->bddm, M->q[i]);
    k=0;

    while (pp) {
      if(pp->to!=sink){
	for (tp = pp->trace; tp && (tp->index != indices[var]); tp =tp->next); //find the bar value
	if (!tp || !(tp->value)) {
	  to_states[k]=pp->to;
	  for (j = 0; j < var; j++) {
	    //the following for loop can be avoided if the indices are in order
	    for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	    if (tp) {
	      if (tp->value) exeps[k*(len+1)+j]='1';
	      else exeps[k*(len+1)+j]='0';
	    }
	    else
	      exeps[k*(len+1)+j]='X';
	  }
	  for (j = var; j < len; j++) {
	    exeps[k*(len+1)+j]='0';
	  }
	  exeps[k*(len+1)+len]='\0';
	  k++;

	}
      }
      pp = pp->next;
    }//end while

    if(pairs[i]!=NULL && pairs[i]->count>0){ //need to add extra edges to states in reachable closure

      for(z=0, tmp=pairs[i]->head;z< pairs[i]->count; z++, tmp = tmp->next){
	to_states[k]=tmp->value;
	for (j = 0; j < var; j++) exeps[k*(len+1)+j]=apath[j];
	set_bitvalue(auxbit, aux, z+1); // aux = 3, z=4, auxbit 001
	for (j = var; j < len; j++) { //set to xxxxxxxx100
	  exeps[k*(len+1)+j]=auxbit[len-j-1];
	}
	exeps[k*(len+1)+len]='\0';
	k++;
      }
    }

    dfaAllocExceptions(b, k);
    for(k--;k>=0;k--)
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);
  }

  statuces[M->ns]='\0';
  tmpM1 = dfaBuild(b, statuces);

  result = project_away_sharps(tmpM1, aux, len);
  dfaFree(tmpM1);

  free(exeps);
  //printf("FREE ToState\n");
  free(to_states);
  //printf("FREE STATUCES\n");
  free(statuces);

  free(apath);

  if(maxCount>0) free(auxbit);

  for(i=0; i<M->ns; i++)
    free_ilt(pairs[i]);
  free(pairs);
	if( DEBUG_SIZE_INFO )
		printf("\t peak : replace_char : states %d : bddnodes %u \n", tmpM1->ns, bdd_size(tmpM1->bddm) );

    return result;
}


int count_accepted_chars(DFA* M){
  paths state_paths, pp;
  int k=0;
  int sink = find_sink(M);
  state_paths = pp = make_paths(M->bddm, M->q[M->s]);
  while (pp){
    if(pp->to!=sink && (M->f[pp->to]==1))  k++;
    pp = pp->next;
  }
  return k;
}



void set_accepted_chars(DFA* M,char** apath, int numchars, int var, int* indices){

  paths state_paths, pp;
  trace_descr tp;
  int k=0;
  int j;
  int sink = find_sink(M);
  state_paths = pp = make_paths(M->bddm, M->q[M->s]);
  while (pp){
    if(pp->to!=sink && (M->f[pp->to]==1)){
      apath[k] = (char *) malloc(var*sizeof(char));
       for (j = 0; j < var; j++) {
	 //the following for loop can be avoided if the indices are in order
	 for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	 if (tp) {
	   if (tp->value) apath[k][j]='1';
	   else apath[k][j]='0';
	 }
	 else
	   apath[k][j]='X';
       }
      k++;
    }
    pp = pp->next;
  }
  assert(k==numchars); // the number of added apaths shall be equal to numchars
}

//Replace sharp1 bar sharp2 to Mr. Mr accepts a set of single chars
//for all i, if pairs[i]!=NULL, add path to each state in pairs[i]
DFA *dfa_replace_M_dot(DFA *M, DFA* Mr, int var, int *oldindices)
{
  DFA *result = NULL;
  DFA *tmpM = NULL;
  int aux=0;
  struct int_list_type **pairs=NULL;
  int maxCount = 0;

  paths state_paths, pp;
  trace_descr tp;
  int i, j, z, k;
  char *exeps;
  int *to_states;
  long max_exeps;
  char *statuces;
  int len=var;
  int sink;
  int *indices=oldindices;
  char *auxbit=NULL;
  struct int_type *tmp=NULL;

  //Get from Mr
  int nc;
  int numchars = count_accepted_chars(Mr);
  char* apath[numchars];
  set_accepted_chars(Mr, apath, numchars, var, indices);

  pairs = get_match(M, var, indices);
  maxCount = get_maxcount(pairs, M->ns);

  if(maxCount>0){ //Need auxiliary bits when there exist some outgoing edges
    aux = get_hsig(maxCount);
    //	printf("Replace one char: %d hits, need to add %d auxiliary bits\n", maxCount, aux);
    auxbit = (char *) calloc(aux, sizeof(char));
    len = var+aux; // extra aux bits
    indices = allocateArbitraryIndex(len);
  }



  max_exeps=1<<len; //maybe exponential
  sink=find_sink(M);
  assert(sink >-1);

  //pairs[i] is the list of all reachable states by \sharp1 \bar \sharp0 from i


  DFABuilder *b = dfaSetup(M->ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)calloc((M->ns+1), sizeof(char));

  //printf("Before Replace Char\n");
  //dfaPrintVerbose(M);

  for (i = 0; i < M->ns; i++) {

    state_paths = pp = make_paths(M->bddm, M->q[i]);
    k=0;

    while (pp) {
      if(pp->to!=sink){
	for (tp = pp->trace; tp && (tp->index != indices[var]); tp =tp->next); //find the bar value
	if (!tp || !(tp->value)) {
	  to_states[k]=pp->to;
	  for (j = 0; j < var; j++) {
	    //the following for loop can be avoided if the indices are in order
	    for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	    if (tp) {
	      if (tp->value) exeps[k*(len+1)+j]='1';
	      else exeps[k*(len+1)+j]='0';
	    }
	    else
	      exeps[k*(len+1)+j]='X';
	  }
	  for (j = var; j < len; j++) {
	    exeps[k*(len+1)+j]='0';
	  }
	  exeps[k*(len+1)+len]='\0';
	  k++;

	}
      }
      pp = pp->next;
    }//end while

    if(pairs[i]!=NULL && pairs[i]->count>0){ //need to add extra edges to states in reachable closure

      for(z=0, tmp=pairs[i]->head;z< pairs[i]->count; z++, tmp = tmp->next){
	set_bitvalue(auxbit, aux, z+1); // aux = 3, z=4, auxbit 001
	for(nc = 0; nc<numchars; nc++){
	  to_states[k]=tmp->value;
	  for (j = 0; j < var; j++) exeps[k*(len+1)+j]=apath[nc][j];
	  for (j = var; j < len; j++) { //set to xxxxxxxx100
	    exeps[k*(len+1)+j]=auxbit[len-j-1];
	  }
	  exeps[k*(len+1)+len]='\0';
	  k++;
	} // end for nc
      }	//end for z
    }

    dfaAllocExceptions(b, k);
    for(k--;k>=0;k--)
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);
  }

  statuces[M->ns]='\0';
  tmpM = dfaBuild(b, statuces);
  result = project_away_sharps(tmpM, aux, len);
  dfaFree(tmpM);

  free(exeps);
  //printf("FREE ToState\n");
  free(to_states);
  //printf("FREE STATUCES\n");
  free(statuces);

  //free(apath);
  for(i=0; i<numchars; i++) free(apath[i]);

  if(maxCount>0){
    free(auxbit);
    free(indices);
  }

  for(i=0; i<M->ns; i++)
    free_ilt(pairs[i]);
  free(pairs);

  return result;

}// End dfa_replace_M_dot


//Get outgoing information from M and fulfill in
//num: number of outgoing edges
//final: number of outgoing edges to final states
//bin: the binary value along the outgoing edge (add aux bits 0 at the tail)
//to: the destination of the outgoing edge

void initial_out_info(DFA* M, int* num, int* final, char*** bin, int** to, int var, int aux, int* indices){

  int i, j, k;
  paths state_paths, pp;
  trace_descr tp;
  int sink = find_sink(M);


  //initialize num

  for(i = 0; i<M->ns; i++){
    k =0;
    state_paths = pp = make_paths(M->bddm, M->q[i]);
    while (pp){
      if(pp->to!=sink)  k++;
      pp = pp->next;
    }
    num[i] = k;
    final[i] = 0;
    kill_paths(state_paths);
  }

  //initialize binary of each outgoing edges

  for(i = 0; i<M->ns; i++){
	  if(num[i]>0){
	  bin[i] = (char **) malloc((num[i])*sizeof(char *));
	  to[i] = (int *) malloc((num[i])*sizeof(int));
	  k=0;
	  state_paths = pp = make_paths(M->bddm, M->q[i]);
	  while (pp){
		  if(pp->to!=sink){

			  bin[i][k]=(char *) malloc((var+aux+1)*sizeof(char)); //may lead to memory leak
			  to[i][k] = pp->to;
			  if(M->f[pp->to] == 1) final[i]++;

			  for (j = 0; j < var; j++) {
				  //the following for loop can be avoided if the indices are in order
				  for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

				  if (tp) {
					  if (tp->value) bin[i][k][j]='1';
					  else bin[i][k][j]='0';
				  }
				  else
					  bin[i][k][j]='X';
			  }
			  for(j=var; j<var+aux; j++) bin[i][k][j]='0';

			  bin[i][k][j]= '\0';//end of string
			  k++;
		  }//end if != sink
		  pp = pp->next;
	  }//end while
	  kill_paths(state_paths);
	  }else{
		  bin[i] = NULL;
		  to[i] = NULL;
	  }
  }

}//end initial_out_info




//Replace every pairs(i,j), so that i can reach j through sharp1 bar sharp0, to i Mr j,
//where Mr is the replacement, whihc can be an arbitrary DFA accepting words >1
DFA *dfa_replace_M_arbitrary(DFA *M, DFA *Mr, int var, int *oldindices)
{
  DFA *result = NULL;
  DFA *tmpM = NULL;
  int aux=0;
  struct int_list_type **pairs=NULL;
  int maxCount, numberOfSharp;


  paths state_paths, pp;
  trace_descr tp;
  int i, j, z, n, o, k, numsharp2;
  int s=0;
  char *exeps;
  char *auxexeps=NULL;
  int *to_states;
  int *aux_to_states=NULL;
  long max_exeps;
  char *statuces;
  int len=var;
  int ns, sink;
  int *indices=oldindices;
  char *auxbit=NULL;
  struct int_type *tmp=NULL;

  int extrastates = Mr->ns; //duplicate states for each sharp pair

  //for out going information in Mr
  char ***binOfOut = (char ***) malloc((Mr->ns)*sizeof(char **)); //the string of the nonsink outgoing edge of each state
  int **toOfOut = (int **) malloc((Mr->ns)*sizeof(int *)); // the destination of the nonsink outgoing edge of each state
  int *numOfOut = (int *) malloc((Mr->ns)*sizeof(int)); // how many nonsink outgoing edges of each state
  int *numOfOutFinal = (int *) malloc((Mr->ns)*sizeof(int)); //how many final outgoing edges of each state

  int *startStates = NULL;



  pairs = get_match(M, var, indices);

  maxCount = get_maxcount(pairs, M->ns);
  numberOfSharp = get_number_of_sharp1_state(pairs, M->ns);


  if(maxCount>0){ //Need auxiliary bits when there exist some outgoing edges

    aux = get_hsig(maxCount);//get the highest significant bit
    if(_FANG_DFA_DEBUG) printf("Replace Arbitrary M: %d hits, need to add %d auxiliary bits\n", maxCount, aux);
    auxbit = (char *) calloc(aux, sizeof(char));//the redundant bits to distinguish outgoing edges
    len = var+aux; // extra aux bits
    indices = allocateArbitraryIndex(len);
    s=0;
    startStates = (int *) malloc(numberOfSharp*sizeof(int));
    for(i =0; i<numberOfSharp; i++){
      startStates[i]=-1; //initially it is -1. There is an error if some of them are not set up later.
    }
    auxexeps=(char *)malloc(maxCount*(len+1)*sizeof(char));
    aux_to_states=(int *)malloc(maxCount*sizeof(int));
  }

  initial_out_info(Mr, numOfOut, numOfOutFinal, binOfOut, toOfOut, var, aux, indices);


  max_exeps=1<<len; //maybe exponential
  sink=find_sink(M);
  assert(sink >-1);
  ns = M->ns + numberOfSharp*extrastates;

  //pairs[i] is the list of all reachable states by \sharp1 \bar \sharp0 from i
  DFABuilder *b = dfaSetup(ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)malloc((ns+1)*sizeof(char));



  for (i = 0; i < M->ns; i++) {

    state_paths = pp = make_paths(M->bddm, M->q[i]);
    k=0;

    while (pp) {
      if(pp->to!=sink){
	for (tp = pp->trace; tp && (tp->index != indices[var]); tp =tp->next); //find the bar value
	if (!tp || !(tp->value)) {
	  to_states[k]=pp->to;
	  for (j = 0; j < var; j++) {
	    //the following for loop can be avoided if the indices are in order
	    for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	    if (tp) {
	      if (tp->value) exeps[k*(len+1)+j]='1';
	      else exeps[k*(len+1)+j]='0';
	    }
	    else
	      exeps[k*(len+1)+j]='X';
	  }
	  for (j = var; j < len; j++) {
	    exeps[k*(len+1)+j]='0'; //all original paths are set to zero
	  }
	  exeps[k*(len+1)+len]='\0';
	  k++;

	}
      }
      pp = pp->next;
    }//end while

    if(pairs[i]!=NULL && pairs[i]->count>0){ //need to add extra edges to states in reachable closure
      startStates[s]=i; //pairs[startStates[s]] is the destination that later we shall use for region s
      for(o=0; o<numOfOut[Mr->s]; o++){
	to_states[k]=M->ns+s*(extrastates)+toOfOut[Mr->s][o]; // go to the next state of intial state of  Mr
	for(j = 0; j < var; j++) exeps[k*(len+1)+j]=binOfOut[Mr->s][o][j];
	for(j = var; j< len-1; j++) exeps[k*(len+1)+j] = '0';
	exeps[k*(len+1)+j]='1'; //to distinguish the original path
	exeps[k*(len+1)+len]='\0';
	k++;
      }
      s++;
    }

    dfaAllocExceptions(b, k);
    for(k--;k>=0;k--)
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);

  }//end for i

  assert(s==numberOfSharp);
  assert(i==M->ns);

  //Add replace states
  for(n=0;n<numberOfSharp; n++){
    assert((pairs[startStates[n]]!=NULL) && (pairs[startStates[n]]->count > 0));
    numsharp2 = pairs[startStates[n]]->count;
    for(i=0; i<Mr->ns; i++){ //internal M (exclude the first and the last char)
      if(numOfOutFinal[i]==0){
	dfaAllocExceptions(b, numOfOut[i]);
	for(o =0; o<numOfOut[i]; o++){
	  dfaStoreException(b, M->ns+n*(extrastates)+toOfOut[i][o], binOfOut[i][o]);
	}
	dfaStoreState(b, sink);
      }else{//need to add aux edges back to sharp destination, for each edge leads to accepting state
	dfaAllocExceptions(b, numOfOut[i]+numOfOutFinal[i]*numsharp2);
	for(o =0; o<numOfOut[i]; o++){
	  dfaStoreException(b, M->ns+n*(extrastates)+toOfOut[i][o], binOfOut[i][o]);
	  if(Mr->f[toOfOut[i][o]]==1){ //add auxiliary back edges
	    for(z=0, tmp=pairs[startStates[n]]->head;z< numsharp2; z++, tmp = tmp->next){
	      aux_to_states[z]=tmp->value;
	      for (j = 0; j < var; j++) auxexeps[z*(len+1)+j]=binOfOut[i][o][j];
	      set_bitvalue(auxbit, aux, z+1); // aux = 3, z=4, auxbit 001
	      for (j = var; j < len; j++) { //set to xxxxxxxx100
		auxexeps[z*(len+1)+j]=auxbit[len-j-1];
	      }
	      auxexeps[z*(len+1)+len]='\0';
	    }

	    for(z--;z>=0;z--)
	      dfaStoreException(b, aux_to_states[z],auxexeps+z*(len+1));
	  }
	}
	dfaStoreState(b, sink);
      }
    }//end for Mr internal
  }

  for(i=M->ns; i<ns; i++) statuces[i]='-';

  statuces[ns]='\0';
  tmpM=dfaBuild(b, statuces);
  result = project_away_sharps(M, aux, len);
  dfaFree(tmpM);

  free(exeps);
  //printf("FREE ToState\n");
  free(to_states);
  //printf("FREE STATUCES\n");
  free(statuces);



  if(maxCount>0){
    free(auxbit);
    free(aux_to_states);
    free(auxexeps);
    free(indices);
    free(startStates);
  }

  for(i=0; i<M->ns; i++)
    free_ilt(pairs[i]);

  for(i=0; i<Mr->ns; i++){
    free(binOfOut[i]);
    free(toOfOut[i]);
  }



  free(binOfOut);
  free(toOfOut);
  free(numOfOut);
  free(numOfOutFinal);

  free(pairs);

  return result;
}


char **get_bitstrings(char *str, int var, int aux){

  int j;
  char **result;
  size_t i = strlen(str);
  result = (char **)malloc(i*sizeof(char*));
  for(j=0; j<i; j++)
    result[j] = bintostrWithExtraBitsZero(str[j], var, aux);
  return result;
}

//Replace sharp1 bar sharp2 to str.
DFA *dfa_replace_string(DFA *M, const char *str, int var, int *oldindices)
{
  DFA *result = NULL;
    DFA *tmpM1 = NULL;
  DFA *tmpM2 = NULL;
  int aux=0;
  struct int_list_type **pairs=NULL;
  int maxCount, numberOfSharp;


  paths state_paths, pp;
  trace_descr tp;
  int i, j, z, k;
  int s=0;
  char *exeps;
  char *auxexeps=NULL;
  int *to_states;
  int *aux_to_states=NULL;
  long max_exeps;
  char *statuces;
  int len=var;
  int ns, sink;
  int *indices=oldindices;
  char *auxbit=NULL;
  struct int_type *tmp=NULL;
  int extrastates = (int) strlen(str)-1;
  char **binOfStr=NULL;
  int *startStates = NULL;



  pairs = get_match(M, var, indices);

  maxCount = get_maxcount(pairs, M->ns);
  numberOfSharp = get_number_of_sharp1_state(pairs, M->ns);

  if(maxCount>0){ //Need auxiliary bits when there exist some outgoing edges
    aux = get_hsig(maxCount);
    //printf("Replace string: %d hits, need to add %d auxiliary bits\n", maxCount, aux);
    auxbit = (char *) calloc(aux, sizeof(char));
    len = var+aux; // extra aux bits
    indices = allocateArbitraryIndex(len);
    binOfStr = get_bitstrings(str, var, aux); //initially extra bit are zero
    s=0;
    startStates = (int *) malloc(numberOfSharp*sizeof(int));
    for(i =0; i<numberOfSharp; i++){
      startStates[i]=-1; //initially it is -1. There is an error if some of them are not set up later.
    }
    auxexeps=(char *)malloc(maxCount*(len+1)*sizeof(char));
    aux_to_states=(int *)malloc(maxCount*sizeof(int));
  }



  max_exeps=1<<len; //maybe exponential
  //printf("len in dfa_replace_string = %d, max_exeps = %ld\n", len, max_exeps);
  sink=find_sink(M);
  assert(sink >-1);
  ns = M->ns + numberOfSharp * (extrastates);
  //printf("old number of states in dfa_replace_string = %d, new number of states = %d\n", M->ns, ns);
  //pairs[i] is the list of all reachable states by \sharp1 \bar \sharp0 from i
  DFABuilder *b = dfaSetup(ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)malloc((ns+1)*sizeof(char));


  for (i = 0; i < M->ns; i++) {

    state_paths = pp = make_paths(M->bddm, M->q[i]);
    k=0;

    while (pp) {
      if(pp->to!=sink){
	for (tp = pp->trace; tp && (tp->index != indices[var]); tp =tp->next); //find the bar value
	if (!tp || !(tp->value)) {
	  to_states[k]=pp->to;
	  for (j = 0; j < var; j++) {
	    //the following for loop can be avoided if the indices are in order
	    for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	    if (tp) {
	      if (tp->value) exeps[k*(len+1)+j]='1';
	      else exeps[k*(len+1)+j]='0';
	    }
	    else
	      exeps[k*(len+1)+j]='X';
	  }
	  for (j = var; j < len; j++) {
	    exeps[k*(len+1)+j]='0'; //all original paths are set to zero
	  }
	  exeps[k*(len+1)+len]='\0';
	  k++;
	}
      }
      pp = pp->next;
    }//end while

    if(pairs[i]!=NULL && pairs[i]->count>0){ //need to add extra edges to states in reachable closure
      startStates[s]=i; //pairs[startStates[s]] is the destination that later we shall use for region s
      to_states[k]=M->ns+s*(extrastates); // go to the initial state of string by the first char
      s++;
      for (j = 0; j < len; j++) exeps[k*(len+1)+j]=binOfStr[0][j];
      exeps[k*(len+1)+len-1]='1'; //to distinguish the original path
      exeps[k*(len+1)+len]='\0';
      k++;
    }

    dfaAllocExceptions(b, k);
    for(k--;k>=0;k--)
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);
  }//end for

  assert(s==numberOfSharp);
  assert(i==M->ns);

  for(i=0;i<numberOfSharp; i++){
    for(j=0; j<extrastates-1; j++){ //internal string (exclude the first and the last char)
      dfaAllocExceptions(b, 1);
      dfaStoreException(b, M->ns+i*(extrastates)+j+1, binOfStr[j+1]);
      dfaStoreState(b, sink);
    }
    assert((pairs[startStates[i]]!=NULL) && (pairs[startStates[i]]->count > 0));

    //for the end state add pathes to get back to pair[startStates[i]]

    for(z=0, tmp=pairs[startStates[i]]->head;z< pairs[startStates[i]]->count; z++, tmp = tmp->next){
      aux_to_states[z]=tmp->value;
      for (j = 0; j < var; j++) auxexeps[z*(len+1)+j]=binOfStr[extrastates][j];
      set_bitvalue(auxbit, aux, z+1); // aux = 3, z=4, auxbit 001
      for (j = var; j < len; j++) { //set to xxxxxxxx100
	auxexeps[z*(len+1)+j]=auxbit[len-j-1];
      }
      auxexeps[z*(len+1)+len]='\0';
    }
    dfaAllocExceptions(b, z);
    for(z--;z>=0;z--)
      dfaStoreException(b, aux_to_states[z],auxexeps+z*(len+1));
    dfaStoreState(b, sink);
  }

  for(i=M->ns; i<ns; i++) statuces[i]='0';

  statuces[ns]='\0';
  tmpM1=dfaBuild(b, statuces);

  result = project_away_sharps(tmpM1, aux, len);
  dfaFree(tmpM1);
  
  free(exeps);
    //printf("FREE ToState\n");
  free(to_states);
  //printf("FREE STATUCES\n");
  free(statuces);
    
  if(maxCount>0){
      free(auxbit);
      free(aux_to_states);
      free(auxexeps);
      free(indices);
      free(startStates);
      for(i=0; i<strlen(str); i++) free(binOfStr[i]);
      free(binOfStr);
  }
    
  for(i=0; i<M->ns; i++)
      free_ilt(pairs[i]);
  free(pairs);
      
  if( DEBUG_SIZE_INFO )
      printf("\t peak : replace_string : states %d : bddnodes %u : before loop \n", result->ns, bdd_size(result->bddm) );

  return result;
}




DFA *dfa_replace_step3_replace(DFA *M, const char *str, int var, int *indices)
{
  DFA *result=NULL;

  if((str ==NULL)||strlen(str)==0){
//    printf("Replacement [%s]!\n", str);
      result = dfa_replace_delete(M, var, indices, 1);
  }else if(strlen(str)==1){
//    printf("Replacement [%s]!\n", str);
    result = dfa_replace_char(M, str[0], var, indices);
  }else {
//    printf("Replacement [%s]!\n", str);
    result = dfa_replace_string(M, str, var, indices);
  }
  return result;
} //END dfa_replace_stpe3_replace

DFA *dfa_replace_once_step3_replace(DFA *M, const char *str, int var, int *indices)
{
  DFA *result=NULL;

  if((str ==NULL)||strlen(str)==0){
//    printf("Replacement [%s]!\n", str);
      result = dfa_replace_delete(M, var, indices, 0);
  }else if(strlen(str)==1){
//    printf("Replacement [%s]!\n", str);
    result = dfa_replace_char(M, str[0], var, indices);
  }else {
//    printf("Replacement [%s]!\n", str);
    result = dfa_replace_string(M, str, var, indices);
  }
  return result;
} //END dfa_replace_stpe3_replace


DFA *dfa_replace_step3_general_replace(DFA *M, DFA* Mr, int var, int *indices)
{
  DFA *result0 = NULL;
  DFA *result1 = NULL;
  DFA *result2 = NULL;
  DFA *result = NULL;
  DFA *tmp = NULL;
  DFA *tmp2 = NULL;

  //dfaPrintGraphvizAsciiRange(M, var, indices, 1);

  if(Mr->f[M->s]==1){
    //printf("Replacement [%s]!\n", str);
      result0 = dfa_replace_delete(M, var, indices, 1);
    result = result0;
  }


  tmp = dfaDot(var, indices);
  tmp2 = dfa_intersect(Mr, tmp);
  dfaFree(tmp);
  tmp = tmp2;
  if(!check_emptiness(tmp, var, indices)){
    result1 = dfa_replace_M_dot(M, tmp, var, indices);
    if(result){
      result = dfa_union(result, result1);
      dfaFree(result0);
      dfaFree(result1);
    } else {
      result = result1;
    }
  }
  dfaFree(tmp);
  
  tmp = dfaSigmaC1toC2(2, -1, var, indices);
  tmp2 = dfa_intersect(Mr, tmp);
  dfaFree(tmp);
  tmp = tmp2;

  if(!check_emptiness(tmp, var, indices)){
    //replace rest rather than single character
    result2 = dfa_replace_M_arbitrary(M, tmp, var, indices);

   if(result) {
     result1 = result;
     result = dfa_union(result1, result2);
     dfaFree(result1);
     dfaFree(result2);
   }
   else result = result2;
  }
  dfaFree(tmp);
  return result;
} //END dfa_replace_stpe3_general_replace



DFA *dfa_replace_extrabit(DFA *M1, DFA *M2, const char *str, int var, int *indices)
{
  DFA *temp1;
  DFA *result;
  DFA *M1_bar;
  DFA *M2_bar;
  DFA *M_inter;
  DFA *M_rep;
  DFA *M_sharp = dfaSharpStringWithExtraBit(var, indices);

  if ((M1 == NULL) || (M2 == NULL)) {
    return NULL;
  }
  // Check if we are replacing the search auto with the replace string
  char* M2_singleton = isSingleton(M2, var, indices);
  if (M2_singleton != NULL) {
    if (strcmp(str, M2_singleton) == 0) {
      free(M2_singleton);
      return dfaCopy(M1);
    }
    free(M2_singleton);
  }

  //printf("Insert sharp1 and sharp2 for duplicate M1\n");
  M1_bar = dfa_replace_step1_duplicate(M1, var, indices);
//  dfaPrintVitals(M1_bar);  //having extra bit
  if(_FANG_DFA_DEBUG) printf("M1_bar: var %d\n", var);
//  dfaPrintVitals(M1_bar);
  //dfaPrintGraphvizAsciiRange(M1_bar, var, indices, 1);
  //printf("Generate M2 bar sharp1 M2 and sharp2\n");
  M2_bar = dfa_replace_step2_match_compliment(M2, var, indices);
//  dfaPrintVitals(M2_bar);  //having extra bit
  if(_FANG_DFA_DEBUG) printf("M2_bar: var %d\n", var);
//  dfaPrintVitals(M2_bar);
  //dfaPrintGraphvizAsciiRange(M2_bar, var, indices, 1);

//  printf("Generate Intersection\n");
  M_inter = dfa_intersect(M1_bar, M2_bar);
  if(_FANG_DFA_DEBUG){
    printf("M_inter\n");
    dfaPrintVerbose(M_inter);
    dfaPrintGraphviz(M_inter, var+1, allocateAscIIIndexUnsigned(var+1));
    dfaPrintVerbose(M_inter);
  }
//  dfaPrintVitals(M_inter);
  //dfaPrintGraphvizAsciiRange(M_inter, var, indices, 1);

//  printf("Check Intersection\n");
  if(check_intersection(M_sharp, M_inter, var, indices)>0){

//    printf("Start Replacement!\n");
    //replace match patterns
    M_rep = dfa_replace_step3_replace(M_inter, str, var, indices);
//    dfaPrintVitals(M_rep);
    temp1=dfaProject(M_rep, (unsigned) var);
    dfaFree(M_rep);

  }else { //no match
    temp1 = dfaCopy(M1);
  }

  //printf("free M1_bar\n");
  dfaFree(M1_bar);
  //printf("free M2_bar\n");
  dfaFree(M2_bar);
  //printf("free M_inter\n");
  dfaFree(M_inter);
  //printf("free M_sharp\n");
  dfaFree(M_sharp);

	if( DEBUG_SIZE_INFO )
		printf("\t peak : replace_extrabit : states %d : bddnodes %u \n", temp1->ns, bdd_size(temp1->bddm) );
  result = dfaMinimize(temp1);
  dfaFree(temp1);
  return result;
}

DFA *dfa_replace_once_extrabit(DFA *M1, DFA *M2, const char *str, int var, int *indices)
{
  if ((M1 == NULL) || (M2 == NULL)) {
    return NULL;
  }
  DFA *temp1;
  DFA *result = NULL;
  DFA *M1_bar;
  DFA *M2_bar;
  DFA *M_inter;
  DFA *M_rep;
  DFA *M_sharp = dfaSharpStringWithExtraBit(var, indices);

  // Check if we are replacing the search auto with the replace string
  char* M2_singleton = isSingleton(M2, var, indices);
  if (M2_singleton != NULL) {
    if (strcmp(str, M2_singleton) == 0) {
      free(M2_singleton);
      return dfaCopy(M1);
    }
    free(M2_singleton);
  }

   /* printf("M1: var %d\n", var); */
   /* dfaPrintGraphvizAsciiRange(M1, var, indices, 1); */

   /* printf("M2: var %d\n", var); */
   /* dfaPrintGraphvizAsciiRange(M2, var, indices, 1); */

   /* printf("str: %s\n", str); */

   // Check is the search string is empty
   if (checkOnlyEmptyString(M2, var, indices)) {
     // If the replace string is also empty:
     if (strlen(str) == 0) {
       // Then there is nothing to do, return the input string
       result = dfaCopy(M1);
     } else {
       // Just concatenate the search and input strings
       DFA* temp1 = dfa_construct_string(str, var, indices);
       DFA* result = dfa_concat(temp1, M1, var, indices);
       dfaFree(temp1);
     }
   } else {
//  printf("Insert sharp1 and sharp2 for duplicate M1\n");
     M1_bar = dfa_replace_step1_duplicate(M1, var, indices);
//  printf("M1_bar: var %d\n", var);
//  dfaPrintGraphvizAsciiRange(M1_bar, var, indices, 1);
//  printf("Generate M2 bar sharp1 M2 and sharp2\n");
     M2_bar = dfa_replace_once_step2_match_compliment(M2, var, indices);
//  printf("M2_bar: var %d\n", var);
//  dfaPrintGraphvizAsciiRange(M2_bar, var, indices, 1);

//  printf("Generate Intersection\n");
     M_inter = dfa_intersect(M1_bar, M2_bar);
//  printf("M_inter\n");
//  dfaPrintGraphvizAsciiRange(M_inter, var, indices, 1);
 
  //printf("Check Intersection\n");
     if(check_intersection(M_sharp, M_inter, var, indices)>0) {
       //printf("Start Replacement!\n");
       //replace match patterns
       M_rep = dfa_replace_once_step3_replace(M_inter, str, var, indices);
       temp1=dfaProject(M_rep, (unsigned) var);
       dfaFree(M_rep);
     } else { //no match
       //printf("No match found");
       temp1 = dfaCopy(M1);
     }

     //printf("free M1_bar\n");
     dfaFree(M1_bar);
     //printf("free M2_bar\n");
     dfaFree(M2_bar);
     //printf("free M_inter\n");
     dfaFree(M_inter);
     //printf("free M_sharp\n");
     dfaFree(M_sharp);

     if( DEBUG_SIZE_INFO )
       printf("\t peak : replace_extrabit : states %d : bddnodes %u \n", temp1->ns, bdd_size(temp1->bddm) );
     result = dfaMinimize(temp1);
     dfaFree(temp1);
   }
   return result;
}

DFA *dfa_general_replace_once_extrabit(DFA *M1, DFA *M2, DFA* M3, int var, int *indices)
{
  if ((M1 == NULL) || (M2 == NULL)) {
    return NULL;
  }
  DFA *temp1;
  DFA *result = NULL;
  DFA *M1_bar;
  DFA *M2_bar;
  DFA *M_inter;
  DFA *M_rep;
  DFA *M_sharp = dfaSharpStringWithExtraBit(var, indices);


   /* printf("M1: var %d\n", var); */
   /* dfaPrintGraphvizAsciiRange(M1, var, indices, 1); */

   /* printf("M2: var %d\n", var); */
   /* dfaPrintGraphvizAsciiRange(M2, var, indices, 1); */

   /* printf("str: %s\n", str); */

//  printf("Insert sharp1 and sharp2 for duplicate M1\n");
     M1_bar = dfa_replace_step1_duplicate(M1, var, indices);
//  printf("M1_bar: var %d\n", var);
//  dfaPrintGraphvizAsciiRange(M1_bar, var, indices, 1);
//  printf("Generate M2 bar sharp1 M2 and sharp2\n");
     M2_bar = dfa_replace_once_step2_match_compliment(M2, var, indices);
//  printf("M2_bar: var %d\n", var);
//  dfaPrintGraphvizAsciiRange(M2_bar, var, indices, 1);

//  printf("Generate Intersection\n");
     M_inter = dfa_intersect(M1_bar, M2_bar);
//  printf("M_inter\n");
//  dfaPrintGraphvizAsciiRange(M_inter, var, indices, 1);
 
  //printf("Check Intersection\n");

     if(check_intersection(M_sharp, M_inter, var, indices)>0) {
       //printf("Start Replacement!\n");
       //replace match patterns
       M_rep = dfa_replace_step3_replace(M_inter, M3, var, indices);
       temp1=dfaProject(M_rep, (unsigned) var);
       dfaFree(M_rep);
     } else { //no match
       //printf("No match found");
       temp1 = dfaCopy(M1);
     }

     //printf("free M1_bar\n");
     dfaFree(M1_bar);
     //printf("free M2_bar\n");
     dfaFree(M2_bar);
     //printf("free M_inter\n");
     dfaFree(M_inter);
     //printf("free M_sharp\n");
     dfaFree(M_sharp);

     if( DEBUG_SIZE_INFO )
       printf("\t peak : replace_extrabit : states %d : bddnodes %u \n", temp1->ns, bdd_size(temp1->bddm) );
     result = dfaMinimize(temp1);
     dfaFree(temp1);

   return result;
}


DFA *dfa_general_replace_extrabit(DFA* M1, DFA* M2, DFA* M3, int var, int* indices){

  DFA *result;
  DFA *M1_bar;
  DFA *M2_bar;
  DFA *M_inter;
  DFA *M_rep;
  DFA *M_sharp = dfaSharpStringWithExtraBit(var, indices);

  // Check if the search and replace automata are equivlaent:
  if (check_equivalence, M2, M3, var, indices) {
    // The replace is a no op, just return the input
    return dfaCopy(M1);
  }
  M1_bar = dfa_replace_step1_duplicate(M1, var, indices);
  M2_bar = dfa_replace_step2_match_compliment(M2, var, indices);

  M_inter = dfa_intersect(M1_bar, M2_bar);

  if(check_intersection(M_sharp, M_inter, var, indices)>0){

      // replace match patterns
    M_rep = dfa_replace_step3_general_replace(M_inter, M3, var, indices);
    result = dfaProject(M_rep, (unsigned) var);
    dfaFree(M_rep);

  }else { //no match
    result = dfaCopy(M1);
  }

  //printf("free M1_bar\n");
  dfaFree(M1_bar);
  //printf("free M2_bar\n");
  dfaFree(M2_bar);
  //printf("free M_inter\n");
  dfaFree(M_inter);
  //printf("free M_sharp\n");
  dfaFree(M_sharp);
    
  DFA *tmp = dfaMinimize(result);
  dfaFree(result);
  return tmp;
    
}



//Take Output DFA
DFA *dfa_replace(M1, M2, M3, var, indices)
     DFA *M1;
     DFA *M2;
     DFA *M3;
     int var;
     int *indices;
{
  return dfa_general_replace_extrabit(M1, M2, M3, var, indices);
}

/**********
 *
 * Automaton which ensures that at least one replaced state is passed through
 * ie, at least one "dash" transition occurs
 *
 * This prevents the original string being an accept state
 */
DFA* dfa_with_bar_transition(int var, int *indices)
{
  DFA* dfa = NULL;
  int len = var + 1;
  DFABuilder *b = dfaSetup(2, len, indices);
  char *arbitrary = getArbitraryStringWithExtraBit(var);

  // State 0
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 0, arbitrary);
  dfaStoreState(b, 1);

  // State 1
  dfaAllocExceptions(b, 0);
  dfaStoreState(b, 1);

  free(arbitrary);

  dfa = dfaBuild(b, "-+");
  return dfa;
}

/**********
 *
 * Automaton which ensures that at UP TO one replaced state is passed through
 * ie, exactly one "dash" transition occurs
 *
 * This prevents the original string being an accept state
 */
DFA* dfa_with_one_bar_transition(int var, int *indices)
{
  DFA* dfa = NULL;
  int len = var + 1;
  DFABuilder *b = dfaSetup(5, len, indices);

  // non-dash has extra bit '0'
  // non-dash is original alphabet
  // dash are the inserted loop state
  char *nondash = getArbitraryStringWithExtraBit(var);

  // State 0 - Initial state
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 1, nondash);
  dfaStoreState(b, 2);

  // State 1 - No dash transitions
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 1, nondash);
  dfaStoreState(b, 2);

  // State 2 - Single dash into loop
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 2, nondash);
  dfaStoreState(b, 3);

  // State 3 - Accept after one loop
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 3, nondash);
  dfaStoreState(b, 4);
  
  // State 4 (sink state)
  dfaAllocExceptions(b, 0);
  dfaStoreState(b, 4);

  free(nondash);

  // states:         01234
  dfa = dfaBuild(b, "-+-+-");

  //dfaPrintGraphvizAsciiRange(dfa, var, indices, 1);
  return dfa;
}

DFA* dfa_with_one_direct_bar_transition(int var, int *indices)
{
  DFA* dfa = NULL;
  int len = var + 1;
  DFABuilder *b = dfaSetup(4, len, indices);

  // non-dash has extra bit '0'
  // non-dash is original alphabet
  // dash are the inserted loop state
  char *nondash = getArbitraryStringWithExtraBit(var);

  // State 0 - Initial state
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 1, nondash);
  dfaStoreState(b, 2);

  // State 1 - No dash transitions
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 1, nondash);
  dfaStoreState(b, 2);

  // State 2 - Single dash into loop
  dfaAllocExceptions(b, 1);
  dfaStoreException(b, 2, nondash);
  dfaStoreState(b, 3);

  // State 3 - Sink
  dfaAllocExceptions(b, 0);
  dfaStoreState(b, 3);
 
  free(nondash);

  // states:         01234
  dfa = dfaBuild(b, "-++-");

  //dfaPrintGraphvizAsciiRange(dfa, var, indices, 1);
  return dfa;
}

// Only allow transitions with at least one bar state
DFA* dfa_ensure_bar_transition(DFA *M, int var, int *indices)
{
  DFA *bar = dfa_with_bar_transition(var, indices);
  DFA *tmp = dfa_intersect(M, bar);
  dfaFree(bar);
  return tmp;
}

// Only allow transitions with exactly one bar state
DFA* dfa_ensure_one_bar_transition(DFA *M, int var, int *indices)
{
  DFA *bar = dfa_with_one_bar_transition(var, indices);
  DFA *tmp = dfa_intersect(M, bar);
  dfaFree(bar);
  return tmp;
}

// Only allow transitions with exactly one bar state
DFA* dfa_ensure_one_direct_bar_transition(DFA *M, int var, int *indices)
{
  DFA *bar = dfa_with_one_direct_bar_transition(var, indices);
  DFA *tmp = dfa_intersect(M, bar);
  dfaFree(bar);
  return tmp;
}

DFA *dfa_create_M_with_extrabit(DFA *M, int var, int *indices)
{
  DFA *result = NULL;
  DFA *tmpM = NULL;

  paths state_paths, pp;
  trace_descr tp;
  int i, j, n, o, k;
  char *exeps;
  char *auxexeps;
  int *to_states;
  long max_exeps;
  char *statuces;
  int len = var + 1;
  int ns, sink;
  int need_new_sink = 0;
  char *arbitrary = getArbitraryStringWithLastExtraBit(var, '1');

  max_exeps=1<<len; //maybe exponential
  sink = find_sink(M);
  ns = M->ns;
  if (sink < 0) {
    // Need to create a new sink state
    sink = ns;
    ns += 1;
    need_new_sink = 1;
  }
  assert(sink >-1);

  DFABuilder *b = dfaSetup(ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)malloc((ns+1)*sizeof(char));

  // Loop over original states
  for (i = 0; i < M->ns; i++) {
    state_paths = pp = make_paths(M->bddm, M->q[i]);
    k=0;
    // add original paths
    while (pp) {
      if(pp->to!=sink){
	  to_states[k]=pp->to;
	  for (j = 0; j < var; j++) {
	    //the following for loop can be avoided if the indices are in order
	    for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	    if (tp) {
              if (tp->value) {
                exeps[k*(len+1)+j]='1';
              } else {
                exeps[k*(len+1)+j]='0';
              }
	    } else {
	      exeps[k*(len+1)+j]='X';
            }
	  }
	  for (j = var; j < len; j++) {
            exeps[k*(len+1)+j]='0';
	  }
	  exeps[k*(len+1)+len]='\0';
	  k++;
      }
      pp = pp->next;
    } // end while

    // If it is an accept state, also accept bar transitions
    if(M->f[i]==1) {
      dfaAllocExceptions(b, k + 1);
    } else {   
      dfaAllocExceptions(b, k);
    }

    for(k--; k>=0; k--) {
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    }
    if(M->f[i]==1) {
      dfaStoreException(b, i, arbitrary);
    }

    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);

  } // end of loop for original states

  // Add sink if needed
  if (need_new_sink) {
    // Call the plumber!
    dfaAllocExceptions(b, 0);
    dfaStoreState(b, sink);
    statuces[i]='-';
  }

  statuces[ns]='\0';

  // Create automaton
  result = dfaBuild(b, statuces);

  if(_FANG_DFA_DEBUG){
    printf("Project the %d bit\n", i);
    printf("Original:%d", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  tmpM = dfaMinimize(result);
  dfaFree(result);
  result = tmpM;

  if(_FANG_DFA_DEBUG){
    printf("Minimized:%d\n", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  free(exeps);
  free(to_states);
  free(statuces);
  free(arbitrary);
  return result;
}

/******************************************************************

Insertion:insert Mr at every state of M

I.e., Output M' so that L(M')={ w0c0w1c1w2c2w3 | c0c1c2 \in L(M), wi \in L(Mr) }

******************************************************************/
DFA *dfa_insert_M_dot(DFA *M, DFA* Mr, int var, int *indices, int replace_once)
{
  DFA *result = NULL;
  DFA *tmpM = NULL;
  DFA *tmpM2 = NULL;
  paths state_paths, pp;
  trace_descr tp;
  int i, j, k;
  char *exeps;
  int *to_states;
  long max_exeps;
  char *statuces;
  int len=var+1;
  int sink;

  //Get from Mr
  int nc;
  int numchars = count_accepted_chars(Mr);
  char* apath[numchars];
  set_accepted_chars(Mr, apath, numchars, var, indices);


  max_exeps=1<<len; //maybe exponential
  sink=find_sink(M);
  assert(sink>-1); //dfa_insert_M_dot

  DFABuilder *b = dfaSetup(M->ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)calloc((M->ns+1), sizeof(char));

  for (i = 0; i < M->ns; i++) {

    state_paths = pp = make_paths(M->bddm, M->q[i]);
    k=0;

    while (pp) {
      if(pp->to!=sink){
	to_states[k]=pp->to;
	for (j = 0; j < var; j++) {
	  //the following for loop can be avoided if the indices are in order
	  for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	  if (tp) {
	    if (tp->value) exeps[k*(len+1)+j]='1';
	    else exeps[k*(len+1)+j]='0';
	  }
	  else
	    exeps[k*(len+1)+j]='X';
	}
	exeps[k*(len+1)+j]='0';//old value
	exeps[k*(len+1)+len]='\0';
	k++;
      }
      pp = pp->next;
    }//end while

    if(i!=sink){
      for(nc = 0; nc<numchars; nc++){
	to_states[k]=i;
	for (j = 0; j < var; j++) exeps[k*(len+1)+j]=apath[nc][j];
	exeps[k*(len+1)+j]='1';
	exeps[k*(len+1)+len]='\0';
	k++;
      } // end for nc
    }
    dfaAllocExceptions(b, k);
    for(k--;k>=0;k--)
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);
  }

  statuces[M->ns]='\0';
  result = dfaBuild(b, statuces);

  if(_FANG_DFA_DEBUG){
    printf("Project the %d bit\n", i);
    printf("Original:%d", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  tmpM = dfaMinimize(result);
  dfaFree(result);
  result = tmpM;

  if(_FANG_DFA_DEBUG){
    printf("Minimized:%d\n", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }
  
  if (replace_once) {
    tmpM2 = dfa_ensure_one_direct_bar_transition(result, var, indices);
    dfaFree(result);
    result = tmpM2;
    if (_FANG_DFA_DEBUG) {
      printf("Ensure single transitions\n");
      dfaPrintGraphvizAsciiRange(result, var, indices, 0);
    }

    // First prepend all strings
    tmpM2 = dfa_star_M_star(Mr, var, indices);
    tmpM = tmpM2;

    // Create invalid solutions to be removed
    tmpM2 = dfa_create_M_with_extrabit(tmpM, var, indices);
    dfaFree(tmpM);
    tmpM = tmpM2;

    if (_FANG_DFA_DEBUG) {
      printf("Additional loops:\n");
      dfaPrintGraphvizAsciiRange(tmpM, var, indices, 1);
    }

    // Negate
    tmpM2 = dfa_negate(tmpM, var + 1, indices);
    dfaFree(tmpM);
    tmpM = tmpM2;

    if (_FANG_DFA_DEBUG) {
      printf("Negated:\n");
      dfaPrintVitals(tmpM);
      dfaPrintGraphvizAsciiRange(tmpM, var, indices, 1);
      printf("Result:\n");
      dfaPrintVitals(result);
      dfaPrintGraphvizAsciiRange(result, var, indices, 1);
    }

    // Remove the additional loops
    tmpM2 = dfa_intersect(result, tmpM);
    dfaFree(result);
    dfaFree(tmpM);
    result = tmpM2;
  }

  if(_FANG_DFA_DEBUG){
    printf("After ensuring bars\n", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  tmpM = dfaProject(result, (unsigned) len-1);
  dfaFree(result);
  result = tmpM;

  if(_FANG_DFA_DEBUG){
    printf("Projected:%d\n", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  tmpM = dfaMinimize(result);
  dfaFree(result);
  result = tmpM;

  free(exeps);
  free(to_states);
  free(statuces);

  //free(apath);
  for(i=0; i<numchars; i++) free(apath[i]);

  return result;

}// End dfa_insert_M_dot

DFA *dfa_insert_M_arbitrary_extrabit(DFA *M, DFA *Mr, int var, int *indices, int insert_everywhere)
{
  DFA *result = NULL;
  DFA *tmpM = NULL;

  paths state_paths, pp;
  trace_descr tp;
  int i, j, n, o, k;
  char *exeps;
  char *auxexeps;
  int *to_states;
  long max_exeps;
  char *statuces;
  int len=var+1;
  int ns, sink;

  int extrastates = Mr->ns; //duplicate states for each sharp pair

  //for out going information in Mr
  char ***binOfOut = (char ***) malloc((Mr->ns)*sizeof(char **)); // the string of the nonsink outgoing edge of each state
  int **toOfOut = (int **) malloc((Mr->ns)*sizeof(int *)); // the destination of the nonsink outgoing edge of each state
  int *numOfOut = (int *) malloc((Mr->ns)*sizeof(int)); // how many nonsink outgoing edges of each state
  int *numOfOutFinal = (int *) malloc((Mr->ns)*sizeof(int)); //how many final outgoing edges of each state

  initial_out_info(Mr, numOfOut, numOfOutFinal, binOfOut, toOfOut, var, 1, indices);

  max_exeps=1<<len; //maybe exponential
  sink = find_sink(M);
  if (sink < 0) sink = 0;
  ns = M->ns + (M->ns)*(extrastates);

  DFABuilder *b = dfaSetup(ns, len, indices);
  exeps=(char *)calloc(max_exeps*(len+1), sizeof(char)); //plus 1 for \0 end of the string
  to_states=(int *)calloc(max_exeps, sizeof(int));
  statuces=(char *)malloc((ns+1)*sizeof(char));
  auxexeps=(char *)malloc((len+1)*sizeof(char));

  // Loop over original states
  for (i = 0; i < M->ns; i++) {
    state_paths = pp = make_paths(M->bddm, M->q[i]);
    k=0;
    // add original paths
    while (pp) {
      if(pp->to!=sink){
	  to_states[k]=pp->to;
	  for (j = 0; j < var; j++) {
	    //the following for loop can be avoided if the indices are in order
	    for (tp = pp->trace; tp && (tp->index != indices[j]); tp =tp->next);

	    if (tp) {
              if (tp->value) {
                exeps[k*(len+1)+j]='1';
              } else {
                exeps[k*(len+1)+j]='0';
              }
	    } else {
	      exeps[k*(len+1)+j]='X';
            }
	  }
	  for (j = var; j < len; j++) {
	    exeps[k*(len+1)+j]='0'; //all original paths are set to zero
	  }
	  exeps[k*(len+1)+len]='\0';
	  k++;
      }
      pp = pp->next;
    } // end while

    // insert transitions to Mr initial states
    // Either everywhere OR at inital and accept states
    for (o=0; o<numOfOut[Mr->s]; o++) {
      to_states[k] = M->ns + i * (extrastates) + toOfOut[Mr->s][o]; // go to the next state of intial state of  Mr
      //printf("i: %d, k: %d to_states[k] = %d, M->ns = %d, extrastates = %d, o = %d, toOfOut = %d\n",
      //       i, k, to_states[k], M->ns, extrastates, o, toOfOut[Mr->s][o]);
      for (j = 0; j < var; j++) {
        exeps[k*(len+1)+j] = binOfOut[Mr->s][o][j];
        //printf("%c",  binOfOut[Mr->s][o][j]);
      }
      //printf("\n");
      exeps[k*(len+1)+j]='1'; // to distinguish the original path
      exeps[k*(len+1)+len]='\0';
      k++;
    }
 
    //print_transitions(i, to_states, k, exeps, len);
    dfaAllocExceptions(b, k);
    for(k--; k>=0; k--) {
      dfaStoreException(b, to_states[k],exeps+k*(len+1));
    }
    dfaStoreState(b, sink);

    if(M->f[i]==1)
      statuces[i]='+';
    else if(M->f[i]==-1)
      statuces[i]='-';
    else
      statuces[i]='0';

    kill_paths(state_paths);

  } // end of loop for original states

  assert(i==M->ns);

  // Add replace states
  k = M->ns;
  // For each original state
  for (n = 0; n < M->ns; n++) {
    // For each loop state which is being inserted
    for(i = 0; i < Mr->ns; i++) { // internal M (exclude the first and the last char)
      if(numOfOutFinal[i] == 0){
        dfaAllocExceptions(b, numOfOut[i]);
        for(o = 0; o < numOfOut[i]; o++){
          dfaStoreException(b, M->ns+n*(extrastates)+toOfOut[i][o], binOfOut[i][o]);
          //printf("Replace State: %d -> %d value: ", k, M->ns+n*(extrastates)+toOfOut[i][o]);
          //print_exep_value(binOfOut[i][o], len);
        }
        dfaStoreState(b, sink);
        k++;
      } else { //need to add aux edges back to sharp destination, for each edge leads to accepting state
        dfaAllocExceptions(b, numOfOut[i] + numOfOutFinal[i]);
        for(o = 0; o < numOfOut[i]; o++) {
          if (Mr->f[toOfOut[i][o]] == 1) { // except state: add auxiliary back edge to n
            for (j = 0; j < var; j++) auxexeps[j]=binOfOut[i][o][j];
            auxexeps[j]='1'; // Transition back is also dashed
            auxexeps[len]='\0';
            //printf("Back to original State: %d -> %d value: ", k, n);
            //print_exep_value(auxexeps, len);
            if ((insert_everywhere) || (M->f[n] == 1) || (n == sink)) {
              // Create a loop back to the original state
              dfaStoreException(b, n, auxexeps);
            } else {
              // Create a loop back to the initial state
              dfaStoreException(b, 0, auxexeps);
            }
          }
          // Transistions which are not accept states
          dfaStoreException(b, M->ns+n*(extrastates)+toOfOut[i][o], binOfOut[i][o]);
          //printf("Internal State: %d -> %d value: ", k, M->ns+n*(extrastates)+toOfOut[i][o]);
          //print_exep_value(binOfOut[i][o], len);
        }
        dfaStoreState(b, sink);
        k++;
      }
    }//end for Mr internal
  }//end for n

  for(i=M->ns; i<ns; i++) statuces[i]='-';

  statuces[ns]='\0';
  result = dfaBuild(b, statuces);

  if(_FANG_DFA_DEBUG){
    printf("Project the %d bit\n", i);
    printf("Original:%d", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  tmpM = dfaMinimize(result);
  dfaFree(result);
  result = tmpM;

  if(_FANG_DFA_DEBUG){
    printf("Minimized:%d\n", i);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  free(exeps);
  free(auxexeps);
  free(to_states);
  free(statuces);

  for(i=0; i<Mr->ns; i++){
    if(binOfOut[i]!=NULL) free(binOfOut[i]);
    if(toOfOut[i]!=NULL) free(toOfOut[i]);
  }

  free(binOfOut);
  free(toOfOut);

  free(numOfOut);
  free(numOfOutFinal);

  return result;
}
//#define _FANG_DFA_DEBUG 1
DFA *dfa_insert_M_arbitrary(DFA *M, DFA *Mr, int var, int *indices, int replace_once)
{
  DFA *result = NULL;
  DFA *tmpM = NULL;
  DFA *tmpM2 = NULL;
  DFA *tmpM3 = Mr; //dfa_construct_string("123", var, indices);

  if (_FANG_DFA_DEBUG) {
    printf("M:\n");
    dfaPrintGraphvizAsciiRange(M, var, indices, 0);
  }
  if (_FANG_DFA_DEBUG) {
    printf("Mr:\n");
    dfaPrintGraphvizAsciiRange(Mr, var, indices, 0);
  }

  result = dfa_insert_M_arbitrary_extrabit(M, tmpM3, var, indices, 1);
  if (_FANG_DFA_DEBUG) {
    printf("M: insert loops\n");
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  // First prepend all strings
  tmpM2 = dfa_star_M_star(Mr, var, indices);
  dfaFree(tmpM);
  tmpM = tmpM2;

  if (_FANG_DFA_DEBUG) {
    printf("*M*\n");
    dfaPrintGraphvizAsciiRange(tmpM, var, indices, 1);
  }

  if (replace_once) {
    // For single replace cases, only solutions where zero or one
    // replace transitions occur are valid. More than one occurance
    // of Mr will not be replaced.
    tmpM2 = dfa_ensure_one_bar_transition(result, var, indices);
    dfaFree(result);
    result = tmpM2;
    if (_FANG_DFA_DEBUG) {
      printf("Ensure single transitions\n");
      dfaPrintGraphvizAsciiRange(result, var, indices, 0);
    }

    tmpM2 = dfa_create_M_with_extrabit(tmpM, var, indices);
    dfaFree(tmpM);
    tmpM = tmpM2;

  } else {

    // If the replace acts multiple times, we need to remove certain cases
    // For example:
    // Operation: replace(/script/, "")
    // Post Image: "script"
    // will give "scriptscript" as a possible solution here.
    // Therefore remove any replacement loop insertions which appear
    // outside of the Mr states.
    
    // Create loops outside of the replacement string
    // e.g. scriptscript
    tmpM2 = dfa_insert_M_arbitrary_extrabit(tmpM, tmpM3, var, indices, 0);
    dfaFree(tmpM);
    tmpM = tmpM2;
  
  }

  if (_FANG_DFA_DEBUG) {
    printf("With loops\n");
    dfaPrintGraphvizAsciiRange(tmpM, var, indices, 1);
  }

  // Negate
  tmpM2 = dfa_negate(tmpM, var + 1, indices);
  dfaFree(tmpM);
  tmpM = tmpM2;

  if (_FANG_DFA_DEBUG) {
    printf("Negated:\n");
    dfaPrintGraphvizAsciiRange(tmpM, var, indices, 0);
  }

  // Remove the additional loops
  tmpM2 = dfa_intersect(result, tmpM);
  dfaFree(result);
  dfaFree(tmpM);
  tmpM = tmpM2;

  // Minimize
  tmpM2 = dfaMinimize(tmpM);
  dfaFree(tmpM);
  tmpM = tmpM2;

  if (_FANG_DFA_DEBUG) {
    printf("Ensure bar transition: %d\n", M->ns);
    dfaPrintVitals(tmpM);
    dfaPrintGraphvizAsciiRange(tmpM, var, indices, 0);
  }

   // Additional checks here
  //tmpM2 = dfaProject(tmpM, (unsigned) var);
  tmpM2 = dfaProjectWithSingletonFallback(tmpM, var + 1, indices, var);
  dfaFree(tmpM);
  tmpM = tmpM2;

  if(_FANG_DFA_DEBUG){
    printf("Projected: %d bit", var);
    dfaPrintVitals(tmpM);
    dfaPrintGraphvizAsciiRange(tmpM, var, indices, 0);
  }

  tmpM2 = dfaMinimize(tmpM);
  dfaFree(tmpM);
  result = tmpM2;

  if(_FANG_DFA_DEBUG){
    printf("Minimized:after %d bit", var);
    dfaPrintVitals(result);
    dfaPrintGraphvizAsciiRange(result, var, indices, 0);
  }

  return result;
}//End dfa_insert_M_arbitrary

DFA *dfa_insert_everywhere(DFA *M, DFA* Mr, int var, int *indices, int replace_once)
{
  DFA *result1 = NULL;
  DFA *result2 = NULL;
  DFA *result = NULL;
  DFA *tmp = NULL;
  DFA *tmp2 = NULL;

  // This is handled in two steps:
  //   1) Subset of all strings in M which are single chars
  //   2) Subset of strings in M which are 2 or more chars long

  // Single chars

  // dfaDot accepts one arbitrary character
  tmp = dfaDot(var, indices);
  tmp2 = dfa_intersect(Mr, tmp);
  dfaFree(tmp);
  tmp = tmp2;
  // tmp is now the subset of all single characters in the replacement

  if (!check_emptiness(tmp, var, indices)) {
      result = dfa_insert_M_dot(M, tmp, var, indices, replace_once);
  }
  dfaFree(tmp);

  // 2 or more char strings
  // Now create set of strings with length 2 or longer
  tmp = dfaSigmaC1toC2(2, -1, var, indices);
  tmp2 = dfa_intersect(Mr, tmp);
  dfaFree(tmp);
  tmp = tmp2;

  if (!check_emptiness(tmp, var, indices)) {

    // Try inserting the 2-char replace string everywhere
    result2 = dfa_insert_M_arbitrary(M, tmp, var, indices, replace_once);

    // Combine if there was a result from single chars
    if (result) {
      result1 = result;
      result = dfa_union(result1, result2);
      dfaFree(result1);
      dfaFree(result2);
    } else {
      result = result2;
    }
  }
  dfaFree(tmp);

  return result;
} //END dfa_insert_everywhere



