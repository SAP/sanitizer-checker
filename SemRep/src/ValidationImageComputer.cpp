#include "ValidationImageComputer.hpp"

ValidationImageComputer::ValidationImageComputer() : ImageComputer() {

}


/*******************************************************************************************************************************/
/********* VALIDATION PATCH EXTRACTION PHASE METHODS ***************************************************************************/
/*******************************************************************************************************************************/

/**
 *
 * Initial Pre-Image computation for validation function computation
 * 1- Start from first __vlab_restrict function
 * 2- Union negation of all restrict functions, (in the case where third parameter of restrict function is true, you do not need to negate since it is already negated)
 * 3- If there are some other ops after first restrict, do pre-image computation for them and intersect result.
 */
AnalysisResult ValidationImageComputer::doBackwardAnalysis_ValidationCase(DepGraph& origDepGraph, DepGraph& depGraph, StrangerAutomaton* initialAuto) {

    queue<DepGraphNode*> process_queue;
    set<DepGraphNode*> visited;
    set<int> processed_SCCs;

    bool has_validation = false;

    AnalysisResult bwValidationPatchResult;
    string message = "there is no validation function!!!";

    // initialize root node
    bwValidationPatchResult[depGraph.getRoot()->getID()] = initialAuto;


    process_queue.push(depGraph.getRoot());
    while (!process_queue.empty()) {

        DepGraphNode *curr = process_queue.front();

        if (!has_validation) {
            if (dynamic_cast< DepGraphNormalNode*>(curr) || dynamic_cast< DepGraphUninitNode*>(curr) || dynamic_cast< DepGraphOpNode*>(curr)) {
                if (dynamic_cast< DepGraphOpNode*>(curr) ) {
                    DepGraphOpNode* op = dynamic_cast< DepGraphOpNode*>(curr);
                    if (op->getName().find("__vlab_restrict") != string::npos) {
                        has_validation = true;
                        message = "validation function found!!!";
                    }
                }

            } else { throw StrangerStringAnalysisException("cannot handle node type"); }

        } else {
            if (depGraph.isSCCElement(curr)) { // handle cycles
                // do not compute a scc more than once
                auto isNotProcessed = processed_SCCs.insert(depGraph.getSCCID(curr));
                if (isNotProcessed.second) {
                    doPreImageComputationForSCC_ValidationCase(origDepGraph, curr, bwValidationPatchResult);
                }
            } else {
                doPreImageComputation_ValidationCase(origDepGraph, curr, bwValidationPatchResult);
            }

        }

        process_queue.pop();

        NodesList successors = depGraph.getSuccessors(curr);
        if (!successors.empty()) {
            for (auto succ_node : successors) {
                auto isNotVisited = visited.insert(succ_node);
                if (isNotVisited.second) {
                    bwValidationPatchResult[succ_node->getID()] = initialAuto;
                    process_queue.push(succ_node);
                }
            }
        }
    }

    cout << "\t" << message << endl;
    return bwValidationPatchResult;
}


/**
 * Do the computation for a node
 * Get the predecessors, and compute the pre-image based on those
 */
void ValidationImageComputer::doPreImageComputation_ValidationCase(DepGraph& origDepGraph, DepGraphNode* node, AnalysisResult& bwAnalysisResult) {

    NodesList predecessors = origDepGraph.getPredecessors(node);
    NodesList successors = origDepGraph.getSuccessors(node);
    DepGraphNormalNode* normalNode = nullptr;
    StrangerAutomaton *newAuto = nullptr, *tempAuto = nullptr;

    if (dynamic_cast< DepGraphNormalNode*>(node) || dynamic_cast< DepGraphUninitNode*>(node) || dynamic_cast< DepGraphOpNode*>(node)) {
        if (predecessors.empty()) {
            // root is already initialized
            newAuto = bwAnalysisResult[node->getID()];
        } else if (successors.empty() && (normalNode = dynamic_cast< DepGraphNormalNode*>(node))) {
            newAuto = ImageComputer::getLiteralorConstantNodeAuto(normalNode, false);
        } else {

            for (auto pred_node : predecessors) {
                StrangerAutomaton* predAuto = nullptr;
                if (pred_node == node) {
                    // ignore simple self loop (check correctness)
                    continue;
                } else if (dynamic_cast< DepGraphNormalNode*>(pred_node)) {
                    predAuto = bwAnalysisResult[pred_node->getID()];
                } else if (dynamic_cast< DepGraphOpNode*>(pred_node)) {
                    predAuto = makePreImageForOpChild_ValidationCase(origDepGraph, dynamic_cast< DepGraphOpNode*>(pred_node), node, bwAnalysisResult);
                }

                if (predAuto == nullptr) {
                    continue;
                }

                if (newAuto == nullptr) {
                    newAuto = predAuto->clone(node->getID());
                } else {
                    tempAuto = newAuto;
                    newAuto = newAuto->union_(predAuto, node->getID());
                    delete tempAuto;
                    delete predAuto;
                }
            }

        }

    } else {
        throw StrangerStringAnalysisException("SNH: cannot handle node type: doBackwardNodeComputation_ValidationPhase()");
    }

    if (newAuto == nullptr) {
        throw StrangerStringAnalysisException("SNH: pre-image is NULL: doBackwardNodeComputation_ValidationPhase()");
    }
    bwAnalysisResult[node->getID()] = newAuto;

}

/**
 * Pre Image computation for cycles (loops) during validation phase
 */
void ValidationImageComputer::doPreImageComputationForSCC_ValidationCase(DepGraph& origDepGraph, DepGraphNode* node, AnalysisResult& bwAnalysisResult) {
    // TODO add to command line options as an optional parameter
    int precise_widening_limit = 5;
    int coarse_widening_limit = 20;

    int scc_id = origDepGraph.getSCCID(node);

    map<int, int> visit_count;
    NodesList current_scc_nodes = origDepGraph.getSCCNodes(scc_id);

    queue<DepGraphNode*> worklist;
    set<DepGraphNode*> visited;

    // initialize all scc_nodes to phi
    for (auto& scc_node : current_scc_nodes) {
        bwAnalysisResult[scc_node->getID()] = StrangerAutomaton::makePhi(scc_node->getID());
        visit_count[scc_node->getID()] = 0;
    }

    // add the predecessors to the worklist
    for ( auto pred_node : origDepGraph.getPredecessors(node)) {
        worklist.push(pred_node);
        visited.insert(pred_node);
    }

    int iteration = 0;

    do {
        DepGraphNode* curr_node = worklist.front();
        worklist.pop();
        // calculate the values for predecessors (in a depgraph predecessors are children during forward analysis)
        for (auto succ_node : origDepGraph.getSuccessors(curr_node)) {
            // ignore nodes that are not part of the current scc
            if (!origDepGraph.isSCCElement(succ_node) || origDepGraph.getSCCID(succ_node) != scc_id)
                continue;

            StrangerAutomaton* prev_auto = bwAnalysisResult[succ_node->getID()]; // may need clone
            StrangerAutomaton* tmp_auto = nullptr;
            StrangerAutomaton* new_auto = nullptr;

            if (dynamic_cast<DepGraphNormalNode*>(curr_node) != nullptr) {
                tmp_auto = bwAnalysisResult[curr_node->getID()]; // may need clone
            } else if (dynamic_cast<DepGraphOpNode*>(curr_node) != nullptr) {
                tmp_auto = makePreImageForOpChild_ValidationCase(origDepGraph, dynamic_cast< DepGraphOpNode*>(curr_node), succ_node, bwAnalysisResult);
            } else {
                throw StrangerStringAnalysisException(stringbuilder() << "Node cannot be an element of SCC component!, node id: " << node->getID());
            }

            if (tmp_auto == nullptr) {
                throw StrangerStringAnalysisException(stringbuilder() << "Could not calculate the corresponding automaton!, node id: " << node->getID());
            }

            new_auto = tmp_auto->union_(prev_auto, succ_node->getID());

            int new_visit_count = visit_count[succ_node->getID()] + 1;
            if (new_visit_count > iteration)
                iteration = new_visit_count;

            // decide whether to do widening operations
            if (new_visit_count > coarse_widening_limit) {
                new_auto = prev_auto->coarseWiden(new_auto, succ_node->getID());
            } else if (new_visit_count > precise_widening_limit) {
                new_auto = prev_auto->preciseWiden(new_auto, succ_node->getID());
            }

            if (!new_auto->checkInclusion(prev_auto, new_auto->getID(), prev_auto->getID())) {
                auto isVisited = visited.insert(succ_node);
                if (isVisited.second) {
                    worklist.push(succ_node);
                }

                bwAnalysisResult[succ_node->getID()] = new_auto;
                visit_count[succ_node->getID()] = new_visit_count;
            }
        }

    } while( !worklist.empty() && iteration < 30000 );
}


/**
 * Do pre-image computation for validation patch
 */
StrangerAutomaton* ValidationImageComputer::makePreImageForOpChild_ValidationCase(DepGraph& depGraph, DepGraphOpNode* opNode,
                                                                        DepGraphNode* childNode, AnalysisResult& bwAnalysisResult) {

    StrangerAutomaton* retMe = nullptr;
    NodesList successors = depGraph.getSuccessors(opNode);
    StrangerAutomaton* opAuto = bwAnalysisResult[opNode->getID()];
    string opName = opNode->getName();

    // __vlab_restrict
    if (opName.find("__vlab_restrict") != string::npos) {
        boost::posix_time::ptime start_time = perfInfo->current_time();
        if (successors.size() != 3) {
            throw StrangerStringAnalysisException(stringbuilder() << "__vlab_restrict invalid number of arguments");
        }

        DepGraphNode* subjectNode = successors[1];
        DepGraphNode* patternNode = successors[0];
        DepGraphNode* complementNode = successors[2];

        if (childNode->equals(subjectNode)) {
            //TODO handle general case for patternAuto and complementString
            StrangerAutomaton* patternAuto = ImageComputer::getLiteralorConstantNodeAuto(patternNode, true);
            // Union __vlab_restricts considering complement parameter
            string complementString = ImageComputer::getLiteralOrConstantValue(complementNode);
            if (complementString.find("false") != string::npos || complementString.find("FALSE") != string::npos) {
                StrangerAutomaton* complementAuto = patternAuto->complement(patternNode->getID());
                retMe = opAuto->union_(complementAuto, childNode->getID());
                delete complementAuto;
            } else {
                retMe = opAuto->union_(patternAuto, childNode->getID());
            }

            perfInfo->pre_vlab_restrict_total_time += perfInfo->current_time() - start_time;
            perfInfo->number_of_pre_vlab_restrict++;

        } else {
            throw StrangerStringAnalysisException(stringbuilder() << "child node (" << childNode->getID() << ") of __vlab_restrict (" << opNode->getID() << ") is not in backward path");
        }
    }  else if (opName == ".") {
        // CONCAT
        throw StrangerStringAnalysisException( "concats are not handled here until we really need");
    } else if (opName == "addslashes") {
        // only has one parameter ==>  string addslashes  ( string $str  )
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = StrangerAutomaton::addslashes(sigmaStar, opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = StrangerAutomaton::pre_addslashes(intersection, childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    } else if (opName == "trim" ) {
        // only has one parameter ==>  string trim  ( string $str  )
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = sigmaStar->trimSpaces(opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = intersection->preTrimSpaces(childNode->getID());

        delete sigmaStar;
        delete forward;
        delete intersection;

    } else if (opName == "ltrim" ) {
        // only has one parameter ==>  string trim  ( string $str  )
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = sigmaStar->trimSpacesLeft(opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = intersection->preTrimSpacesLeft(childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    }  else if (opName == "rtrim" ) {
        // only has one parameter ==>  string trim  ( string $str  )
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = sigmaStar->trimSpacesRight(opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = intersection->preTrimSpacesRigth(childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    } else if (opName == "strtoupper" ) {
        // only has one parameter ==> string strtoupper  ( string $str  )
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = sigmaStar->toUpperCase(opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = intersection->preToUpperCase(childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    }  else if (opName == "strtolower" ) {
        // only has one parameter ==> string strtolower  ( string $str  )
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = sigmaStar->toLowerCase(opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = intersection->preToLowerCase(childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    } else if (opName == "mysql_escape_string") {
        // has one parameter
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = StrangerAutomaton::mysql_escape_string(sigmaStar, opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = StrangerAutomaton::pre_mysql_escape_string(intersection, childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    } else if (opName == "mysql_real_escape_string") {
        // has one parameter
        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
        StrangerAutomaton* forward = StrangerAutomaton::mysql_real_escape_string(sigmaStar, opNode->getID());
        StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
        retMe = StrangerAutomaton::pre_mysql_real_escape_string(intersection, childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    } else if (opName == "htmlspecialchars") {
        if (childNode->equals(successors[0])) {
            string flagString = "ENT_COMPAT";
            if (successors.size() > 1) {
                flagString = ImageComputer::getLiteralOrConstantValue(successors[1]);
            }
            StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(opNode->getID());
            StrangerAutomaton* forward = StrangerAutomaton::htmlSpecialChars(sigmaStar, flagString, opNode->getID());
            StrangerAutomaton* intersection = opAuto->intersect(forward, childNode->getID());
            retMe = StrangerAutomaton::preHtmlSpecialChars(intersection, flagString, childNode->getID());
            delete sigmaStar;
            delete forward;
            delete intersection;
        } else {
            throw StrangerStringAnalysisException(stringbuilder() << "SNH: child node (" << childNode->getID() << ") of htmlspecialchars (" << opNode->getID() << ") is not in backward path,\ncheck implementation");
        }

    } else if (opName == "preg_replace" || opName == "ereg_replace" || opName == "str_replace") {

        if (successors.size() != 3) {
            throw StrangerStringAnalysisException(stringbuilder() << "replace invalid number of arguments");
        }

        DepGraphNode* subjectNode = successors[2];
        DepGraphNode* patternNode = successors[0];
        DepGraphNode* replaceNode = successors[1];

        StrangerAutomaton* subjectAuto = opAuto;

        if (childNode->equals(subjectNode)) {

            AnalysisResult analysisResult;
            doForwardAnalysis_GeneralCase(depGraph, patternNode, analysisResult);
            doForwardAnalysis_GeneralCase(depGraph, replaceNode, analysisResult);

            StrangerAutomaton* patternAuto = analysisResult[patternNode->getID()];
            StrangerAutomaton* replaceAuto = analysisResult[replaceNode->getID()];

            StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(subjectAuto->getID());
            StrangerAutomaton* forward = StrangerAutomaton::general_replace(patternAuto, replaceAuto, sigmaStar, subjectAuto->getID());
            StrangerAutomaton* intersection = subjectAuto->intersect(forward, childNode->getID());
            string replaceStr = replaceAuto->getStr();

            // checking for special case where a character is escaped by another character
            if (patternAuto->isSingleton()) {
                string patternStr = patternAuto->generateSatisfyingExample();
                if ( replaceStr.length() == 2 && patternStr.length() == 1 && patternStr[0] == replaceStr[1]) {
                    retMe = StrangerAutomaton::general_replace(replaceAuto, patternAuto, intersection, childNode->getID());
                } else {
                    retMe = intersection->preReplace(patternAuto, replaceStr, childNode->getID());
                }
            } else {
                retMe = intersection->preReplace(patternAuto, replaceStr, childNode->getID());
            }

            delete sigmaStar;
            delete forward;
            delete intersection;

        } else {
            throw StrangerStringAnalysisException(stringbuilder() << "SNH: child node (" << childNode->getID() << ") of preg_replace (" << opNode->getID() << ") is not in backward path,\ncheck implementation: "
                                                                                                                                                              "makeBackwardAutoForOpChild_ValidationPhase()");
        }
    }  else if (opName == "substr"){

        if (successors.size() != 3) {
            throw StrangerStringAnalysisException(stringbuilder() << "SNH: substr invalid number of arguments: "
                                                                     "makeForwardAutoForOp_RegularPhase()");
        }

        DepGraphNode* startNode = successors[1];
        DepGraphNode* lengthNode = successors[2];

        StrangerAutomaton* subjectAuto = opAuto;

        AnalysisResult analysisResult;
        doForwardAnalysis_GeneralCase(depGraph, startNode, analysisResult);
        doForwardAnalysis_GeneralCase(depGraph, lengthNode, analysisResult);

        string startValue = analysisResult[startNode->getID()]->getStr();
        int start = stoi(startValue);
        string lengthValue = analysisResult[lengthNode->getID()]->getStr();
        int length = stoi(lengthValue);

        StrangerAutomaton* sigmaStar = StrangerAutomaton::makeAnyString(subjectAuto->getID());
        StrangerAutomaton* forward = sigmaStar->substr(start, length, subjectAuto->getID());
        StrangerAutomaton* intersection = subjectAuto->intersect(forward, childNode->getID());
        retMe = intersection->pre_substr(start, length, childNode->getID());
        delete sigmaStar;
        delete forward;
        delete intersection;

    } else if (opName == "") {

    } else if (opName == "md5") {
        retMe = StrangerAutomaton::makeAnyString(childNode->getID());
    } else {
        throw StrangerStringAnalysisException( "Not implemented yet for validation phase: " + opName);
    }

//	cout << endl << "auto after each operation : " << opName << endl << endl;
//	retMe->toDotAscii(0);
//	cout << endl << endl;
    return retMe;

}
