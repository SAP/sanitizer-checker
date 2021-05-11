/*
 * ImageComputer.cpp
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

#include "ImageComputer.hpp"
#include "exceptions/StrangerException.hpp"

using namespace std;

ImageComputer::ImageComputer()
    : uninit_node_default_initialization(StrangerAutomaton::makePhi())
    , m_doConcats(true)
    , m_doSubstr(true)
{
}

ImageComputer::ImageComputer(bool doConcats, bool doSubstr)
    : uninit_node_default_initialization(StrangerAutomaton::makePhi())
    , m_doConcats(doConcats)
    , m_doSubstr(doSubstr)
{
}

ImageComputer::~ImageComputer() {
    delete uninit_node_default_initialization;
}

/**
 * 1- prints the dot format for result automatons
 * 2- prints the MONA internal states for result automatons
 */




PerfInfo* ImageComputer::perfInfo = &PerfInfo::getInstance();

/*******************************************************************************************************************************/
/*********** SANITIZATION PATCH EXTRACTION METHODS *****************************************************************************/
/*******************************************************************************************************************************/

/**
 *
 */
void ImageComputer::doForwardAnalysis_SingleInput(DepGraph& origDepGraph,  DepGraphUninitNode* inputNode, AnalysisResult& analysisResult) {
	DepGraph inputDepGraph = origDepGraph.getInputRelevantGraph(inputNode);
	doForwardAnalysis_SingleInput(origDepGraph, inputDepGraph, analysisResult);
}

/**
 * Do forward analysis from an input node to a sink
 *
 */
void ImageComputer::doForwardAnalysis_SingleInput(
		DepGraph& origDepGraph, DepGraph& inputDepGraph, AnalysisResult& analysisResult) {

	stack<DepGraphNode*> process_stack;
	set<DepGraphNode*> visited;

	process_stack.push( inputDepGraph.getRoot() );
	while (!process_stack.empty()) {

		DepGraphNode *curr = process_stack.top();
		auto isNotVisited = visited.insert(curr);
		NodesList successors = inputDepGraph.getSuccessors(curr);

		if (!successors.empty() && isNotVisited.second) {
			for (NodesListConstReverseIterator it = successors.rbegin(); it != successors.rend(); it++) {
				if (analysisResult.find((*it)->getID()) == analysisResult.end()) {
					process_stack.push(*it);
				}
			}
		} else {
			doPostImageComputation_SingleInput(origDepGraph, inputDepGraph, curr, analysisResult);
			process_stack.pop();
		}
	}

	return;
}


void ImageComputer::doPostImageComputation_SingleInput(
    DepGraph& origDepGraph, DepGraph& inputDepGraph, DepGraphNode* node, AnalysisResult& analysisResult) {

    NodesList successors = origDepGraph.getSuccessors(node);

    StrangerAutomaton* newAuto = nullptr;
    DepGraphNormalNode* normalnode;
    DepGraphOpNode* opNode;
    DepGraphUninitNode* uninitNode;
    if ((normalnode = dynamic_cast<DepGraphNormalNode*>(node)) != nullptr) {
    	if (successors.empty()) {
            newAuto = getLiteralorConstantNodeAuto(normalnode, false);
    	} else {
            // an interior node, union of all its successors
            for (auto succ_node : successors) {
                if (succ_node->getID() == node->getID() ) {
                    // avoid simple loops
                    continue;
                }
                // explore new paths
                if (analysisResult.find(succ_node->getID()) == analysisResult.end()) {
                    cout << "exploring succ_node: " << succ_node->getID() << endl;
                    doForwardAnalysis_GeneralCase(origDepGraph, succ_node, analysisResult);
                }

                const StrangerAutomaton *succAuto = analysisResult.get(succ_node->getID());
                if (newAuto == nullptr) {
                    newAuto = succAuto->clone(node->getID());
                } else {
                    StrangerAutomaton* temp = newAuto;
                    newAuto = newAuto->union_(succAuto, node->getID());
                    delete temp;
                }
            }
    	}

    } else if ((opNode = dynamic_cast<DepGraphOpNode*>(node)) != nullptr) {
        newAuto = makePostImageForOp_GeneralCase(origDepGraph, opNode, analysisResult);
    } else if ((uninitNode = dynamic_cast<DepGraphUninitNode*>(node)) != nullptr) {
    	// input node that we are interested in should have been initialized already
    	if (analysisResult.find(node->getID()) == analysisResult.end()){
            throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "input node id(" << uninitNode->getID() << ") automaton must be initizalized before analysis begins!");
    	}
    	newAuto = analysisResult.get(node->getID())->clone();
    } else {
    	throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Cannot figure out node type!, node id: " << node->getID());
    }

    if (newAuto == nullptr) {
    	throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Forward automaton cannot be computed!, node id: " << node->getID());
    }

    analysisResult.set(node->getID(), newAuto);
}

/*******************************************************************************************************************************/
/*********** REGULAR BACKWARD IMAGE COMPUTATION METHODS *************************************************************************/
/*******************************************************************************************************************************/

/**
 * Giving an initial auto for root, using the results from previous forward analysis,
 * do a backward analysis. Second parameter is the input relevant depgraph.
 *
 */
AnalysisResult ImageComputer::doBackwardAnalysis_GeneralCase(
    const DepGraph& origDepGraph, const DepGraph& depGraph, const StrangerAutomaton* initialAuto, const AnalysisResult& fwAnalysisResult) {

    queue<const DepGraphNode*> process_queue;
    set<const DepGraphNode*> visited;
    set<int> processed_SCCs;

    AnalysisResult bwAnalysisResult;

    try {
        // initialize root node
        bwAnalysisResult.set(depGraph.getRoot()->getID(), initialAuto->clone());

        process_queue.push(depGraph.getRoot());
        while (!process_queue.empty()) {

            const DepGraphNode *curr = process_queue.front();
            if (depGraph.isSCCElement(curr)) { // handle cycles
                // do not compute a scc more than once
                auto isNotProcessed = processed_SCCs.insert(depGraph.getSCCID(curr));
                if (isNotProcessed.second) {
                    doPreImageComputationForSCC_GeneralCase(origDepGraph, curr, bwAnalysisResult, fwAnalysisResult);
                }
            } else {
                doPreImageComputation_GeneralCase(origDepGraph, curr, bwAnalysisResult, fwAnalysisResult);
            }

            process_queue.pop();

            NodesList successors = depGraph.getSuccessors(curr);
            if (!successors.empty()) {
                for (auto succ_node : successors) {
                    auto isNotVisited = visited.insert(succ_node);
                    if (isNotVisited.second) {
                        process_queue.push(succ_node);
                    }
                }
            }
        }
    } catch (...) {
        throw;
    }
    
    return bwAnalysisResult;
}

/**
 *
 */
void ImageComputer::doPreImageComputation_GeneralCase(
    const DepGraph& origDepGraph, const DepGraphNode* node,
    AnalysisResult& bwAnalysisResult, const AnalysisResult& fwAnalysisResult) {

	NodesList predecessors = origDepGraph.getPredecessors(node);
	NodesList successors = origDepGraph.getSuccessors(node);
	const DepGraphNormalNode* normalNode = nullptr;
	StrangerAutomaton *newAuto = nullptr, *tempAuto = nullptr;

	if (dynamic_cast<const DepGraphNormalNode*>(node) || dynamic_cast<const DepGraphUninitNode*>(node) || dynamic_cast<const DepGraphOpNode*>(node)) {
		if (predecessors.empty()) {
			// root is already initialized
                    newAuto = bwAnalysisResult.get(node->getID())->clone();
		} else if (successors.empty() && (normalNode = dynamic_cast<const DepGraphNormalNode*>(node))) {
                        newAuto = getLiteralorConstantNodeAuto(normalNode, false);
		} else {
			// the automa is union of all prodecessors and interstect with forward analysis result
                        const StrangerAutomaton* forwardAuto = fwAnalysisResult.find(node->getID())->second;
			for (auto pred_node : predecessors) {
				StrangerAutomaton* predAuto = nullptr;
				if (pred_node == node) {
					// ignore simple self loop (check correctness)
					continue;
				} else if (dynamic_cast<const DepGraphNormalNode*>(pred_node)) {
                                    predAuto = bwAnalysisResult.get(pred_node->getID())->clone(node->getID());
				} else if (dynamic_cast<const DepGraphOpNode*>(pred_node)) {
                                    predAuto = makePreImageForOpChild_GeneralCase(origDepGraph,dynamic_cast<const DepGraphOpNode*>(pred_node), node,
                                                                                  bwAnalysisResult, fwAnalysisResult);
			}

				if (predAuto == nullptr) {
					continue;
				}

				if (newAuto == nullptr) {
					newAuto = predAuto->clone(node->getID());
                                        delete predAuto;
				} else {
					tempAuto = newAuto;
					newAuto = newAuto->union_(predAuto, node->getID());
					delete tempAuto;
					delete predAuto;
				}
			}

			if (newAuto == nullptr) {
				throw StrangerException(AnalysisError::MalformedDepgraph, "Cannot calculate backward auto, fix me\nndoBackwardNodeComputation_RegularPhase()");
			}

			tempAuto = newAuto;
			newAuto = forwardAuto->intersect(newAuto, node->getID());
			delete tempAuto;
		}

	} else {
		throw StrangerException(AnalysisError::MalformedDepgraph, "SNH: cannot handle node type:\ndoBackwardNodeComputation_RegularPhase()");
	}


	if (newAuto == nullptr) {
		throw StrangerException(AnalysisError::MalformedDepgraph, "SNH: pre-image is NULL:\ndoBackwardNodeComputation_RegularPhase()");
	}

	bwAnalysisResult.set(node->getID(), newAuto);
}

/**
 * Pre Image Computation for cycles (loops)
 */
void ImageComputer::doPreImageComputationForSCC_GeneralCase(const DepGraph& origDepGraph, const DepGraphNode* node, AnalysisResult& bwAnalysisResult, const AnalysisResult& fwAnalysisResult) {
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
            bwAnalysisResult.set(scc_node->getID(), StrangerAutomaton::makePhi(scc_node->getID()));
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

			const StrangerAutomaton* forward_auto = fwAnalysisResult.find(succ_node->getID())->second;
			const StrangerAutomaton* prev_auto = bwAnalysisResult.get(succ_node->getID());
			StrangerAutomaton* tmp_auto = nullptr;
			StrangerAutomaton* new_auto = nullptr;

			if (dynamic_cast<const DepGraphNormalNode*>(curr_node) != nullptr) {
                            tmp_auto = bwAnalysisResult.get(curr_node->getID())->clone(); // may need clone
			} else if (dynamic_cast<const DepGraphOpNode*>(curr_node) != nullptr) {
				tmp_auto = makePreImageForOpChild_GeneralCase(origDepGraph, dynamic_cast<const DepGraphOpNode*>(curr_node), succ_node,
						bwAnalysisResult, fwAnalysisResult);
			} else {
				throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Node cannot be an element of SCC component!, node id: " << node->getID());
			}

			if (tmp_auto == nullptr) {
				throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Could not calculate the corresponding automaton!, node id: " << node->getID());
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

				tmp_auto = new_auto;
				new_auto = forward_auto->intersect(new_auto, node->getID());
				delete tmp_auto;

				bwAnalysisResult.set(succ_node->getID(), new_auto);
				visit_count[succ_node->getID()] = new_visit_count;
			}
		}

	} while( !worklist.empty() && iteration < 30000 );
}

/**
 *
 */
StrangerAutomaton* ImageComputer::makePreImageForOpChild_GeneralCase(
    const DepGraph& depGraph, const DepGraphOpNode* opNode, const DepGraphNode* childNode,
    AnalysisResult& bwAnalysisResult, const AnalysisResult& fwAnalysisResult) {

	StrangerAutomaton* retMe = nullptr;
	NodesList successors = depGraph.getSuccessors(opNode);
	const StrangerAutomaton* opAuto = bwAnalysisResult.get(opNode->getID());
	string opName = opNode->getName();



	// __vlab_restrict
	if (opName.find("__vlab_restrict") != string::npos) {
		boost::posix_time::ptime start_time = perfInfo->current_time();
		if (successors.size() != 3) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "__vlab_restrict invalid number of arguments");
		}

		DepGraphNode* subjectNode = successors[1];
		DepGraphNode* patternNode = successors[0];
		DepGraphNode* complementNode = successors[2];

		if (childNode->equals(subjectNode)){
			retMe = opAuto->clone(childNode->getID());
		} else if (childNode->equals(patternNode) || childNode->equals(complementNode)) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "child node (" << childNode->getID() << ") of __vlab_restrict (" << opNode->getID() << ") should not be on the backward path");
		} else {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "child node (" << childNode->getID() << ") of __vlab_restrict (" << opNode->getID() << ") is not in backward path");
		}
		perfInfo->pre_vlab_restrict_total_time += perfInfo->current_time() - start_time;
		perfInfo->number_of_pre_vlab_restrict++;

	} else if ((opName == ".") || (opName == "concat")) {
		if (successors.size() < 2)
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "less than two successors for concat node " << opNode->getID());

		const StrangerAutomaton* concatAuto = opAuto;

		DepGraphNode* leftSibling = successors[0];
		DepGraphNode* rightSibling = successors[1];

		AnalysisResultConstIterator leftIt = fwAnalysisResult.find(leftSibling->getID());
		AnalysisResultConstIterator rightIt = fwAnalysisResult.find(rightSibling->getID());

		if (childNode->equals(leftSibling)){
			if (leftIt == fwAnalysisResult.end()) {
				throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Should not visit left node(" << leftSibling->getID() << ") in concat");
			} else if (rightIt == fwAnalysisResult.end()) {
				// we can just clone the previous auto, in that case actual concat operation is not done during forward analysis
				retMe = concatAuto->clone(childNode->getID());
			} else {
				if (isLiteralOrConstant(rightSibling, depGraph.getSuccessors(rightSibling))) {
                                    // Check if we need to do concats
                                    if (m_doConcats) {
					string value = getLiteralOrConstantValue(rightSibling);
					retMe = concatAuto->leftPreConcatConst(value, childNode->getID());
                                    } else {
                                        retMe = concatAuto->clone(childNode->getID());
                                    }
				} else {
                                        const StrangerAutomaton* rightSiblingAuto = fwAnalysisResult.find(rightSibling->getID())->second;
					retMe = concatAuto->leftPreConcat(rightSiblingAuto, childNode->getID());
				}
			}

		} else if (childNode->equals(rightSibling)){

			if (rightIt == fwAnalysisResult.end()) {
				throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Should not visit right node(" << leftSibling->getID() << ") in concat");
			} else if (leftIt == fwAnalysisResult.end()) {
				// we can just clone the previous auto, in that case actual concat operation is not done during forward analysis
				retMe = concatAuto->clone(childNode->getID());
			} else {
				if (isLiteralOrConstant(leftSibling, depGraph.getSuccessors(leftSibling))){
                                    // Check if we need to do concats
                                    if (m_doConcats) {
					string value = getLiteralOrConstantValue(leftSibling);
					retMe = concatAuto->rightPreConcatConst(value, childNode->getID());
                                    } else {
                                        retMe = concatAuto->clone(childNode->getID());
                                    }
				} else {
                                        const StrangerAutomaton* leftSiblingAuto = fwAnalysisResult.find(leftSibling->getID())->second;
					retMe = concatAuto->rightPreConcat(leftSiblingAuto, childNode->getID());
				}
			}

		}else {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "child (" << childNode->getID() << ") of concat (" << opNode->getID() << ") is not equal to any of the two successors.");
		}

	} else if (opName == "addslashes") {
		// only has one parameter ==>  string addslashes  ( string $str  )
		retMe = StrangerAutomaton::pre_addslashes(opAuto,childNode->getID());

	} else if (opName == "encodeAttrString") {
        // only has one parameter ==>  string encodeAttrString  ( string $str  )
        retMe = StrangerAutomaton::pre_encodeAttrString(opAuto,childNode->getID());
    } else if (opName == "encodeTextFragment") {
        // only has one parameter ==>  string addslashes  ( string $str  )
        retMe = StrangerAutomaton::pre_encodeTextFragment(opAuto,childNode->getID());
    } else if (opName == "trim" ) {
		// only has one parameter ==>  string trim  ( string $str  )
		retMe = opAuto->preTrimSpaces(childNode->getID());
	} else if (opName == "rtrim" ) {
		// only has one parameter ==>  string trim  ( string $str  )
		retMe = opAuto->preTrimSpacesRigth(childNode->getID());
	} else if (opName == "ltrim" ) {
		// only has one parameter ==>  string trim  ( string $str  )
		retMe = opAuto->preTrimSpacesLeft(childNode->getID());

	}  else if (opName == "strtoupper" ) {
		// only has one parameter ==>  string strtoupper  ( string $str  )
		retMe = opAuto->preToUpperCase(childNode->getID());

	}  else if (opName == "strtolower" ) {
		// only has one parameter ==>  string strtolower  ( string $str  )
		retMe = opAuto->preToLowerCase(childNode->getID());

	} else if (opName == "htmlspecialchars") {
		if (childNode->equals(successors[0])) {
			string flagString = "ENT_COMPAT";
			if (successors.size() > 1) {
				DepGraphNode* flagNode = successors[1];
				const StrangerAutomaton* flagAuto = fwAnalysisResult.find(flagNode->getID())->second;
				flagString = flagAuto->getStr();
			}
			retMe = StrangerAutomaton::preHtmlSpecialChars(opAuto, flagString, childNode->getID());
		} else {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "SNH: child node (" << childNode->getID() << ") of htmlspecialchars (" << opNode->getID() << ") is not in backward path");
		}
	} else if (opName == "mysql_escape_string") {
		// has one parameter
		retMe = StrangerAutomaton::pre_mysql_escape_string(opAuto, childNode->getID());

	}  else if (opName == "mysql_real_escape_string") {
		// has one parameter
		retMe = StrangerAutomaton::pre_mysql_real_escape_string(opAuto, childNode->getID());

	} else if (opName == "preg_replace" || opName == "ereg_replace" || opName == "str_replace") {

		if (successors.size() != 3) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "replace invalid number of arguments");
		}

		DepGraphNode* patternNode = successors[0];
		DepGraphNode* replaceNode = successors[1];

		const StrangerAutomaton* subjectAuto = opAuto;
                // std::cout << "opAuto to dot:\n";
                // subjectAuto->toDotAscii(1);
		const StrangerAutomaton* patternAuto = fwAnalysisResult.find(patternNode->getID())->second;
		const StrangerAutomaton* replaceAuto = fwAnalysisResult.find(replaceNode->getID())->second;
                // std::cout << "PatternAuto to dot:" << patternNode->getID() << std::endl;
                // patternAuto->toDotAscii(1);
		// std::cout << "ReplaceAuto to dot:" << replaceNode->getID() << std::endl;
		// replaceAuto->toDotAscii(1);
                string replaceStr = replaceAuto->getStr();
                // checking for special case where a character is escaped by another character
		if (patternAuto->isSingleton()) {
			string patternStr = patternAuto->generateSatisfyingExample();
			if ( replaceStr.length() == 2 && patternStr.length() == 1 && patternStr[0] == replaceStr[1]) {
				retMe = StrangerAutomaton::general_replace(replaceAuto, patternAuto, subjectAuto, childNode->getID());
			} else {
				retMe = subjectAuto->preReplace(patternAuto, replaceStr, childNode->getID());
			}
		} else {
			retMe = subjectAuto->preReplace(patternAuto, replaceStr, childNode->getID());
		}
        } else if (opName == "str_replace_once") {
            if (successors.size() != 3) {
                throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "replace invalid number of arguments");
            }

            DepGraphNode* patternNode = successors[0];
            DepGraphNode* replaceNode = successors[1];

            const StrangerAutomaton* subjectAuto = opAuto;
            const StrangerAutomaton* patternAuto = fwAnalysisResult.find(patternNode->getID())->second;
            const StrangerAutomaton* replaceAuto = fwAnalysisResult.find(replaceNode->getID())->second;
            string replaceStr = replaceAuto->getStr();
            retMe = subjectAuto->preReplaceOnce(patternAuto, replaceStr, childNode->getID());

	} else if ((opName == "regex_match") || (opName == "regex_exec")) {

		if (successors.size() != 3) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "replace invalid number of arguments");
		}

		DepGraphNode* patternNode = successors[0];
		DepGraphNode* groupNode = successors[1];

		const StrangerAutomaton* subjectAuto = opAuto;

		const StrangerAutomaton* patternAuto = fwAnalysisResult.find(patternNode->getID())->second;
		const StrangerAutomaton* groupAuto = fwAnalysisResult.find(groupNode->getID())->second;

                string groupValue = groupAuto->getStr();
                int group = stoi(groupValue);

                retMe = subjectAuto->preMatch(patternAuto, group, childNode->getID());
	} else if (opName == "split") {
                // Model split as simply replacing the split character with an empty string
		if (successors.size() != 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "replace invalid number of arguments: " << opNode->getID());
		}

		DepGraphNode* subjectNode = successors[1];
		DepGraphNode* patternNode = successors[0];
		const StrangerAutomaton* patternAuto = fwAnalysisResult.find(patternNode->getID())->second;
		const StrangerAutomaton* subjectAuto = opAuto;

		retMe = subjectAuto->preReplace(patternAuto,"", childNode->getID());

	} else if (opName == "substr"){

		if (successors.size() < 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "substr invalid number of arguments");
		}
                const StrangerAutomaton* subjectAuto = opAuto;

                if (m_doSubstr) {
                    // Compute the start parameter
                    DepGraphNode* startNode = successors[1];
                    const StrangerAutomaton* startAuto = fwAnalysisResult.find(startNode->getID())->second;
                    // std::cout << "StartAuto:\n";
                    // startAuto->toDotAscii(2);
                    string startValue = startAuto->getStr();
                    int start = stoi(startValue);

                    // Check if there is a length argument
                    if (successors.size() >=3) {
                        DepGraphNode* lengthNode = successors[2];
                        const StrangerAutomaton* lengthAuto = fwAnalysisResult.find(lengthNode->getID())->second;
                        // std::cout << "LengthAuto:\n";
                        // startAuto->toDotAscii(2);
                        string lengthValue = lengthAuto->getStr();
                        int length = stoi(lengthValue);

                        retMe = subjectAuto->pre_substr(start, length, opNode->getID());
                    } else {
                        retMe = subjectAuto->pre_substr(start, opNode->getID());
                    }
                } else {
                    //std::cout << "Ignoring substr operation" << std::endl;
                    retMe = subjectAuto->clone(opNode->getID());
                }

	} else if (opName == "md5") {
		retMe = StrangerAutomaton::makeAnyString(opNode->getID());
	} else if (opName == "encodeURIComponent") {
                // Backwards analysis, so perform the inversion function
                retMe = StrangerAutomaton::decodeURIComponent(opAuto, opNode->getID());
	} else if (opName == "decodeURIComponent") {
                // Backwards analysis, so perform the inversion function
            if (opAuto->get_num_of_states() > 1000) {
                std::cout << "Approximating BW analysis for " << opName << " nStates: " << opAuto->get_num_of_states() << std::endl;
                retMe = opAuto->clone();
            } else {
		retMe = StrangerAutomaton::encodeURIComponent(opAuto, opNode->getID());
            }
	} else if (opName == "encodeURI") {
                // Backwards analysis, so perform the inversion function
                retMe = StrangerAutomaton::decodeURI(opAuto, opNode->getID());
	} else if (opName == "decodeURI") {
                // Backwards analysis, so perform the inversion function
               retMe = StrangerAutomaton::encodeURI(opAuto, opNode->getID());
	} else if (opName == "escape") {
                // Backwards analysis, so perform the inversion function
                retMe = StrangerAutomaton::unescape(opAuto, opNode->getID());
	} else if (opName == "unescape") {
                // Backwards analysis, so perform the inversion function
               retMe = StrangerAutomaton::escape(opAuto, opNode->getID());
	} else if (opName == "JSON.stringify") {
                // Backwards analysis, so perform the inversion function
                retMe = StrangerAutomaton::jsonParse(opAuto, opNode->getID());
	} else if (opName == "JSON.parse") {
                // Backwards analysis, so perform the inversion function
                retMe = StrangerAutomaton::jsonStringify(opAuto, opNode->getID());
	} else {
		throw StrangerException(AnalysisError::NotImplemented,  "Not implemented yet for regular validation phase: " + opName);
	}

	return retMe;
}

// ********************************************************************************
//
string ImageComputer::getLiteralOrConstantValue( const DepGraphNode* node) {
    string retMe = "";
    const DepGraphNormalNode* normalNode = dynamic_cast<const DepGraphNormalNode*>(node);
    if (normalNode == nullptr)
        throw runtime_error("can not cast DepGraphNode into DepGraphNormalNode");
    TacPlace* place = normalNode->getPlace();
    if (dynamic_cast<Literal*>(place) != nullptr || dynamic_cast<Constant*>(place) != nullptr) {
        retMe = place->toString();
    }
    else
        throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "SNH: node should be literal.\n");
    return retMe;
}



// ********************************************************************************
//
bool ImageComputer::isLiteralOrConstant(const DepGraphNode* node, NodesList successors) {
    if ((dynamic_cast<const DepGraphNormalNode*>(node) != nullptr)  && (successors.empty())){
        const DepGraphNormalNode* normalNode = dynamic_cast<const DepGraphNormalNode*>(node);
        TacPlace* place = normalNode->getPlace();
        if (dynamic_cast<Literal*>(place) != nullptr || dynamic_cast<Constant*>(place) )
            return true;
        else
            return false;
    } else
        return false;
}

StrangerAutomaton* ImageComputer::getLiteralorConstantNodeAuto(const DepGraphNode* node, bool is_vlab_restrict) {
    StrangerAutomaton* retMe = nullptr;
    const DepGraphNormalNode* normalNode = dynamic_cast<const DepGraphNormalNode*>(node);
    if (normalNode == nullptr)
        throw runtime_error("can not cast DepGraphNode into DepGraphNormalNode");
	TacPlace* place = normalNode->getPlace();
	if (dynamic_cast<Literal*>(place) != nullptr || dynamic_cast<Constant*>(place)) {
		string value = place->toString();
		// check if it is a regular expression
                // Make sure we don't try to parse single chars
                auto firstSlash = value.find_first_of('/');
                auto lastSlash = value.find_last_of('/');
		if ((firstSlash == 0) && (lastSlash != 0) &&
                    (lastSlash  == (value.length() - 1))) {
                    string regString = value.substr(1, value.length() - 2);
                    if(regString.find_first_of('^') == 0 &&
                       regString.find_last_of('$') == (regString.length() -1)) {
                        regString = "/" + regString.substr( 1,regString.length()-2) + "/";
                    }
                    else if (is_vlab_restrict) {
                        regString = "/.*(" + regString + ").*/";
                    }
                    else {
                        regString = "/" + regString + "/";
                    }
                    retMe = StrangerAutomaton::regExToAuto(regString, true, node->getID());
		} else {
                    if (value == "NUL") {
                        retMe = StrangerAutomaton::makeChar(0);
                    } else {
			retMe = StrangerAutomaton::makeString(value, node->getID());
                    }
		}
	} else {
		throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Unhandled node type, node id: " << node->getID());
	}

	return retMe;
}

/**
 * Calculate the automaton for the given node, using post-order dfs traversal of the Depgraph starting from given node
 */
void ImageComputer::doForwardAnalysis_GeneralCase(DepGraph& depGraph, DepGraphNode* node, AnalysisResult& analysisResult) {


	stack<DepGraphNode*> process_stack;
	set<DepGraphNode*> visited;
	set<int> processed_SCCs;

	process_stack.push(node);
	while (!process_stack.empty()) {

		DepGraphNode *curr = process_stack.top();
		auto isNotVisited = visited.insert(curr);
		NodesList successors = depGraph.getSuccessors(curr);

		if (!successors.empty() && isNotVisited.second) {
			for (NodesListConstReverseIterator it = successors.rbegin(); it != successors.rend(); it++) {
				if (analysisResult.find((*it)->getID()) == analysisResult.end()) {
					process_stack.push(*it);
				}
			}
		} else {
			if (depGraph.isSCCElement(curr)) { // handle cycles
				// do not compute a scc more than once
				auto isNotProcessed = processed_SCCs.insert(depGraph.getSCCID(curr));
				if (isNotProcessed.second) {
					doPostImageComputationForSCC_GeneralCase(depGraph, curr, analysisResult);
				}
			} else {
				doPostImageComputation_GeneralCase(depGraph, curr, analysisResult);
			}
			process_stack.pop();
		}
	  }
}

void ImageComputer::doPostImageComputation_GeneralCase(DepGraph& depGraph, DepGraphNode* node, AnalysisResult& analysisResult) {

	NodesList successors = depGraph.getSuccessors(node);

	StrangerAutomaton* newAuto = nullptr;
	DepGraphNormalNode* normalNode;
	DepGraphOpNode* opNode;
	DepGraphUninitNode* uninitNode;
	if ((normalNode = dynamic_cast<DepGraphNormalNode*>(node)) != nullptr) {
		if (successors.empty()) {
			newAuto = getLiteralorConstantNodeAuto(normalNode, false);
		} else {
			// an interior node, union of all its successors
			for (auto succ_node : successors) {
				if (succ_node->getID() == node->getID() ) {
					// avoid simple loops
					continue;
				}

				const StrangerAutomaton *succAuto = analysisResult.get(succ_node->getID());
				if (newAuto == nullptr) {
					newAuto = succAuto->clone(node->getID());
				} else {
					StrangerAutomaton* temp = newAuto;
					newAuto = newAuto->union_(succAuto, node->getID());
					delete temp;
				}
			}
		}
	} else if ((opNode = dynamic_cast<DepGraphOpNode*>(node)) != nullptr) {
		newAuto = makePostImageForOp_GeneralCase(depGraph, opNode, analysisResult);
	} else if ((uninitNode = dynamic_cast<DepGraphUninitNode*>(node)) != nullptr) {
		newAuto = ImageComputer::uninit_node_default_initialization->clone(node->getID());
	} else {
		throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Cannot figure out node type!, node id: " << node->getID());
	}

	if (newAuto == nullptr) {
		throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Forward automaton cannot be computed!, node id: " << node->getID());
	}
	analysisResult.set(node->getID(), newAuto);
}

/**
 * Post Image computation for cycles (loops)
 */
void ImageComputer::doPostImageComputationForSCC_GeneralCase(DepGraph& depGraph, DepGraphNode* node, AnalysisResult& analysisResult) {

	// TODO add to command line options as an optional parameter
	int precise_widening_limit = 5;
	int coarse_widening_limit = 20;

	int scc_id = depGraph.getSCCID(node);

	map<int, int> visit_count;
	NodesList current_scc_nodes = depGraph.getSCCNodes(scc_id);

	queue<DepGraphNode*> worklist;
	set<DepGraphNode*> visited;

	// initialize all scc_nodes to phi
	for (auto& scc_node : current_scc_nodes) {
            analysisResult.set(scc_node->getID(), StrangerAutomaton::makePhi(scc_node->getID()));
            visit_count[scc_node->getID()] = 0;
	}

	// add the successors to the worklist (in a depgraph successors are parents during forward analysis)
	for ( auto succ_node : depGraph.getSuccessors(node)) {
		worklist.push(succ_node);
		visited.insert(succ_node);
	}

	int iteration = 0;

	do {
		DepGraphNode* curr_node = worklist.front();
		worklist.pop();
		// calculate the values for predecessors (in a depgraph predecessors are children during forward analysis)
		for (auto pred_node : depGraph.getPredecessors(curr_node)) {
			// ignore nodes that are not part of the current scc
			if (!depGraph.isSCCElement(pred_node) || depGraph.getSCCID(pred_node) != scc_id)
				continue;

			const StrangerAutomaton* prev_auto = analysisResult.get(pred_node->getID()); // may need clone
			StrangerAutomaton* tmp_auto = nullptr;
			StrangerAutomaton* new_auto = nullptr;

			if (dynamic_cast<DepGraphNormalNode*>(pred_node) != nullptr) {
                            tmp_auto = analysisResult.get(curr_node->getID())->clone(); // may need clone
			} else if (dynamic_cast<DepGraphOpNode*>(pred_node) != nullptr) {
                            tmp_auto = makePostImageForOp_GeneralCase(depGraph, dynamic_cast<DepGraphOpNode*>(pred_node), analysisResult);
			} else {
                            throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Node cannot be an element of SCC component!, node id: " << node->getID());
			}

			if (tmp_auto == nullptr) {
                            throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Could not calculate the corresponding automaton!, node id: " << node->getID());
			}

			new_auto = tmp_auto->union_(prev_auto, pred_node->getID());

			int new_visit_count = visit_count[pred_node->getID()] + 1;
			if (new_visit_count > iteration)
				iteration = new_visit_count;

			// decide whether to do widening operations
			if (new_visit_count > coarse_widening_limit) {
				new_auto = prev_auto->coarseWiden(new_auto, pred_node->getID());
			} else if (new_visit_count > precise_widening_limit) {
				new_auto = prev_auto->preciseWiden(new_auto, pred_node->getID());
			}

			if (!new_auto->checkInclusion(prev_auto, new_auto->getID(), prev_auto->getID())) {
				auto isVisited = visited.insert(pred_node);
				if (isVisited.second) {
					worklist.push(pred_node);
				}
				analysisResult.set(pred_node->getID(), new_auto);
				visit_count[pred_node->getID()] = new_visit_count;
			}
		}

	} while( !worklist.empty() && iteration < 30000 );
}

/**
 * Calculates post image of an operation
 * Recursive calls may only happen if the function is called from single input analysis functions
 */
StrangerAutomaton* ImageComputer::makePostImageForOp_GeneralCase(DepGraph& depGraph, DepGraphOpNode* opNode, AnalysisResult& analysisResult) {
	NodesList successors = depGraph.getSuccessors(opNode);
	StrangerAutomaton* retMe = nullptr;
	string opName = opNode->getName();
        //cout << "Computing : " << opName << endl;
	// __vlab_restrict
	if (opName.find("__vlab_restrict") != string::npos) {
		boost::posix_time::ptime start_time = perfInfo->current_time();
		if (successors.size() != 3) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "__vlab_restrict invalid number of arguments: " << opNode->getID());
		}

		DepGraphNode* subjectNode = successors[1];
		DepGraphNode* patternNode = successors[0];
		DepGraphNode* complementNode = successors[2];

		// recursion happens only in single input mode when needed
		if (analysisResult.find(subjectNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, subjectNode, analysisResult);
		}

		// TODO handle general case
		if (analysisResult.find(patternNode->getID()) == analysisResult.end()) {
//				doForwardAnalysis_GeneralCase(depGraph, patternNode, analysisResult);
                    analysisResult.set(patternNode->getID(), getLiteralorConstantNodeAuto(patternNode, true));
		}
		// TODO handle general case
		if (analysisResult.find(complementNode->getID()) == analysisResult.end()) {
//				doForwardAnalysis_GeneralCase(depGraph, complementNode, analysisResult);

		}

		const StrangerAutomaton* subjectAuto = analysisResult.get(subjectNode->getID());
		const StrangerAutomaton* patternAuto = analysisResult.get(patternNode->getID());
		string complementString = getLiteralOrConstantValue(complementNode);
		if (complementString.find("false") != string::npos || complementString.find("FALSE") != string::npos) {
			retMe = subjectAuto->intersect(patternAuto, opNode->getID());
		} else {
			StrangerAutomaton* complementAuto = patternAuto->complement(patternNode->getID());
			retMe = subjectAuto->intersect(complementAuto, opNode->getID());
			delete complementAuto;
		}
		perfInfo->vlab_restrict_total_time += perfInfo->current_time() - start_time;
		perfInfo->number_of_vlab_restrict++;

	} else if ((opName == ".") || (opName == "concat")) {
		// TODO add option to ignore concats (heuristic)
		for (auto succ_node : successors){
			if (analysisResult.find(succ_node->getID()) == analysisResult.end()) {
                            doForwardAnalysis_GeneralCase(depGraph, succ_node, analysisResult);
			}
			const StrangerAutomaton* succAuto = analysisResult.get(succ_node->getID());
                        if (isLiteralOrConstant(succ_node, depGraph.getSuccessors(succ_node)) && !m_doConcats) {
                            string value = getLiteralOrConstantValue(succ_node);
                            //std::cout << "Ignoring concat of string value: " << value << std::endl;
                        } else {
                            if (retMe == nullptr) {
                                retMe = succAuto->clone(opNode->getID());
                            } else {
                                //std::cout << "Doing concat with node " << succ_node->getID() << std::endl;
                                StrangerAutomaton* temp = retMe;
                                retMe = retMe->concatenate(succAuto, opNode->getID());
                                delete temp;
                            }
			}
		}
		if (retMe == nullptr) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "Check successors of concatenation: " << opNode->getID());
		}

	} else if (opName == "preg_replace" || opName == "ereg_replace" || opName == "str_replace") {
		if (successors.size() != 3) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "replace invalid number of arguments: " << opNode->getID());
		}

		DepGraphNode* subjectNode = successors[2];
		DepGraphNode* patternNode = successors[0];
		DepGraphNode* replaceNode = successors[1];

		if (analysisResult.find(subjectNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, subjectNode, analysisResult);
		}
		if (analysisResult.find(patternNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, patternNode, analysisResult);
		}

		if (analysisResult.find(replaceNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, replaceNode, analysisResult);
		}

		const StrangerAutomaton* subjectAuto = analysisResult.get(subjectNode->getID());
		const StrangerAutomaton* patternAuto = analysisResult.get(patternNode->getID());
		const StrangerAutomaton* replaceAuto = analysisResult.get(replaceNode->getID());

		retMe = StrangerAutomaton::general_replace(patternAuto,replaceAuto,subjectAuto, opNode->getID());

	} else if (opName == "str_replace_once") {
		if (successors.size() != 3) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "replace invalid number of arguments: " << opNode->getID());
		}

		DepGraphNode* subjectNode = successors[2];
		DepGraphNode* patternNode = successors[0];
		DepGraphNode* replaceNode = successors[1];

		if (analysisResult.find(subjectNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, subjectNode, analysisResult);
		}
		if (analysisResult.find(patternNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, patternNode, analysisResult);
		}

		if (analysisResult.find(replaceNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, replaceNode, analysisResult);
		}

		const StrangerAutomaton* subjectAuto = analysisResult.get(subjectNode->getID());
		const StrangerAutomaton* patternAuto = analysisResult.get(patternNode->getID());
		const StrangerAutomaton* replaceAuto = analysisResult.get(replaceNode->getID());

                // Check here whether the depgraph contains the url
                if (depGraph.get_metadata().is_initialized()) {
                    std::string url = depGraph.get_metadata().get_url();
                    std::string replaceStr = replaceAuto->getStr();
                    //std::cout << "Checking for " << url << " in " << replaceStr << std::endl;
                    if (replaceStr.find(url) != std::string::npos) {
                        throw StrangerException(AnalysisError::UrlInReplaceString,
                                                stringbuilder() << "URL: " << url
                                                << " found in replace string: " << replaceStr);
                    }
                }

		retMe = StrangerAutomaton::str_replace_once(patternAuto,replaceAuto,subjectAuto, opNode->getID());

	} else if ((opName == "regex_match") || (opName == "regex_exec")) {
		if (successors.size() != 3) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "match invalid number of arguments: " << opNode->getID());
		}

		DepGraphNode* subjectNode = successors[2];
		DepGraphNode* patternNode = successors[0];
		DepGraphNode* groupNode = successors[1];

		if (analysisResult.find(subjectNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, subjectNode, analysisResult);
		}

		if (analysisResult.find(patternNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, patternNode, analysisResult);
		}

		if (analysisResult.find(groupNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, groupNode, analysisResult);
		}

		const StrangerAutomaton* subjectAuto = analysisResult.get(subjectNode->getID());
		const StrangerAutomaton* patternAuto = analysisResult.get(patternNode->getID());
		const StrangerAutomaton* groupAuto = analysisResult.get(groupNode->getID());

                string groupValue = groupAuto->getStr();
                int group = stoi(groupValue);
                
		retMe = StrangerAutomaton::match(patternAuto, group, subjectAuto, opNode->getID());

	} else if (opName == "split") {
                // Model split as simply replacing the split character with an empty string
		if (successors.size() != 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "replace invalid number of arguments: " << opNode->getID());
		}

		DepGraphNode* subjectNode = successors[1];
		DepGraphNode* patternNode = successors[0];

		if (analysisResult.find(subjectNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, subjectNode, analysisResult);
		}
		if (analysisResult.find(patternNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, patternNode, analysisResult);
		}

		const StrangerAutomaton* subjectAuto = analysisResult.get(subjectNode->getID());
		const StrangerAutomaton* patternAuto = analysisResult.get(patternNode->getID());
		const StrangerAutomaton* replaceAuto = StrangerAutomaton::makeEmptyString();

		retMe = StrangerAutomaton::general_replace(patternAuto,replaceAuto,subjectAuto, opNode->getID());

                delete replaceAuto;

	} else if (opName == "addslashes") {
		if (successors.size() != 1) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "addslashes should have one child: " << opNode->getID());
		}

		const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* slashesAuto = StrangerAutomaton::addslashes(paramAuto, opNode->getID());
		retMe = slashesAuto;

	} else if (opName == "stripslashes") {
		throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "stripslashes is not handled yet: " << opNode->getID());

	} else if (opName == "mysql_escape_string") {
		if (successors.size() < 1 || successors.size() > 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "mysql_escape_string wrong number of arguments: " << opNode->getID());
		}
		//we only care about the first parameter
		const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* mysqlEscapeAuto = StrangerAutomaton::mysql_escape_string(paramAuto, opNode->getID());
		retMe = mysqlEscapeAuto;

	} else if (opName == "mysql_real_escape_string") {
		if (successors.size() < 1 || successors.size() > 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "mysql_real_escape_string wrong number of arguments: " << opNode->getID());
		}
		//we only care about the first parameter
		const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* mysqlEscapeAuto = StrangerAutomaton::mysql_real_escape_string(paramAuto, opNode->getID());
		retMe = mysqlEscapeAuto;

	} else if (opName == "htmlspecialchars") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		string flagString = "ENT_COMPAT";
		if (successors.size() > 1) {
			if (analysisResult.find(successors[1]->getID()) == analysisResult.end()) {
				doForwardAnalysis_GeneralCase(depGraph, successors[1], analysisResult);
			}
			flagString = analysisResult.get(successors[1]->getID())->getStr();
		}

		StrangerAutomaton* htmlSpecAuto = StrangerAutomaton::htmlSpecialChars(paramAuto, flagString, opNode->getID());
		retMe = htmlSpecAuto;

	} else if (opName == "nl2br"){
		if (successors.size() < 1 || successors.size() > 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "nl2br wrong number of arguments: " << opNode->getID());
		}

		const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* nl2brAuto = StrangerAutomaton::nl2br(paramAuto, opNode->getID());
		retMe = nl2brAuto;

	}  else if (opName == "substr"){
		if (successors.size() < 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "SNH: substr invalid number of arguments: " << opNode->getID());
		}

		DepGraphNode* subjectNode = successors[0];
		DepGraphNode* startNode = successors[1];

                // Get the subject automaton
		if (analysisResult.find(subjectNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, subjectNode, analysisResult);
		}
                const StrangerAutomaton* subjectAuto = analysisResult.get(subjectNode->getID());

                if (m_doSubstr) {
                // Compute the starting index
                    if (analysisResult.find(startNode->getID()) == analysisResult.end()) {
			doForwardAnalysis_GeneralCase(depGraph, startNode, analysisResult);
                    }
                    string startValue = analysisResult.get(startNode->getID())->getStr();
                    int start = stoi(startValue);

                    // Check if there is also a length argument
                    if (successors.size() >=3) {
                        DepGraphNode* lengthNode = successors[2];
                        if (analysisResult.find(lengthNode->getID()) == analysisResult.end()) {
                            doForwardAnalysis_GeneralCase(depGraph, lengthNode, analysisResult);
                        }
                        string lengthValue = analysisResult.get(lengthNode->getID())->getStr();
                        int length = stoi(lengthValue);
                        StrangerAutomaton* substrAuto = subjectAuto->substr(start,length,opNode->getID());
                        retMe = substrAuto;
                    } else {
                        StrangerAutomaton* substrAuto = subjectAuto->substr(start,opNode->getID());
                        retMe = substrAuto;
                    }
                } else {
                    //std::cout << "Ignoring substr operation" << std::endl;
                    retMe = subjectAuto->clone(opNode->getID());
                }
	} else if (opName == "strtoupper" || opName == "strtolower") {
		if (successors.size() != 1) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << opName << " has more than one successor in depgraph" );
		}

		const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		if (opName == "strtoupper") {
			retMe = paramAuto->toUpperCase(opNode->getID());
		}
		else if (opName == "strtolower") {
			retMe = paramAuto->toLowerCase(opNode->getID());
		}

	} else if (opName == "trim" || opName == "rtrim" || opName == "ltrim") {
		if (successors.size() > 2) {
			throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << opName << " has more than one successor in depgraph" );
		} else if (successors.size() == 2) {
			cout << "!!! Second parameter of " << opName << " ignored!!!. If it is not whitespace, modify implementation to handle that situation" << endl;
//			if (analysisResult.find(successors[1]->getID()) == analysisResult.end()) {
//				doForwardAnalysis_GeneralCase(depGraph, successors[1], analysisResult);
//			}
			// get trim char from automaton
		}

		const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		if (opName == "trim")
			retMe = paramAuto->trimSpaces(opNode->getID());
		else if (opName == "rtrim") {
			retMe = paramAuto->trimSpacesRight(opNode->getID());
		}
		else if (opName == "ltrim") {
			retMe = paramAuto->trimSpacesLeft(opNode->getID());
		}

	} else if (opName == "md5") {
		//conservative desicion
		retMe = StrangerAutomaton::regExToAuto("/[aAbBcCdDeEfF0-9]{32,32}/",true, opNode->getID());
	} else if (opName == "encodeURIComponent") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* uriAuto = StrangerAutomaton::encodeURIComponent(paramAuto, opNode->getID());
		retMe = uriAuto;

	} else if (opName == "decodeURIComponent") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* uriAuto = StrangerAutomaton::decodeURIComponent(paramAuto, opNode->getID());
		retMe = uriAuto;

	} else if (opName == "encodeURI") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* uriAuto = StrangerAutomaton::encodeURI(paramAuto, opNode->getID());
		retMe = uriAuto;

	} else if (opName == "decodeURI") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* uriAuto = StrangerAutomaton::decodeURI(paramAuto, opNode->getID());
		retMe = uriAuto;

	} else if (opName == "escape") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* uriAuto = StrangerAutomaton::escape(paramAuto, opNode->getID());
		retMe = uriAuto;

	} else if (opName == "unescape") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* uriAuto = StrangerAutomaton::unescape(paramAuto, opNode->getID());
		retMe = uriAuto;

	} else if (opName == "JSON.stringify") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* json = StrangerAutomaton::jsonStringify(paramAuto, opNode->getID());
		retMe = json;
	} else if (opName == "JSON.parse") {
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());
		StrangerAutomaton* json = StrangerAutomaton::jsonParse(paramAuto, opNode->getID());
		retMe = json;
	} else if (opName == "encodeTextFragment") {
                if (successors.size() < 1 || successors.size() > 2) {
                    throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "encodeTextFragment wrong number of arguments: " << opNode->getID());
                }
                const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());

                StrangerAutomaton* encodedAuto = StrangerAutomaton::encodeTextFragment(paramAuto, opNode->getID());
                retMe = encodedAuto;
        } else if (opName == "encodeAttrString") {
            if (successors.size() < 1 || successors.size() > 2) {
                throw StrangerException(AnalysisError::MalformedDepgraph, stringbuilder() << "encodeAttrString wrong number of arguments: " << opNode->getID());
            }
            const StrangerAutomaton* paramAuto = analysisResult.get(successors[0]->getID());

        StrangerAutomaton* encodedAuto = StrangerAutomaton::encodeAttrString(paramAuto, opNode->getID());
        retMe = encodedAuto;
    } else {
            cout << "!!! Warning: Unmodeled builtin general function : " << opName << endl;
            f_unmodeled.push_back(opNode);

            //conservative decision for operations that have not been
            //modeled yet: .*
            //retMe = StrangerAutomaton::makeAnyString(opNode->getID());
            // Block anything that has not been modelled yet
            //retMe = StrangerAutomaton::makeEmptyString(opNode->getID());
            // Throw an exception
            
            throw StrangerException(AnalysisError::NotImplemented, stringbuilder() << "Unknown function " << opName);
    }

        //retMe->printAutomatonVitals();
    return retMe;
}
