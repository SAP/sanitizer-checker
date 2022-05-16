#ifndef SEMREP_VALIDATIONIMAGECOMPUTER_HPP
#define SEMREP_VALIDATIONIMAGECOMPUTER_HPP

#include "ImageComputer.hpp"

class ValidationImageComputer : public ImageComputer {
public:
    ValidationImageComputer();
    /****************************************************************************************************/
    /********* VALIDATION FUNCTION CALCULATION METHODS ************************************************/
    /****************************************************************************************************/

    AnalysisResult doBackwardAnalysis_ValidationCase(DepGraph& origDepGraph, DepGraph& depGraph, StrangerAutomaton* initialAuto);
    void doPreImageComputation_ValidationCase(DepGraph& origDepGraph, DepGraphNode* node, AnalysisResult& bwAnalysisResult);
    StrangerAutomaton* makePreImageForOpChild_ValidationCase(DepGraph& depGraph, DepGraphOpNode* opNode,
                                                             DepGraphNode* childNode,AnalysisResult& bwAnalysisResult);
    void doPreImageComputationForSCC_ValidationCase(DepGraph& origDepGraph, DepGraphNode* node, AnalysisResult& bwAnalysisResult);
};


#endif //SEMREP_VALIDATIONIMAGECOMPUTER_HPP
