{
  "targets": [
    {
      "target_name": "sanitizerchecker",
      "cflags!": [ "-fno-exceptions" ],
      'cflags_cc!': [ '-fno-rtti', '-fno-exceptions' ],
      "sources": [ 
        "./src/index.cpp",
        "../semattack/src/AttackPatterns.cpp",
        "../semattack/src/SemRepair.cpp",
        "../semattack/src/MultiAttack.cpp",
        "../semattack/src/RegExp.cpp",
        # "../semattack/src/main_attack_bw.cpp",
        "../semattack/src/StrangerAutomaton.cpp",
        "../semattack/src/AttackContext.cpp",
        "../semattack/src/ImageComputer.cpp",
        "../semattack/src/PerfInfo.cpp",
        "../semattack/src/depgraph/DepGraph.cpp",
        "../semattack/src/depgraph/DepGraphSccNode.cpp",
        "../semattack/src/depgraph/DepGraphNode.cpp",
        "../semattack/src/depgraph/Metadata.cpp",
        "../semattack/src/depgraph/DepGraphUninitNode.cpp",
        "../semattack/src/depgraph/DepGraphNormalNode.cpp",
        "../semattack/src/depgraph/DepGraphOpNode.cpp",
        "../semattack/src/main_attack.cpp",
        "../semattack/src/SemRepairDebugger.cpp",
        "../semattack/src/ValidationImageComputer.cpp",
        # "../semattack/src/automatonify.cpp",
        "../semattack/src/AutomatonGroups.cpp",
        "../semattack/src/SemAttack.cpp",
        "../semattack/src/exceptions/StrangerException.cpp",
        "../semattack/src/exceptions/AnalysisError.cpp",
        "../semattack/src/SemAttackBw.cpp",
        "../semattack/src/AnalysisResult.cpp",
        # "../semattack/src/main_multi_attack.cpp",
        # "../semattack/src/main.cpp",
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
      ],
    'libraries': [
        "<!@(ls /usr/local/lib/*.so)",
        "<!@(find /usr/lib/x86_64-linux-gnu/ | grep 'libboost' | grep '\.so$')"
    ],
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'OTHER_CPLUSPLUSFLAGS' : ['-std=c++11','-stdlib=libc++', '-v'],
            'OTHER_LDFLAGS': ['-stdlib=libc++'],
            'MACOSX_DEPLOYMENT_TARGET': '10.7',
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
            'GCC_ENABLE_CPP_RTTI': 'YES'
          }
        }]
      ],
    }
  ]
}