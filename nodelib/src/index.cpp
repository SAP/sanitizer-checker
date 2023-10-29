#include <napi.h>
#include <string>
#include <tuple>
#include <iostream>
#include <sstream>
#include <cassert>
#include "../../semattack/src/main_attack.hpp"

void printToJSConsole(Napi::Env env, const char* text);
const char* resultStatusToString(const ResultStatus status);

napi_value parseDepString(const Napi::CallbackInfo& info) {
    napi_status status;
    Napi::Env env = info.Env();

    std::string depgraph = (std::string) info[0].ToString();
    std::string fieldName = (std::string) info[1].ToString();
    std::string exploit = (std::string) info[2].ToString();
    std::string resultExploitString;
    ResultStatus resultStatus;
    std::ostringstream oss;

    // Redirect stdout to our stringstream buffer
    std::streambuf* oldCoutStreamBuf = std::cout.rdbuf();
    std::cout.rdbuf(oss.rdbuf());

    // Redirect stderr to our stringstream buffer
    std::streambuf* oldCerrStreamBuf = std::cerr.rdbuf();
    std::cerr.rdbuf(oss.rdbuf());

    try {
        std::tuple<ResultStatus, std::string> result = call_sem_attack("", depgraph, fieldName, exploit);
        resultStatus = std::get<0>(result);
        resultExploitString = std::get<1>(result);
    } catch (std::exception& e) {
        Napi::Error::New(env, e.what()).ThrowAsJavaScriptException();
        // Don't forget to restore the original stream
        std::cout.rdbuf(oldCoutStreamBuf);
        std::cerr.rdbuf(oldCerrStreamBuf);
        return Napi::String::New(env, "error");
    }
    std::cout.clear();
    // Redirect back to the original stream
    std::cout.rdbuf(oldCoutStreamBuf);
    std::cerr.rdbuf(oldCerrStreamBuf);

    napi_value obj;
    status = napi_create_object(env, &obj);
    assert(status == napi_ok);

    napi_value resultStatusValue;
    status = napi_create_string_utf8(env, resultStatusToString(resultStatus), NAPI_AUTO_LENGTH, &resultStatusValue);
    assert(status == napi_ok);

    napi_value resultExploitStringValue;
    status = napi_create_string_utf8(env, resultExploitString.c_str(), NAPI_AUTO_LENGTH, &resultExploitStringValue);
    assert(status == napi_ok);

    status = napi_set_named_property(env, obj, "resultStatus", resultStatusValue);
    assert(status == napi_ok);

    status = napi_set_named_property(env, obj, "resultExploitString", resultExploitStringValue);
    assert(status == napi_ok);


    printToJSConsole(env, oss.str().c_str());
    return obj;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(
        Napi::String::New(env, "parseDepString"),
        Napi::Function::New(env, parseDepString)
    );

    return exports;
}

void printToJSConsole(Napi::Env env, const char* text) {


    napi_value global, console, log, result2;
    napi_status status;

    // Get the global object
    status = napi_get_global(env, &global);

    // Get the console object
    status = napi_get_named_property(env, global, "console", &console);

    // Get the console.log function
    status = napi_get_named_property(env, console, "log", &log);

    napi_value message;
    // Create a JavaScript string from a C string
    status = napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &message);

    napi_value argv[1] = { message };

    // Call the function
    status = napi_call_function(env, console, log, 1, argv, &result2);
}

const char* resultStatusToString(const ResultStatus status) {
    switch(status) {
        case VULNERABLE_SANITIZER_FOUND: return "VULNERABLE_SANITIZER_FOUND";
        case VULNERABLE_NO_SANITIZER_FOUND: return "VULNERABLE_NO_SANITIZER_FOUND";
        case NOT_VULNERABLE: return "NOT_VULNERABLE";
        case ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

NODE_API_MODULE(sanitizerchecker, Init);