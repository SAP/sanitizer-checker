#include <napi.h>
#include <string>
#include <iostream>
#include "../../semattack/src/main_attack.hpp"

Napi::String parseDepString(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    std::string depgraph = (std::string) info[0].ToString();
    std::string fieldName = (std::string) info[1].ToString();
    std::string result;
    std::cout.setstate(std::ios_base::failbit);
    try {
        result = call_sem_attack("", depgraph, fieldName);
    } catch (...) {
        Napi::Error::New(env, "Example exception").ThrowAsJavaScriptException();
        return Napi::String::New(env, "error");
    }
    std::cout.clear();
    return Napi::String::New(env, result);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set(
        Napi::String::New(env, "parseDepString"),
        Napi::Function::New(env, parseDepString)
    );

    return exports;
}

NODE_API_MODULE(sanitizerchecker, Init);