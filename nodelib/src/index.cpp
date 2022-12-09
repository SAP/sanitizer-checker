#include <napi.h>
#include <string>
#include "../../semattack/src/main_attack.hpp"

Napi::String parseDepString(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    std::string depgraph = (std::string) info[0].ToString();
    std::string fieldName = (std::string) info[1].ToString();
    std::string result = call_sem_attack("", depgraph, fieldName);

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