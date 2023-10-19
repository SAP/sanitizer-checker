#include <string>
#include <tuple>
enum ResultStatus {
    VULNERABLE_SANITIZER_FOUND,
    VULNERABLE_NO_SANITIZER_FOUND,
    NOT_VULNERABLE,
    ERROR
};
std::tuple<ResultStatus, std::string> call_sem_attack(const std::string& target_name, const std::string& dep_graph, const std::string& field_name, const std::string& exploit_string);