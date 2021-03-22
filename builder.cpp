#include <cppcoro/generator.hpp>
#include <cstdint>
#include <exception>
#include <fstream>
#include <nlohmann/json.hpp>
#include <optional>
#include <seccomp.h>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

using json           = nlohmann::json;
using argument_index = decltype(scmp_arg_cmp::arg);

auto read_json(std::string_view sv) {
    std::ifstream profile_file{sv.data()};
    if (!profile_file) {
        throw std::runtime_error{"profile.json existiert nicht"};
    }

    json j;
    profile_file >> j;
    return j;
}

class profile {
public:
    using param_description   = const json&;
    using params_description  = cppcoro::generator<param_description>;
    using params_descriptions = cppcoro::generator<params_description>;
    using syscall_alterations = std::pair<std::string_view, params_descriptions>;

private:
    json j_;

    params_description iterate_params_description(const json& in) {
        for(const auto& x : in) {
            co_yield x;
        }
    }

    params_descriptions iterate_params_descriptions(const json& in) {
        for(const auto& x : in) {
            if(!x.is_array()) {
                throw std::runtime_error{"Parameter-Beschreibung ist kein Array"};
            }
            co_yield iterate_params_description(x);
        }
    }

public:
    profile(std::string_view path) : j_(read_json(path)) {
        if(!j_.is_object()) {
            throw std::runtime_error{"Profil ist kein JSON-Objekt"};
        }
    }

    cppcoro::generator<syscall_alterations> items() {
        for(const auto& p : j_.items()) {
            if(!p.value().is_array()) {
                throw std::runtime_error{"Parameter-Beschreibungen zu Systemaufruf ist kein Array"};
            }

            co_yield std::make_pair(
                p.key(),
                iterate_params_descriptions(p.value())
            );
        }
    }
};

class model {
    json j_;

public:
    enum class param_type {
        immediate,
        string,
        sockaddr,
        socklen
    };
    using opt_param_type = std::optional<param_type>;

private:
    const std::unordered_map<std::string_view, param_type> param_type_map{
        {"immediate", param_type::immediate},
        {"string", param_type::string},
        {"sockaddr", param_type::sockaddr},
        {"socklen", param_type::socklen}
    };

public:
    model(std::string_view path) : j_(read_json(path)) {
        if(!j_.is_object()) {
            throw std::runtime_error{"Modell ist kein JSON-Objekt"};
        }
    }

    int resolve_syscall(std::string_view syscall) {
        int nr = seccomp_syscall_resolve_name(syscall.data());
        if (nr == __NR_SCMP_ERROR) {
            throw std::runtime_error{"Systemaufruf wurde nicht gefunden!"};
        }
        return nr;
    }

    cppcoro::generator<opt_param_type> get_param_types(std::string_view syscall) {
        if(!j_.contains(syscall)) {
            throw std::runtime_error{"Systemaufruf ist nicht im Modell hinterlegt"};
        }

        const auto& j_param_types = j_[syscall.data()];
        if(!j_param_types.is_array()) {
            throw std::runtime_error{"Parameterliste ist kein Array"};
        }

        for(const auto& j_param_type : j_param_types) {
            if(!j_param_type.is_string()) {
                throw std::runtime_error{"Parameter in Parameterliste ist kein String"};
            }

            auto s_param_type = j_param_type.get<std::string_view>();
            if(s_param_type == "-") {
                co_yield std::nullopt;
            } else {
                auto it = param_type_map.find(s_param_type);
                if(it == param_type_map.cend()) {
                    throw std::runtime_error{"Unbekannter Parametertyp"};
                }
                co_yield (*it).second;
            }
        }
    }
};

template<typename Container>
void format_immediate_param(Container& cont, argument_index arg_idx, profile::param_description desc) {
    static std::unordered_map<std::string_view, scmp_compare> scmp_compare_map{
        {"ne", SCMP_CMP_NE},
        {"lt", SCMP_CMP_LT},
        {"le", SCMP_CMP_LE},
        {"eq", SCMP_CMP_EQ},
        {"ge", SCMP_CMP_GE},
        {"gt", SCMP_CMP_GT},
        {"masked_eq", SCMP_CMP_MASKED_EQ},
    };

    const auto& cmp = desc["cmp"].get<std::string_view>();
    const auto& val = desc["val"].get<std::uint64_t>();

    const auto it = scmp_compare_map.find(cmp);
    if(it == scmp_compare_map.end()) {
        throw std::runtime_error{"Nicht erlaubter Komparator für direkten Parameter"};
    }

    cont.emplace_back(SCMP_CMP64(arg_idx, it->second, val));
}

template<typename Container>
void format_string_param(Container& cont, argument_index arg_idx, profile::param_description desc) {
    // String-Parameter werden von seccomp derzeit nicht unterstützt
}

template<typename Container>
void format_sockaddr_param(Container& cont, argument_index arg_idx, profile::param_description desc) {
    // sockaddr-Parameter werden von seccomp derzeit nicht unterstützt
}

template<typename Container>
void format_socklen_param(Container& cont, argument_index arg_idx, profile::param_description desc) {
    // socklen-Parameter werden von seccomp derzeit nicht unterstützt
}

template<typename Container>
void format_param_description(Container& cont, argument_index arg_idx, model::param_type type, profile::param_description desc) {
    using handler_func = void(&)(Container&, argument_index, profile::param_description);
    static std::unordered_map<model::param_type, handler_func> descriptor_map{
        {model::param_type::immediate, format_immediate_param},
        {model::param_type::string, format_string_param},
        {model::param_type::sockaddr, format_sockaddr_param},
        {model::param_type::socklen, format_socklen_param},
    };

    const auto it = descriptor_map.find(type);
    if(it == descriptor_map.end()) {
        throw std::runtime_error{"Kein Handler für Parametertyp gefunden"};
    }

    it->second(cont, arg_idx, desc);
}

int main(int argc, char** argv) {
    profile p{"profile.json"};
    model m{"model.json"};

    auto filter_ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_arch_add(filter_ctx, SCMP_ARCH_X86_64);

    for(auto& [syscall, params_descriptions] : p.items()) {
        int syscall_nr = m.resolve_syscall(syscall);
        for(auto& params_description : params_descriptions) {
            auto param_types = m.get_param_types(syscall);
            std::vector<scmp_arg_cmp> arg_cmps{};

            auto param_description_it = params_description.begin();
            argument_index arg_idx{0}; 
            for(auto& param_type : param_types) {
                if(param_description_it == params_description.end()) {
                    break;
                }

                if(param_type.has_value()) {
                    auto param_description = *param_description_it;
                    format_param_description(arg_cmps, arg_idx, param_type.value(), param_description);
                    param_description_it++;
                }

                arg_idx++;
            }
            seccomp_rule_add_array(filter_ctx, SCMP_ACT_ALLOW, syscall_nr, arg_cmps.size(), arg_cmps.data());
        }
    }

    seccomp_export_pfc(filter_ctx, 2);

    return 0;
}
