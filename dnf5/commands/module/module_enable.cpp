/*
Copyright Contributors to the libdnf project.

This file is part of libdnf: https://github.com/rpm-software-management/libdnf/

Libdnf is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Libdnf is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with libdnf.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "module_enable.hpp"

namespace dnf5 {

using namespace libdnf5::cli;

void ModuleEnableCommand::set_argument_parser() {
    auto & ctx = get_context();
    auto & parser = ctx.get_argument_parser();

    auto & cmd = *get_argument_parser_command();
    cmd.set_description("Enable module streams and make their packages available.");

    auto keys = parser.add_new_positional_arg("specs", ArgumentParser::PositionalArg::AT_LEAST_ONE, nullptr, nullptr);
    keys->set_description("List of module specs to enable");
    keys->set_parse_hook_func(
        [this]([[maybe_unused]] ArgumentParser::PositionalArg * arg, int argc, const char * const argv[]) {
            for (int i = 0; i < argc; ++i) {
                module_specs.emplace_back(argv[i]);
            }
            return true;
        });
    keys->set_complete_hook_func([&ctx](const char * arg) { return match_specs(ctx, arg, false, true, true, false); });
    cmd.register_positional_arg(keys);
}

void ModuleEnableCommand::configure() {
    auto & context = get_context();
    context.set_load_system_repo(true);
    context.set_load_available_repos(Context::LoadAvailableRepos::ENABLED);
}

void ModuleEnableCommand::run() {
    auto goal = get_context().get_goal();
    for (const auto & spec : module_specs) {
        goal->add_module_enable(spec);
    }
}

}  // namespace dnf5
