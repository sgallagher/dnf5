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

#ifndef DNF5DAEMON_CLIENT_WRAPPERS_DBUS_ADVISORY_WRAPPER_HPP
#define DNF5DAEMON_CLIENT_WRAPPERS_DBUS_ADVISORY_WRAPPER_HPP

#include <dnf5daemon-server/dbus.hpp>
#include <libdnf5/rpm/nevra.hpp>

#include <string>

namespace dnfdaemon::client {

class DbusAdvisoryWrapper;

class DbusAdvisoryReferenceWrapper {
public:
    DbusAdvisoryReferenceWrapper(
        const std::string & id, const std::string & type, const std::string & title, const std::string & url)
        : id(id),
          type(type),
          title(title),
          url(url) {}

    std::string get_id() const { return id; }
    std::string get_type() const { return type; }
    std::string get_title() const { return title; }
    std::string get_url() const { return url; }

private:
    std::string id;
    std::string type;
    std::string title;
    std::string url;
};


class DbusAdvisoryPackageWrapper {
public:
    DbusAdvisoryPackageWrapper(const dnfdaemon::KeyValueMap & rawdata, DbusAdvisoryWrapper * advisory);
    std::string get_name() const { return rawdata.at("n"); }
    std::string get_epoch() const { return rawdata.at("e"); }
    std::string get_version() const { return rawdata.at("v"); }
    std::string get_release() const { return rawdata.at("r"); }
    std::string get_arch() const { return rawdata.at("a"); }
    std::string get_nevra() const { return libdnf5::rpm::to_nevra_string(*this); }
    std::string get_applicability() const { return rawdata.at("applicability"); }

    DbusAdvisoryWrapper get_advisory() const;

private:
    dnfdaemon::KeyValueMap rawdata{};
    DbusAdvisoryWrapper * advisory;
};


class DbusAdvisoryCollectionWrapper {
public:
    DbusAdvisoryCollectionWrapper(const dnfdaemon::KeyValueMap & rawdata, DbusAdvisoryWrapper * advisory);
    std::vector<DbusAdvisoryPackageWrapper> get_packages() const { return packages; }

private:
    dnfdaemon::KeyValueMap rawdata{};
    std::vector<DbusAdvisoryPackageWrapper> packages{};
};


class DbusAdvisoryWrapper {
public:
    explicit DbusAdvisoryWrapper(const dnfdaemon::KeyValueMap & rawdata);

    std::string get_advisoryid() const { return rawdata.at("advisoryid"); }
    std::string get_name() const { return rawdata.at("name"); }
    std::string get_severity() const { return rawdata.at("severity"); }
    std::string get_type() const { return rawdata.at("type"); }
    uint64_t get_buildtime() const { return rawdata.at("buildtime"); }
    std::string get_vendor() const { return rawdata.at("vendor"); }
    std::string get_description() const { return rawdata.at("description"); }
    std::string get_title() const { return rawdata.at("title"); }
    std::string get_status() const { return rawdata.at("status"); }
    std::string get_rights() const { return rawdata.at("rights"); }
    std::string get_message() const { return rawdata.at("message"); }
    std::vector<DbusAdvisoryReferenceWrapper> get_references() const { return references; }
    std::vector<DbusAdvisoryCollectionWrapper> get_collections() const { return collections; }

private:
    dnfdaemon::KeyValueMap rawdata{};
    std::vector<DbusAdvisoryReferenceWrapper> references;
    std::vector<DbusAdvisoryCollectionWrapper> collections;
};

}  // namespace dnfdaemon::client

#endif  // DNF5DAEMON_CLIENT_WRAPPERS_DBUS_ADVISORY_WRAPPER_HPP
